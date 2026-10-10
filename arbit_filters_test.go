package main

import (
	"math"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/banprice"
)

var testArbitOffer = arbitOffer{
	Rarities: []string{"mythic", "rare", "uncommon", "common"},
	Finishes: []banprice.Finish{{Value: "nonfoil"}, {Value: "foil"}, {Value: "etched"}},
}

func parseArbitQuery(t *testing.T, query string) arbitState {
	t.Helper()
	form, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	return parseArbitState(form, testArbitOffer)
}

// TestArbitDefaultsMatchToday pins a page with nothing set to the options
// the pages ran with before the filter bar, the chips each page turned on
// by default included. Sealed arbit and reverse drop their -$100 floor on
// the difference, on purpose.
func TestArbitDefaultsMatchToday(t *testing.T) {
	for _, tt := range []struct {
		desc                 string
		mode                 arbitMode
		minSpread, maxSpread float64
		minDiff              float64
		profConst            float64
		minSell, minBuy      float64
		priceFilter, edits   bool
	}{
		{"arbit", arbitMode{}, 10, 0, 0, ProfConst, 0, 0, false, false},
		{"reverse", arbitMode{Reverse: true}, 10, 0, 0, ProfConst, 0, 0, false, false},
		{"sealed arbit", arbitMode{Sealed: true}, -30, 0, math.Inf(-1), ProfConstGlobal, 0, 0, false, false},
		{"sealed reverse", arbitMode{Reverse: true, Sealed: true}, -30, 0, math.Inf(-1), ProfConstGlobal, 0, 0, false, false},
		{"global", arbitMode{Global: true}, 200, 1000, 5, ProfConst, 1, 1, true, true},
		{"global with AnySpread", arbitMode{Global: true, AnySpread: true}, 50, 1000, 5, ProfConst, 1, 1, true, true},
		{"global sealed", arbitMode{Global: true, Sealed: true}, 10, 0, 1, ProfConst, 0, 0, true, false},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			opts, rows := arbitState{}.apply(backend(), tt.mode)
			if opts.MinSpread != tt.minSpread || opts.MaxSpread != tt.maxSpread || opts.MinDiff != tt.minDiff {
				t.Errorf("spread %v..%v diff %v, want %v..%v diff %v",
					opts.MinSpread, opts.MaxSpread, opts.MinDiff, tt.minSpread, tt.maxSpread, tt.minDiff)
			}
			if opts.ProfitabilityConstant != tt.profConst {
				t.Errorf("profitability constant %v, want %v", opts.ProfitabilityConstant, tt.profConst)
			}
			if rows.limits.MinSell != tt.minSell || rows.limits.MinBuy != tt.minBuy {
				t.Errorf("price floors %v/%v, want %v/%v", rows.limits.MinSell, rows.limits.MinBuy, tt.minSell, tt.minBuy)
			}
			if (opts.CustomPriceFilter != nil) != tt.priceFilter {
				t.Errorf("price filter set: %v, want %v", opts.CustomPriceFilter != nil, tt.priceFilter)
			}
			if (opts.MaxPriceRatio == MaxPriceRatio && slices.Equal(opts.Editions, FilteredEditions)) != tt.edits {
				t.Errorf("ratio %v and editions %v, want global's: %v", opts.MaxPriceRatio, opts.Editions, tt.edits)
			}
			if opts.Conditions != nil || opts.Rarities != nil || opts.CustomCardFilter != nil ||
				opts.MinProfitability != 0 || opts.MinPrice != 0 || opts.MinBuyPrice != 0 || opts.MinQuantity != 0 {
				t.Errorf("a filter is set by default: %+v", opts)
			}
			if rows.limits.MaxSell != math.Inf(1) || rows.limits.MaxBuy != math.Inf(1) || rows.limits.MinQty != 0 {
				t.Errorf("a row limit is set by default: %+v", rows.limits)
			}
		})
	}
}

// TestArbitFloors pins the lowest spread and difference each page honours.
// Global's spread floor is the AnySpread grant's tier gate; its 1000% cap is
// the engine's, whatever the reader asks.
func TestArbitFloors(t *testing.T) {
	for _, tt := range []struct {
		desc            string
		mode            arbitMode
		query           string
		spread, diff    float64
		engineMaxSpread float64
	}{
		{"arbit", arbitMode{}, "minspread=-500&mindiff=-500", -30, -100, 0},
		{"reverse", arbitMode{Reverse: true}, "minspread=-500&mindiff=-500", -30, -100, 0},
		{"sealed arbit has no difference floor", arbitMode{Sealed: true}, "minspread=-500&mindiff=-500", -30, -500, 0},
		{"global", arbitMode{Global: true}, "minspread=0&mindiff=-5&maxspread=0", 200, 0, 1000},
		{"global with AnySpread", arbitMode{Global: true, AnySpread: true}, "minspread=0&maxspread=5000", 50, 5, 1000},
		{"global sealed", arbitMode{Global: true, Sealed: true}, "minspread=-500&mindiff=-500", -30, -100, 0},
		{"a value above the floor stands", arbitMode{Global: true}, "minspread=350&mindiff=12", 350, 12, 1000},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			opts, _ := parseArbitQuery(t, tt.query).apply(backend(), tt.mode)
			if opts.MinSpread != tt.spread || opts.MinDiff != tt.diff || opts.MaxSpread != tt.engineMaxSpread {
				t.Errorf("spread %v diff %v cap %v, want %v %v %v",
					opts.MinSpread, opts.MinDiff, opts.MaxSpread, tt.spread, tt.diff, tt.engineMaxSpread)
			}
		})
	}
}

func TestParseArbitState(t *testing.T) {
	for _, tt := range []struct {
		desc, query, want string
	}{
		{"nothing", "", "f=1"},
		{"the old chips mean nothing", "nolow=true&nopenny=true&nocond=true&nononrl=true", "f=1"},
		{"limits, an explicit zero kept", "minsell=2.5&maxbuy=40&minspread=0", "f=1&maxbuy=40&minsell=2.5&minspread=0"},
		{"numbers that are not finite", "minsell=NaN&maxsell=1e309&minbuy=abc&mindiff=-Inf", "f=1"},
		{"a pick, in the offer's order", "cond=HP,NM", "cond=NM%2CHP&f=1"},
		{"a pick from the boxes", "cond=SP&cond=NM&cond_on=1", "cond=NM%2CSP&f=1"},
		{"a pick of the whole list is none", "cond=NM,SP,MP,HP,PO", "f=1"},
		{"every box unchecked keeps nothing", "cond_on=1", "cond=&f=1"},
		{"values no picker offers", "rarity=bogus,rare&finish=sealed", "f=1&finish=&rarity=rare"},
		{"toggles", "rl=1&legit=0&stocks=true", "f=1&legit=0&rl=1&stocks=1"},
		{"a shown toggle left unchecked is off", "toggles_on=legit,syp&syp=1", "f=1&legit=0&syp=1"},
		{"a sort the pages know", "sort=spread", "f=1&sort=spread"},
		{"a sort they do not", "sort=bogus", "f=1"},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			st := parseArbitQuery(t, tt.query)
			got := st.values().Encode()
			if got != tt.want {
				t.Errorf("%q reads as %q, want %q", tt.query, got, tt.want)
			}
			again := parseArbitQuery(t, got).values().Encode()
			if again != got {
				t.Errorf("%q does not read back as itself: %q", got, again)
			}
		})
	}
}

// TestArbitChanged pins the bar's count to what differs from the page's
// defaults, not to what the URL spells out.
func TestArbitChanged(t *testing.T) {
	for _, tt := range []struct {
		mode  arbitMode
		query string
		want  int
	}{
		{arbitMode{}, "", 0},
		{arbitMode{}, "rl=0&abu4h=0&minspread=10&cond=NM,SP,MP,HP", 0},
		{arbitMode{}, "cond=NM&minsell=2&rl=1", 3},
		{arbitMode{}, "minspread=-500", 1},
		{arbitMode{Global: true}, "minspread=0&legit=1&minsell=1", 0},
		{arbitMode{Global: true}, "legit=0&minsell=0", 2},
		{arbitMode{Sealed: true}, "cond=NM", 0},
	} {
		got := parseArbitQuery(t, tt.query).changed(tt.mode)
		if got != tt.want {
			t.Errorf("%+v %q counts %d changes, want %d", tt.mode, tt.query, got, tt.want)
		}
	}
}

// TestArbitSortsAreKnown pins the sorts a URL may name to the ones the
// pages sort by.
func TestArbitSortsAreKnown(t *testing.T) {
	for _, sort := range arbitSorts {
		if arbitLess(backend(), nil, sort, false) == nil {
			t.Errorf("%q is accepted but sorts nothing", sort)
		}
	}
}

// TestArbitApplied pins which on/off options a page applies: the reader's,
// else the page's own default, and only among those it shows. RL, ABU4H and
// profitability need no grant.
func TestArbitApplied(t *testing.T) {
	for _, tt := range []struct {
		desc  string
		mode  arbitMode
		query string
		want  []string
	}{
		{"arbit", arbitMode{}, "rl=1&abu4h=1&syp=1", []string{"abu4h", "rl"}},
		{"global hides abu4h", arbitMode{Global: true}, "rl=1&abu4h=1&syp=1", []string{"legit", "rl", "syp"}},
		{"global turned off legit", arbitMode{Global: true}, "legit=0", nil},
		{"global sealed", arbitMode{Global: true, Sealed: true}, "rl=1&decklists=1", []string{"decklists", "stable"}},
		{"reverse", arbitMode{Reverse: true}, "", []string{"tradable"}},
		{"sealed reverse", arbitMode{Reverse: true, Sealed: true}, "", []string{"tradable"}},
		{"reverse turned off tradable", arbitMode{Reverse: true}, "tradable=0", nil},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			var got []string
			for key := range parseArbitQuery(t, tt.query).applied(tt.mode) {
				got = append(got, key)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("applied %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArbitApplyPicks(t *testing.T) {
	st := parseArbitQuery(t, "cond=NM,SP,MP,PO&rarity=mythic,rare&finish=etched")
	opts, _ := st.apply(rarityBackend(mtgmatcher.GameMagic, testArbitOffer.Rarities, nil), arbitMode{})
	if !slices.Equal(opts.Conditions, []mtgban.Condition{"HP", "PO"}) {
		t.Errorf("conditions dropped %v, want HP and the PO that goes with it", opts.Conditions)
	}
	kept, _ := parseArbitQuery(t, "cond=NM,HP").apply(backend(), arbitMode{})
	if !slices.Equal(kept.Conditions, []mtgban.Condition{"SP", "MP"}) {
		t.Errorf("keeping HP dropped %v, want SP and MP", kept.Conditions)
	}
	if !slices.Equal(opts.Rarities, []string{"uncommon", "common"}) {
		t.Errorf("rarities dropped %v, want uncommon and common", opts.Rarities)
	}
	if opts.CustomCardFilter == nil {
		t.Fatal("a finish pick sets no card filter")
	}
	for finish, keep := range map[string]bool{"etched": true, "foil": false, "nonfoil": false, "": false} {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{Finish: finish}}
		_, skip := opts.CustomCardFilter(co)
		if skip == keep {
			t.Errorf("a %q printing is kept: %v, want %v", finish, !skip, keep)
		}
	}

	sealed, _ := st.apply(rarityBackend(mtgmatcher.GameMagic, testArbitOffer.Rarities, nil), arbitMode{Sealed: true})
	if sealed.Conditions != nil || sealed.Rarities != nil || sealed.CustomCardFilter != nil {
		t.Errorf("a sealed source applies the singles' picks: %+v", sealed)
	}
}

// TestArbitRowFilter pins the price limits to the columns the table shows:
// the buy price in arbit, which is the row's own condition's, and the other
// store's listing in global.
func TestArbitRowFilter(t *testing.T) {
	row := mtgban.ArbitEntry{
		InventoryEntry: mtgban.InventoryEntry{Price: 10},
		BuylistEntry:   mtgban.BuylistEntry{BuyPrice: 25},
		ReferenceEntry: mtgban.InventoryEntry{Price: 4},
		Spread:         150,
		Quantity:       2,
	}
	for _, tt := range []struct {
		query      string
		global     bool
		noQuantity bool
		keep       bool
	}{
		{"", false, false, true},
		{"minsell=10&maxsell=10", false, false, true},
		{"minsell=10.01", false, false, false},
		{"maxsell=9.99", false, false, false},
		{"minbuy=25", false, false, true},
		{"minbuy=26", false, false, false},
		{"minbuy=5", true, false, false},
		{"maxbuy=4", true, false, true},
		{"maxspread=150", false, false, true},
		{"maxspread=149", false, false, false},
		{"minqty=2", false, false, true},
		{"minqty=3", false, false, false},
		{"minqty=3", false, true, true},
		{"minqty=3&minsell=11", false, true, false},
	} {
		_, rows := parseArbitQuery(t, tt.query).apply(backend(), arbitMode{Global: tt.global, AnySpread: true})
		if rows.keep(row, tt.noQuantity) != tt.keep {
			t.Errorf("%q (global=%v, no quantities=%v) keeps the row: %v, want %v",
				tt.query, tt.global, tt.noQuantity, !tt.keep, tt.keep)
		}
	}
}

// TestArbitMinQuantitySparesSellersWithout pins a quantity limit to the
// sellers that publish quantities: a table from one that does not, such as
// Mana Pool, has no Qty column and kept every row before the limit was a
// field.
func TestArbitMinQuantitySparesSellersWithout(t *testing.T) {
	skipWithoutDatastore(t)
	m10 := backend().GetUUIDsInSet("M10")
	if len(m10) == 0 {
		t.Skip("M10 not present in this datastore")
	}
	cardID := m10[0]
	withSigMode(t, true, false)

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	inv := mtgban.InventoryRecord{}
	inv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, URL: "u"})
	// Add counts a copy with no quantity as one; a dump keeps the zero
	inv[cardID][0].Quantity = 0
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "No Qty Shop", Shorthand: "NOQTY", NoQuantityInventory: true}),
	}
	sellersPtr.Store(&sellers)
	bl := mtgban.BuylistRecord{}
	bl.Add(cardID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 40, URL: "u"})
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Name: "Qty Buyer", Shorthand: "QTYBUY"}),
	}
	vendorsPtr.Store(&vendors)

	r := httptest.NewRequest("GET", "/arbit?source=NOQTY&minqty=1", nil)
	w := httptest.NewRecorder()
	scraperCompare(testSite.datastore(), w, r, PageVars{UserNav: &NavElem{Short: "beta"}}, []string{"NOQTY"}, nil, scraperCompareOpts{AllResults: true})
	if !strings.Contains(w.Body.String(), `data-arb-id="`+cardID+`"`) {
		t.Error("a minimum quantity empties the table of a seller that publishes none")
	}
}

// TestGlobalDirectKeepsItsConditions pins TCG Direct's own condition rule to
// adding to the reader's: keeping only SP must not let Direct's NM back in.
func TestGlobalDirectKeepsItsConditions(t *testing.T) {
	skipWithoutDatastore(t)
	m10 := backend().GetUUIDsInSet("M10")
	if len(m10) == 0 {
		t.Skip("M10 not present in this datastore")
	}
	cardID := m10[0]

	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })
	shelf := func(price float64) mtgban.InventoryRecord {
		inv := mtgban.InventoryRecord{}
		inv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: 1, URL: "u"})
		return inv
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(shelf(10), mtgban.ScraperInfo{Name: "Filter Shop", Shorthand: "FILTSHOP"}),
		mtgban.NewSellerFromInventory(shelf(40), mtgban.ScraperInfo{Name: "Direct", Shorthand: "TCGDirect"}),
	}
	sellersPtr.Store(&sellers)

	// No TCG Market is loaded, which "only Legit" reads as every price
	// being off
	row := `data-arb-id="` + cardID + `"`
	if !strings.Contains(renderGlobal(t, "FILTSHOP", "&legit=0"), row) {
		t.Fatal("the NM row is missing by default")
	}
	if strings.Contains(renderGlobal(t, "FILTSHOP", "&legit=0&cond=SP"), row) {
		t.Error("keeping only SP still lists an NM row against TCG Direct")
	}
}

// TestArbitStoreLinksCarryState pins the store links to the state asked
// for, and to nothing where none was.
func TestArbitStoreLinksCarryState(t *testing.T) {
	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Link Source", Shorthand: "LINKSRC"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Link Other", Shorthand: "LINKOTH"}),
	}
	sellersPtr.Store(&sellers)
	withSigMode(t, true, false)

	render := func(query string) string {
		r := httptest.NewRequest("GET", "/global?source=LINKSRC"+query, nil)
		w := httptest.NewRecorder()
		pageVars := PageVars{ArbitVars: ArbitVars{GlobalMode: true}, UserNav: &NavElem{Short: "beta"}}
		scraperCompare(testSite.datastore(), w, r, pageVars, []string{"LINKSRC", "LINKOTH"}, nil, scraperCompareOpts{AllResults: true})
		return w.Body.String()
	}

	page := render("&minsell=2&nolow=true")
	if !strings.Contains(page, `value="/global?f=1&amp;minsell=2&amp;source=LINKOTH"`) {
		t.Error("a store link drops the filters asked for")
	}
	if strings.Contains(page, "nolow") {
		t.Error("an unknown key is echoed into the links")
	}

	page = render("")
	if !strings.Contains(page, `value="/global?source=LINKOTH"`) {
		t.Error("a store link carries filters nobody asked for")
	}
}

// TestRequestArbitState pins which state a request gets: its own query
// where that carries the marker, else the saved filters with the query's
// sort for the one view, else the query.
func TestRequestArbitState(t *testing.T) {
	saved := url.QueryEscape("f=1&cond=NM%2CSP&minsell=2&sort=diff&t=1728000000000")
	for _, tt := range []struct {
		desc, query, saved, want string
		savedAt                  int64
	}{
		{"nothing saved", "source=CK", "", "f=1", 0},
		{"the saved filters", "source=CK", saved, "cond=NM%2CSP&f=1&minsell=2&sort=diff", 1728000000000},
		{"a marked link wins", "source=CK&f=1&minsell=5", saved, "f=1&minsell=5", 0},
		{"a marked link with nothing set is the defaults", "source=CK&f=1", saved, "f=1", 0},
		{"an unmarked sort is for this view", "source=CK&sort=spread", saved, "cond=NM%2CSP&f=1&minsell=2&sort=spread", 1728000000000},
		{"an unknown sort is not", "source=CK&sort=bogus", saved, "cond=NM%2CSP&f=1&minsell=2&sort=diff", 1728000000000},
		{"old chip keys do not mark a link", "source=CK&nolow=true", saved, "cond=NM%2CSP&f=1&minsell=2&sort=diff", 1728000000000},
		{"a value that is no query is nothing saved", "source=CK&minsell=3", "%zz", "f=1&minsell=3", 0},
		{"a reset saves the defaults", "source=CK", url.QueryEscape("f=1&t=1"), "f=1", 1},
		{"a saved state with no time", "source=CK", url.QueryEscape("f=1&minsell=2"), "f=1&minsell=2", 0},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			form, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatal(err)
			}
			st, savedAt := requestArbitState(form, tt.saved, testArbitOffer)
			got := st.values().Encode()
			if got != tt.want || savedAt != tt.savedAt {
				t.Errorf("got %q applied at %d, want %q at %d", got, savedAt, tt.want, tt.savedAt)
			}
		})
	}
}

// TestArbitSavedCookies pins arbit and reverse to one saved state, and
// global to its own, read off the request the way the handler reads it.
func TestArbitSavedCookies(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Saved Source", Shorthand: "SAVSRC"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Saved Other", Shorthand: "SAVOTH"}),
	}
	sellersPtr.Store(&sellers)
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Saved Buyer", Shorthand: "SAVBUY"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Saved Buyer Two", Shorthand: "SAVBU2"}),
	}
	vendorsPtr.Store(&vendors)
	withSigMode(t, true, false)

	cookies := "ArbitFilters=" + url.QueryEscape("f=1&minsell=2&t=1") + "; GlobalFilters=" + url.QueryEscape("f=1&minsell=7&t=1")
	render := func(path string, pageVars PageVars, allow []string) string {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Cookie", cookies)
		w := httptest.NewRecorder()
		pageVars.UserNav = &NavElem{Short: "beta"}
		scraperCompare(testSite.datastore(), w, r, pageVars, allow, nil, scraperCompareOpts{AllResults: true})
		return w.Body.String()
	}
	for _, tt := range []struct {
		desc, page string
		want       string
	}{
		{"arbit", render("/arbit?source=SAVSRC", PageVars{}, []string{"SAVSRC", "SAVOTH"}), "minsell=2"},
		{"reverse", render("/reverse?source=SAVBUY", PageVars{ReverseMode: true}, nil), "minsell=2"},
		{"global", render("/global?source=SAVSRC", PageVars{ArbitVars: ArbitVars{GlobalMode: true}}, []string{"SAVSRC", "SAVOTH"}), "minsell=7"},
	} {
		if !strings.Contains(tt.page, "&amp;"+tt.want+"&amp;source=") {
			t.Errorf("%s does not carry its saved %s into its links", tt.desc, tt.want)
		}
		if !strings.Contains(tt.page, `name="minsell" value="`+strings.TrimPrefix(tt.want, "minsell=")+`"`) {
			t.Errorf("%s does not fill its saved %s into the bar", tt.desc, tt.want)
		}
		if !regexp.MustCompile(`savedAt:\s*1\b`).MatchString(tt.page) {
			t.Errorf("%s does not tell its script when the saved state was applied", tt.desc)
		}
	}
}
