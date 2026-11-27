package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

func TestGroupBySlab(t *testing.T) {
	row := func(store string, price float64, slab mtgban.Slab) SearchEntry {
		return SearchEntry{Shorthand: store, Price: price, Slab: &slab}
	}
	gather := func() map[string]map[mtgban.Condition][]SearchEntry {
		return map[string]map[mtgban.Condition][]SearchEntry{"card": {
			"NM": {
				row("A", 50, mtgban.Slab{Grader: "CGC", Score: 10}),
				row("B", 30, mtgban.Slab{Grader: "BGS", Score: 9.5}),
				row("C", 90, mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}),
				row("D", 20, mtgban.Slab{Grader: "CGC", Score: 10}),
				row("E", 10, mtgban.Slab{Label: "SGC 9"}),
				row("F", 70, mtgban.Slab{Grader: "PSA", Score: 10}),
				row("I", 80, mtgban.Slab{Grader: "BGS", Score: 10, Label: "Pristine"}),
				row("J", 85, mtgban.Slab{Grader: "BGS", Score: 10, Label: "Black Label"}),
				row("K", 60, mtgban.Slab{Grader: "BGS", Score: 10}),
				row("L", 40, mtgban.Slab{Grader: "AiGrading", Score: 10}),
				row("M", 45, mtgban.Slab{Grader: "GRAAD", Score: 9.5}),
			},
			"SP": {
				row("G", 15, mtgban.Slab{Grader: "CGC", Label: "Less than 8"}),
				row("H", 5, mtgban.Slab{}),
			},
		}}
	}

	for byPrice, wantCGC := range map[bool]string{true: "DA", false: "AD"} {
		found := gather()
		keys := groupBySlab(found, byPrice)
		want := []mtgban.Condition{"PSA 10", "BGS 10 Black Label", "BGS 10 Pristine", "BGS 10", "BGS 9.5", "CGC 10 Pristine", "CGC 10", "CGC Less than 8", "GRAAD 9.5", "AiGrading 10", otherSlabs}
		if !slices.Equal(keys, want) {
			t.Errorf("byPrice %v: groups = %q, want %q", byPrice, keys, want)
		}
		var stores string
		for _, entry := range found["card"]["CGC 10"] {
			stores += entry.Shorthand
		}
		if stores != wantCGC {
			t.Errorf("byPrice %v: CGC 10 lists %s, want %s", byPrice, stores, wantCGC)
		}
		if len(found["card"][otherSlabs]) != 2 {
			t.Errorf("byPrice %v: other slabs = %+v, want two", byPrice, found["card"][otherSlabs])
		}
		if len(found["card"]["NM"]) != 0 {
			t.Errorf("byPrice %v: a row is left under its condition", byPrice)
		}
	}

	if keys := groupBySlab(map[string]map[mtgban.Condition][]SearchEntry{}, true); len(keys) != 0 {
		t.Errorf("groups of nothing = %q", keys)
	}
}

// The Graded page finds only the cards a slab seller offers, lists that
// seller's slabs under their grades and no buylist, while the search keeps
// every store.
func TestGradedPage(t *testing.T) {
	skipWithoutDatastore(t)
	// DevMode so render reads templates from disk
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 2)
	stock := func(name string, graded bool, inv mtgban.InventoryRecord) mtgban.Seller {
		return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: name, Shorthand: name, GradedMode: graded})
	}
	withPrices(t, []mtgban.Seller{
		stock("RAWSHOP", false, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 10, URL: "u"}},
			cards[1]: {{Conditions: "NM", Price: 10, URL: "u"}},
		}),
		stock("SLABSHOP", true, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 40, URL: "u", Slab: &mtgban.Slab{Grader: "PSA", Score: 9}}},
		}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{cards[0]: {{Conditions: "NM", BuyPrice: 5, URL: "u"}}},
			mtgban.ScraperInfo{Name: "BUYSHOP", Shorthand: "BUYSHOP"}),
	})

	row := func(store string) string { return `data-track-value="` + store + `"` }
	card := func(i int) string { return `data-card-id="` + cards[i] + `"` }
	serve := func(path, agent string) string {
		req := httptest.NewRequest(http.MethodGet, path+"?q="+strings.Join(cards, ","), nil)
		req.Header.Set("User-Agent", agent)
		rec := httptest.NewRecorder()
		testSite.Search(rec, req)
		return rec.Body.String()
	}
	for _, agent := range []string{"", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"} {
		body := serve("/graded", agent)
		for _, want := range []string{row("SLABSHOP"), ">PSA 9</div>", "Last Sold", "No sales on record", card(0)} {
			if !strings.Contains(body, want) {
				t.Errorf("graded, %q: %q is missing", agent, want)
			}
		}
		for _, not := range []string{row("RAWSHOP"), row("BUYSHOP"), "Condition: NM", card(1), "/search/export/", "data-buyers-set"} {
			if strings.Contains(body, not) {
				t.Errorf("graded, %q: %q is shown", agent, not)
			}
		}

		// The phone's panel names its landscape column too.
		if agent != "" && !strings.Contains(body, `role="region" aria-label="Last Sold"`) {
			t.Errorf("graded, %q: the Last Sold panel is not named", agent)
		}

		body = serve("/search", agent)
		for _, want := range []string{row("RAWSHOP"), row("SLABSHOP"), row("BUYSHOP"), "Condition: NM", card(0), card(1)} {
			if !strings.Contains(body, want) {
				t.Errorf("search, %q: %q is missing", agent, want)
			}
		}
		if agent != "" && !strings.Contains(body, `role="region" aria-label="Buyers"`) {
			t.Errorf("search, %q: the Buyers panel is not named", agent)
		}

		// The phone's drawer lists the Graded page's own sellers, the slabs' alone.
		if agent != "" {
			_, graded, _ := strings.Cut(body, `id="m-set-graded-sellers"`)
			graded, _, _ = strings.Cut(graded, "m-settings-section")
			if !strings.Contains(graded, `name="SLABSHOP"`) || strings.Contains(graded, `name="RAWSHOP"`) {
				t.Errorf("search, %q: the Graded page's sellers are not SLABSHOP alone:\n%s", agent, graded)
			}
		}
	}

	// The Graded page hides the stores its own list names, and search those
	// of its list: hiding a seller of slabs on one leaves it on the other.
	for _, tc := range []struct {
		path, cookie string
		shown        bool
	}{
		{"/graded", "SearchSellersList=SLABSHOP,", true},
		{"/graded", "SearchGradedSellersList=SLABSHOP,", false},
		{"/search", "SearchGradedSellersList=SLABSHOP,", true},
		{"/search", "SearchSellersList=SLABSHOP,", false},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path+"?q="+strings.Join(cards, ","), nil)
		req.Header.Set("Cookie", tc.cookie)
		rec := httptest.NewRecorder()
		testSite.Search(rec, req)
		if strings.Contains(rec.Body.String(), row("SLABSHOP")) != tc.shown {
			t.Errorf("%s with %s: SLABSHOP shown %v, want %v", tc.path, tc.cookie, !tc.shown, tc.shown)
		}
	}
}

// is:graded on the search page hands the search to the Graded page, query
// and pinned bar intact, which keeps the graded stores alone; not:graded
// leaves the search as it was.
func TestSearchIsGraded(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 2)
	stock := func(name string, graded bool, inv mtgban.InventoryRecord) mtgban.Seller {
		return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: name, Shorthand: name, GradedMode: graded})
	}
	withPrices(t, []mtgban.Seller{
		stock("RAWSHOP", false, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 10, URL: "u"}},
			cards[1]: {{Conditions: "NM", Price: 10, URL: "u"}},
		}),
		stock("SLABSHOP", true, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 40, URL: "u", Slab: &mtgban.Slab{Grader: "PSA", Score: 9}}},
		}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{cards[0]: {{Conditions: "NM", BuyPrice: 5, URL: "u"}}},
			mtgban.ScraperInfo{Name: "BUYSHOP", Shorthand: "BUYSHOP"}),
	})

	// A list of ids names its own cards and no filter narrows it, so the
	// search is by the first card's name.
	name := currentDatastore().backend.UUIDs[cards[0]].Name
	row := func(store string) string { return `data-track-value="` + store + `"` }
	serve := func(filter, scope string) string {
		query := "q=" + url.QueryEscape(name+" "+filter) + "&scope=" + url.QueryEscape(scope)
		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/search?"+query, nil))
		if rec.Code != http.StatusFound {
			return rec.Body.String()
		}
		if where := rec.Header().Get("Location"); where != "/graded?"+query {
			t.Errorf("%q, pinned %q: sent to %q", filter, scope, where)
			return ""
		}
		rec = httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded?"+query, nil))
		return rec.Body.String()
	}
	slabsOnly := []string{row("SLABSHOP"), "Last Sold"}
	for _, tc := range []struct {
		filter, scope string
		shown         []string
		notShown      []string
	}{
		{"is:graded", "", slabsOnly, []string{row("RAWSHOP"), row("BUYSHOP")}},
		{"", "is:graded", slabsOnly, []string{row("RAWSHOP"), row("BUYSHOP")}},
		{"not:graded", "", []string{row("RAWSHOP"), row("SLABSHOP"), row("BUYSHOP")}, []string{"Last Sold"}},
	} {
		body := serve(tc.filter, tc.scope)
		for _, want := range tc.shown {
			if !strings.Contains(body, want) {
				t.Errorf("%q, pinned %q: %q is missing", tc.filter, tc.scope, want)
			}
		}
		for _, not := range tc.notShown {
			if strings.Contains(body, not) {
				t.Errorf("%q, pinned %q: %q is shown", tc.filter, tc.scope, not)
			}
		}
	}
}

// is:graded is a search of graded stores, never a card property, so beside
// another is: value it leaves that value's filter alone.
func TestParseIsGraded(t *testing.T) {
	b := colorBackend(matcher.GamePokemon, map[string][]string{"a": nil})
	for _, tc := range []struct {
		query  string
		graded bool
		is     []string
	}{
		{"pikachu is:graded", true, nil},
		{"pikachu is:foil,graded", true, []string{"foil"}},
		{"pikachu not:graded", false, []string{"graded"}},
		{"pikachu is:foil", false, []string{"foil"}},
	} {
		config := parseSearchOptionsNG(b, currentPrices(), tc.query, nil, nil, nil)
		var is []string
		for _, filter := range config.CardFilters {
			if filter.Name == "is" {
				is = append(is, filter.Values...)
			}
		}
		if config.GradedOnly != tc.graded || config.SkipBuylist != tc.graded || !slices.Equal(is, tc.is) || config.CleanQuery != "pikachu" {
			t.Errorf("%q: graded %v, skip buylist %v, is %v, query %q; want graded %v, is %v, query pikachu",
				tc.query, config.GradedOnly, config.SkipBuylist, is, config.CleanQuery, tc.graded, tc.is)
		}
	}
}

// The sorts that read raw copies' prices and sales do not order the Graded
// page, wherever they were asked for.
func TestGradedPageSort(t *testing.T) {
	config := SearchConfig{VelocitySort: true}
	gradedSearch(&config)
	for _, sort := range []string{"retail", "buylist", "velocity"} {
		req := httptest.NewRequest(http.MethodGet, "/graded?sort="+sort, nil)
		req.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: sort})
		asked := config
		asked.SortMode = sort
		if got := readSearchSort(req, asked); got != "" {
			t.Errorf("sort %s orders the page by %q", sort, got)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/graded?sort=retail", nil)
	req.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: "number"})
	if got := readSearchSort(req, config); got != "number" {
		t.Errorf("the saved sort gives %q, want number", got)
	}
}

// The Graded page is in the menu only where a store lists slabs.
func TestGradedPageHiddenWithoutSlabs(t *testing.T) {
	nav, found := ExtraNavs["Search"].pageAt("/graded")
	if !found {
		t.Fatal("no /graded page")
	}
	for _, graded := range []bool{false, true} {
		withPrices(t, []mtgban.Seller{
			mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "SHOP", GradedMode: graded}),
		}, nil)
		if nav.hiddenOn(testSite) == graded {
			t.Errorf("with a graded store %v: hidden = %v", graded, !graded)
		}
	}
}

// The Last Sold column opens with the slabs' Sales Velocity, then draws the
// sales of the grades a store lists the card in as the Sales pane draws the
// recent orders, in the page's order, and shows a reader without the sales an
// upsell instead.
func TestGradedPageLastSold(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 1)
	psa9 := mtgban.Slab{Grader: "PSA", Score: 9}
	pristine := mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {
				{Conditions: "NM", Price: 40, URL: "u", Slab: &psa9},
				{Conditions: "NM", Price: 90, URL: "u", Slab: &pristine},
			},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
	}, nil)

	now := time.Now()
	at := func(days int) uint32 { return uint32(now.AddDate(0, 0, -days).Unix()) }
	previous := gradedSalesStore.Snapshot()
	t.Cleanup(func() { gradedSalesStore.Publish(previous) })
	gradedSalesStore.Publish(&salesvelocity.GradedSnapshot{Day: now, Cards: map[string]*salesvelocity.GradedCard{
		cards[0]: {
			Grades: map[mtgban.Slab]*salesvelocity.GradeSales{
				psa9: {Sales: []salesvelocity.GradedSale{
					{At: at(1), Cents: 51500, ListingID: "111"},
					{At: at(3), Cents: 70000, ListingID: "222", BestOffer: true},
				}},
				pristine: {Sales: []salesvelocity.GradedSale{{At: at(200), Cents: 99900, Fanatics: true, ListingID: "fanatics:W1"}}},
				// No store lists a PSA 10 of it.
				{Grader: "PSA", Score: 10}: {Sales: []salesvelocity.GradedSale{{At: at(1), Cents: 123400, ListingID: "333"}}},
			},
			Sales: 3, Days: 2,
			Last: salesvelocity.GradedSale{At: at(1), Cents: 51500}, LastSlab: psa9,
		},
	}})

	req := httptest.NewRequest(http.MethodGet, "/graded?q="+cards[0], nil)
	rec := httptest.NewRecorder()
	testSite.Search(rec, req)
	body := rec.Body.String()
	for _, want := range []string{
		"<span>PSA 9</span><span class=\"sales-avg\">avg <b>$ 515.00</b>",
		`href="https://www.ebay.com/itm/111?nordt=true"`,
		`data-track="ui.graded.sale" data-track-value="eBay"`,
		`data-track="ui.graded.sale" data-track-value="Fanatics"`,
		`<span class="sales-qty">offer</span>`,
		"<span>CGC 10 Pristine</span><span class=\"sales-avg\">avg <b>$ 999.00</b>",
		`href="https://sales-history.fanaticscollect.com/items/W1"`,
		`<span class="store-name dim">Sales Velocity</span>`,
		">0.1/day<",
		"$515.00 PSA 9",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Last Sold: %q is missing", want)
		}
	}
	if strings.Contains(body, "ebay.com/itm/333") {
		t.Error("Last Sold lists a grade no store lists the card in")
	}
	psa, cgc := strings.Index(body, "ebay.com/itm/111"), strings.Index(body, "items/W1")
	if psa < 0 || cgc < 0 || psa > cgc {
		t.Error("Last Sold does not follow the page's order of grades")
	}
	if strings.Contains(body, "No sales on record") || strings.Contains(body, "Condition: PSA") {
		t.Error("Last Sold says there are no sales, or heads a grade as a condition")
	}

	// The velocity sits in the sidebar, where the products a card comes in
	// are listed elsewhere, and heads the sales only where that is hidden.
	var sidebar string
	if hover := strings.Index(body, `<div class="hover-velocity">`); hover >= 0 {
		sidebar, _, _ = strings.Cut(body[hover:], "</template>")
	}
	if !strings.Contains(body, `id="sidebarVelocity"`) ||
		!strings.Contains(sidebar, `<div class="sales-velocity sales-velocity-fixed">`) ||
		!strings.Contains(sidebar, `<span class="store-name dim">Sales Velocity</span>`) || strings.Contains(sidebar, "<details") ||
		!strings.Contains(body, `<div class="graded-velocity-col">`) || strings.Contains(body, `id="productsCard"`) {
		t.Error("the sidebar does not carry the velocity, always open, in place of the products")
	}

	// Without the sales, the column says how to get them.
	withSigMode(t, true, true)
	rec = httptest.NewRecorder()
	testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded?q="+cards[0], nil))
	body = rec.Body.String()
	if strings.Contains(body, "ebay.com/itm/111") || strings.Contains(body, ">0.1/day<") || strings.Contains(body, "$515.00 PSA 9") ||
		strings.Contains(body, `<div class="hover-velocity">`) || !strings.Contains(body, `data-track-value="sales_upsell"`) {
		t.Error("a reader without the sales sees them or their velocity, or no upsell")
	}

	// With no sales to unlock, the column only says so.
	gradedSalesStore.Publish(&salesvelocity.GradedSnapshot{Day: now})
	rec = httptest.NewRecorder()
	testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded?q="+cards[0], nil))
	body = rec.Body.String()
	if strings.Contains(body, `data-track-value="sales_upsell"`) || !strings.Contains(body, "No sales on record") {
		t.Error("a reader without the sales gets an upsell for a card with none")
	}
}

// The Graded page's random card is always one a graded store the reader sees
// lists, never a raw card or one only a blocked or hidden store lists.
func TestRandomGradedSearch(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	cards := somePlainCardUUIDs(t, 3)
	slab := &mtgban.Slab{Grader: "PSA", Score: 9}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 10, URL: "u"}},
		}, mtgban.ScraperInfo{Name: "RAWSHOP", Shorthand: "RAWSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[1]: {{Conditions: "NM", Price: 40, URL: "u", Slab: slab}},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[2]: {{Conditions: "NM", Price: 40, URL: "u", Slab: slab}},
		}, mtgban.ScraperInfo{Name: "HIDDENSLABS", Shorthand: "HIDDENSLABS", GradedMode: true}),
	}, nil)
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"HIDDENSLABS"}

	for range 30 {
		rec := httptest.NewRecorder()
		testSite.RandomGradedSearch(rec, httptest.NewRequest(http.MethodGet, "/randomgraded", nil))
		want := "/graded?q=" + cards[1]
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
			t.Fatalf("redirect %d to %q, want %q", rec.Code, rec.Header().Get("Location"), want)
		}
	}

	// A store the reader hid from the Graded page is skipped too, and one
	// hidden from search alone is not.
	Config().Stores.SearchRetailBlockList = nil
	req := httptest.NewRequest(http.MethodGet, "/randomgraded", nil)
	req.Header.Set("Cookie", "SearchSellersList=SLABSHOP,HIDDENSLABS,")
	rec := httptest.NewRecorder()
	testSite.RandomGradedSearch(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/graded?q=") {
		t.Fatalf("with both hidden from search, redirect %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	for range 30 {
		req := httptest.NewRequest(http.MethodGet, "/randomgraded", nil)
		req.Header.Set("Cookie", "SearchGradedSellersList=SLABSHOP,")
		rec := httptest.NewRecorder()
		testSite.RandomGradedSearch(rec, req)
		want := "/graded?q=" + cards[2]
		if rec.Header().Get("Location") != want {
			t.Fatalf("with SLABSHOP hidden, redirect to %q, want %q", rec.Header().Get("Location"), want)
		}
	}
}

// The Graded page's landing shows the dearest slabs in stock at the graded
// stores the reader sees, one per card, in place of the recent searches and
// favorites the other search pages keep.
func TestGradedLandingShowcase(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	cards := somePlainCardUUIDs(t, 4)
	psa9 := &mtgban.Slab{Grader: "PSA", Score: 9}
	psa10 := &mtgban.Slab{Grader: "PSA", Score: 10}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 5000, URL: "u"}},
		}, mtgban.ScraperInfo{Name: "RAWSHOP", Shorthand: "RAWSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[1]: {
				{Conditions: "NM", Price: 40, URL: "u", Slab: psa9},
				{Conditions: "NM", Price: 90, URL: "u", Slab: psa10},
			},
			cards[2]: {{Conditions: "NM", Price: 20, URL: "u", Slab: psa9}},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[1]: {{Conditions: "NM", Price: 60, URL: "u", Slab: psa9}},
		}, mtgban.ScraperInfo{Name: "OTHERSLABS", Shorthand: "OTHERSLABS", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[3]: {{Conditions: "NM", Price: 9000, URL: "u", Slab: psa10}},
		}, mtgban.ScraperInfo{Name: "HIDDENSLABS", Shorthand: "HIDDENSLABS", GradedMode: true}),
	}, nil)
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"HIDDENSLABS"}

	landing := func(path string) string {
		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Body.String()
	}
	body := landing("/graded")
	// Each tile is drawn twice, for the carousel's loop.
	for link, want := range map[string]int{
		`href="/graded?q=` + cards[0] + `"`: 0,
		`href="/graded?q=` + cards[1] + `"`: 2,
		`href="/graded?q=` + cards[2] + `"`: 2,
		`href="/graded?q=` + cards[3] + `"`: 0,
	} {
		if got := strings.Count(body, link); got != want {
			t.Errorf("%s occurs %d times, want %d", link, got, want)
		}
	}
	for _, want := range []string{
		`<span class="slab-showcase-slab">PSA 10</span>`,
		`<span class="landing-popular-label">SLABSHOP</span>`,
		`90.00</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the showcase is missing %q", want)
		}
	}
	if strings.Contains(body, "OTHERSLABS") || strings.Contains(body, "40.00") {
		t.Error("the showcase shows a card's cheaper slab")
	}
	if strings.Index(body, cards[1]) > strings.Index(body, cards[2]) {
		t.Error("the showcase is not dearest first")
	}
	if strings.Contains(body, `id="desktop-favorites"`) {
		t.Error("the Graded page's landing still shows the favorites")
	}

	body = landing("/search")
	if strings.Contains(body, "slab-showcase") || !strings.Contains(body, `id="desktop-favorites"`) {
		t.Error("the search landing lost its favorites, or shows slabs")
	}
}

// A card no graded store lists is on the Graded page for a reader who may see
// the slabs' sales, with every grade it sold in, and is:lastsold keeps the
// cards with a slab sold. Any other reader gets neither, and a notice.
func TestGradedLastSoldCards(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 3)
	psa9 := mtgban.Slab{Grader: "PSA", Score: 9}
	bgs10 := mtgban.Slab{Grader: "BGS", Score: 10}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 40, URL: "u", Slab: &psa9}},
			cards[2]: {{Conditions: "NM", Price: 40, URL: "u", Slab: &psa9}},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
	}, nil)
	now := time.Now()
	at := uint32(now.AddDate(0, 0, -1).Unix())
	previous := gradedSalesStore.Snapshot()
	t.Cleanup(func() { gradedSalesStore.Publish(previous) })
	sold := func(listing string) *salesvelocity.GradeSales {
		return &salesvelocity.GradeSales{Sales: []salesvelocity.GradedSale{{At: at, Cents: 5000, ListingID: listing}}}
	}
	gradedSalesStore.Publish(&salesvelocity.GradedSnapshot{Day: now, Cards: map[string]*salesvelocity.GradedCard{
		cards[0]: {Grades: map[mtgban.Slab]*salesvelocity.GradeSales{psa9: sold("100")}},
		cards[1]: {Grades: map[mtgban.Slab]*salesvelocity.GradeSales{psa9: sold("101"), bgs10: sold("102")}},
	}})

	search := func(path string) string {
		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Body.String()
	}
	shows := func(body, cardID string) bool {
		return strings.Contains(body, `data-card-id="`+cardID+`"`)
	}

	body := search("/graded?q=" + cards[1])
	if !shows(body, cards[1]) || !strings.Contains(body, "No offers") {
		t.Fatal("a card no store lists is not on the Graded page with its sales")
	}
	bgs, psa := strings.Index(body, "ebay.com/itm/102"), strings.Index(body, "ebay.com/itm/101")
	if psa < 0 || bgs < 0 || psa > bgs {
		t.Error("Last Sold does not list every grade sold, in the page's order")
	}

	body = search("/graded?q=" + url.QueryEscape("is:lastsold"))
	if !shows(body, cards[0]) || !shows(body, cards[1]) || shows(body, cards[2]) {
		t.Error("is:lastsold does not keep exactly the cards a slab of sold")
	}
	body = search("/graded?q=" + url.QueryEscape("not:lastsold"))
	if !shows(body, cards[2]) || shows(body, cards[0]) || shows(body, cards[1]) {
		t.Error("not:lastsold does not keep exactly the cards no slab of sold")
	}

	// Without the sales, neither the card nor the filter reads them.
	withSigMode(t, true, true)
	if shows(search("/graded?q="+cards[1]), cards[1]) {
		t.Error("a reader without the sales finds a card no store lists")
	}
	body = search("/graded?q=" + url.QueryEscape("is:lastsold"))
	if shows(body, cards[0]) || !strings.Contains(body, LastSoldLockedMessage) {
		t.Error("is:lastsold judges cards for a reader without the sales, or says nothing")
	}
	withSigMode(t, true, false)
	body = search("/search?q=" + url.QueryEscape("is:lastsold"))
	if shows(body, cards[0]) || !strings.Contains(body, LastSoldGradedMessage) {
		t.Error("is:lastsold runs off the Graded page, or says nothing")
	}
}

// A reader who may see the slabs' sales gets the newest slab sold of each card,
// newest first and never a best offer; no other reader gets the carousel.
func TestGradedLandingSoldSlabs(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	cards := somePlainCardUUIDs(t, 3)
	psa9 := mtgban.Slab{Grader: "PSA", Score: 9}
	bgs10 := mtgban.Slab{Grader: "BGS", Score: 10}
	withPrices(t, nil, nil)
	now := time.Now()
	at := func(days int) uint32 { return uint32(now.AddDate(0, 0, -days).Unix()) }
	previous := gradedSalesStore.Snapshot()
	t.Cleanup(func() { gradedSalesStore.Publish(previous) })
	gradedSalesStore.Publish(&salesvelocity.GradedSnapshot{Day: now, Cards: map[string]*salesvelocity.GradedCard{
		cards[0]: {Grades: map[mtgban.Slab]*salesvelocity.GradeSales{
			psa9:  {Sales: []salesvelocity.GradedSale{{At: at(1), Cents: 99900, BestOffer: true}, {At: at(5), Cents: 12300}}},
			bgs10: {Sales: []salesvelocity.GradedSale{{At: at(3), Cents: 45600, Fanatics: true}}},
		}},
		cards[1]: {Grades: map[mtgban.Slab]*salesvelocity.GradeSales{
			psa9: {Sales: []salesvelocity.GradedSale{{At: at(2), Cents: 7800}}},
		}},
	}})

	landing := func() string {
		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded", nil))
		return rec.Body.String()
	}
	body := landing()
	for _, want := range []string{
		`href="/graded?q=is%3Alastsold"`,
		`<span class="slab-showcase-slab">BGS 10</span>`,
		`<span class="slab-showcase-price">$456.00</span>`,
		"Fanatics · ",
		`<span class="slab-showcase-price">$78.00</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the sold carousel is missing %q", want)
		}
	}
	if strings.Contains(body, "999.00") || strings.Contains(body, "123.00") {
		t.Error("the sold carousel shows a best offer, or a card's older sale")
	}
	if strings.Index(body, `href="/graded?q=`+cards[1]+`"`) > strings.Index(body, `href="/graded?q=`+cards[0]+`"`) {
		t.Error("the sold carousel is not newest first")
	}
	if strings.Contains(body, cards[2]) {
		t.Error("the sold carousel shows a card with no sale")
	}

	withSigMode(t, true, true)
	if strings.Contains(landing(), "Graded slabs sold lately") {
		t.Error("a reader without the sales gets the sold carousel")
	}
}

// An open-mode reader sees a store that is no affiliate locked, or nothing of
// it where the config hides those stores, and is told why the carousel is empty.
func TestGradedLandingLocked(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, true)
	cards := somePlainCardUUIDs(t, 2)
	psa9 := &mtgban.Slab{Grader: "PSA", Score: 9}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 40, URL: "u", Slab: psa9}},
		}, mtgban.ScraperInfo{Name: "PARTNERSLABS", Shorthand: "PARTNERSLABS", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[1]: {{Conditions: "NM", Price: 77, URL: "u", Slab: psa9}},
		}, mtgban.ScraperInfo{Name: "OTHERSLABS", Shorthand: "OTHERSLABS", GradedMode: true}),
	}, nil)
	saved := affiliatesPtr.Load()
	t.Cleanup(func() { affiliatesPtr.Store(saved) })
	affiliatesPtr.Store(&AffiliatesConfig{List: []string{"PARTNERSLABS"}})
	withConfigCopy(t)

	landing := func() string {
		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded", nil))
		return rec.Body.String()
	}
	body := landing()
	if !strings.Contains(body, "40.00</span>") || strings.Contains(body, "77.00") || !strings.Contains(body, `data-lucide="lock"`) {
		t.Error("an open-mode reader does not see the affiliate's price and the other store locked")
	}

	Config().SearchHideNonAffiliates = true
	body = landing()
	if strings.Contains(body, `href="/graded?q=`+cards[1]+`"`) || !strings.Contains(body, `href="/graded?q=`+cards[0]+`"`) {
		t.Error("a hidden store's slab is on the carousel, or the affiliate's is not")
	}
	affiliatesPtr.Store(&AffiliatesConfig{})
	body = landing()
	if !strings.Contains(body, "Join BAN to see the graded stores&#39; slabs") {
		t.Error("an empty carousel does not say the slabs are hidden")
	}
}
