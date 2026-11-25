package main

import (
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

// The custom buylist rule prices no card from the Collectors' Editions, 30A or
// the World Championship Decks, on upload or on search, and still prices
// everything else, those sets' sealed products included.
func TestCustomBuylistSkipsSets(t *testing.T) {
	cardID := firstPlainCard(t)
	skipped := map[string]string{}
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) && skipped[co.SetCode] == "" {
			skipped[co.SetCode] = id
		}
	}
	for _, code := range customBuylistSkipSets {
		if skipped[code] == "" {
			t.Errorf("no %s card in the datastore", code)
		}
	}
	var sealedID string
	for _, id := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) {
			sealedID = id
			break
		}
	}
	if sealedID == "" {
		t.Fatal("no sealed product of a skipped set in the datastore")
	}

	rule := EntryRule{SkipSets: customBuylistSkipSets, Rate: 0.5}
	priced := func(id string) bool {
		out := map[string]map[string]*BanPrice{}
		processEntry(backend(), currentPrices(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", id, "CUSTOM", false, false, false, rule)
		return out[id]["CUSTOM"] != nil
	}
	for code, id := range skipped {
		if priced(id) {
			t.Errorf("%s card %s priced by the custom buylist", code, id)
		}
	}
	if !priced(cardID) {
		t.Errorf("plain card %s not priced by the custom buylist", cardID)
	}
	if !priced(sealedID) {
		t.Errorf("sealed product %s not priced by the custom buylist", sealedID)
	}

	// Search prices the rule off the reference sellers the cookies name.
	singles, sealed := mtgban.InventoryRecord{}, mtgban.InventoryRecord{}
	ids := []string{cardID, sealedID}
	for _, id := range skipped {
		ids = append(ids, id)
		singles.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	}
	singles.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	sealed.Add(sealedID, &mtgban.InventoryEntry{Price: 10, Quantity: 1})
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(singles, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(sealed, mtgban.ScraperInfo{Shorthand: "CKSealed", Name: "Card Kingdom Sealed", SealedMode: true}),
	}, []mtgban.Vendor{})
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5",
		"UploadCustomBuyer": "CK", "UploadCustomSealedBuyer": "CKSealed",
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	found := map[string]map[mtgban.Condition][]SearchEntry{}
	searchCustomBuylist(backend(), currentPrices(), r, ids, found)
	for code, id := range skipped {
		if found[id] != nil {
			t.Errorf("search priced %s card %s off the custom buylist", code, id)
		}
	}
	if found[cardID] == nil || found[sealedID] == nil {
		t.Errorf("search priced %v, want the plain card %s and the sealed product %s", found, cardID, sealedID)
	}
	if tip := found[cardID]["NM"][0].RuleTip; tip != "50% of CK" {
		t.Errorf("the card's tip is %q", tip)
	}
	for _, entries := range found[sealedID] {
		if tip := entries[0].RuleTip; tip != "50% of CKSealed" {
			t.Errorf("the sealed product's tip is %q", tip)
		}
	}
}

// A rate cookie that is not a positive finite number turns the custom
// buylist off, for search and arbit alike, rather than pricing at it; such
// a minimum price is no minimum.
func TestCustomBuylistRefusesABadRate(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  float64
	}{
		{"0.5", 0.5},
		{"NaN", 0},
		{"Inf", 0},
		{"+Inf", 0},
		{"-Inf", 0},
		{"0", 0},
		{"-0.5", 0},
		{"half", 0},
	} {
		read := func(rate, minPrice string) customBuylistRule {
			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			r.AddCookie(&http.Cookie{Name: "UploadCustomOpts", Value: "enabled"})
			r.AddCookie(&http.Cookie{Name: "UploadCustomRate", Value: rate})
			r.AddCookie(&http.Cookie{Name: "UploadCustomMinPrice", Value: minPrice})
			rules := readCustomBuylistRules(r)
			if len(rules) == 0 {
				return customBuylistRule{}
			}
			return rules[0]
		}
		rate := read(tt.value, "").rate
		if rate != tt.want {
			t.Errorf("rate cookie %q reads as %v, want %v", tt.value, rate, tt.want)
		}
		minPrice := read("0.5", tt.value).minPrice
		if minPrice != tt.want {
			t.Errorf("minimum price cookie %q reads as %v, want %v", tt.value, minPrice, tt.want)
		}
	}
}

// The custom buylist prices a card or sealed product only once it has been
// out by the rule's date, on upload and on search and arbit alike.
func TestCustomBuylistSkipsUnreleased(t *testing.T) {
	ids := []string{firstPlainCard(t), backend().GetSealedUUIDs()[0]}
	for _, id := range ids {
		co, err := backend().GetUUID(id)
		if err != nil {
			t.Fatal(err)
		}
		released, err := backend().CardReleaseDate(id)
		if err != nil {
			t.Fatal(err)
		}
		before := released.Add(-24 * time.Hour)

		if customBuylistSkips(backend(), co, released) {
			t.Errorf("%s skipped on its release date %s", id, released.Format(time.DateOnly))
		}
		if !customBuylistSkips(backend(), co, before) {
			t.Errorf("%s priced before its release date %s", id, released.Format(time.DateOnly))
		}

		priced := func(releasedBy time.Time) bool {
			out := map[string]map[string]*BanPrice{}
			rule := EntryRule{ReleasedBy: releasedBy, Rate: 0.5}
			processEntry(backend(), currentPrices(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", id, "CUSTOM", false, false, false, rule)
			return out[id]["CUSTOM"] != nil
		}
		if !priced(released) || priced(before) {
			t.Errorf("%s priced %v on its release date and %v the day before, want true and false", id, priced(released), priced(before))
		}
	}
}

// A card whose set lists no release date counts as not out yet, whatever
// the rule's date.
func TestCustomBuylistSkipsUndated(t *testing.T) {
	co := &matcher.CardObject{}
	co.UUID, co.SetCode = "promo", "UND"
	b := &matcher.Backend{
		UUIDs: map[string]*matcher.CardObject{co.UUID: co},
		Sets:  map[string]*matcher.Set{"UND": {}},
	}
	releasedBy := time.Now()
	if !customBuylistSkips(b, co, releasedBy) {
		t.Error("undated card priced by the custom buylist")
	}
	out := map[string]map[string]*BanPrice{}
	processEntry(b, currentPrices(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", co.UUID, "CUSTOM", false, false, false, EntryRule{ReleasedBy: releasedBy})
	if out[co.UUID]["CUSTOM"] != nil {
		t.Error("undated card priced on upload by the custom buylist")
	}
}

// The fallback fills the grades the reference does not price, best grade
// first, never above a better grade's price, and an index reference, which
// has one price, only when it has none.
func TestCustomBuylistReference(t *testing.T) {
	inv := func(grade mtgban.Condition, price float64) mtgban.InventoryEntry {
		return mtgban.InventoryEntry{Conditions: grade, Price: price}
	}
	index := []mtgban.InventoryEntry{inv("INDEX", 0), inv("INDEX", 5)}

	for _, tt := range []struct {
		name      string
		entries   []mtgban.InventoryEntry
		fallback  []mtgban.InventoryEntry
		isIndex   bool
		wantEntry []mtgban.InventoryEntry
	}{
		{
			name:      "no fallback leaves the listings alone",
			entries:   []mtgban.InventoryEntry{inv("SP", 8)},
			wantEntry: []mtgban.InventoryEntry{inv("SP", 8)},
		},
		{
			name:      "an unpriced fallback leaves the listings alone",
			entries:   []mtgban.InventoryEntry{inv("SP", 8)},
			fallback:  []mtgban.InventoryEntry{inv("INDEX", 0)},
			wantEntry: []mtgban.InventoryEntry{inv("SP", 8)},
		},
		{
			name:      "missing grades take the fallback, in grade order",
			entries:   []mtgban.InventoryEntry{inv("NM", 10), inv("NM", 12), inv("MP", 6)},
			fallback:  index,
			wantEntry: []mtgban.InventoryEntry{inv("NM", 10), inv("NM", 12), inv("SP", 5), inv("MP", 6), inv("HP", 5), inv("PO", 5)},
		},
		{
			name:      "a better grade under the fallback sets the price",
			entries:   []mtgban.InventoryEntry{inv("NM", 20), inv("NM", 22), inv("SP", 15)},
			fallback:  []mtgban.InventoryEntry{inv("INDEX", 18)},
			wantEntry: []mtgban.InventoryEntry{inv("NM", 20), inv("NM", 22), inv("SP", 15), inv("MP", 15), inv("HP", 15), inv("PO", 15)},
		},
		{
			name:      "a worse listed grade does not lower a better one",
			entries:   []mtgban.InventoryEntry{inv("MP", 6)},
			fallback:  []mtgban.InventoryEntry{inv("INDEX", 18)},
			wantEntry: []mtgban.InventoryEntry{inv("NM", 18), inv("SP", 18), inv("MP", 6), inv("HP", 6), inv("PO", 6)},
		},
		{
			name:      "an unpriced grade is a missing one",
			entries:   []mtgban.InventoryEntry{inv("NM", 0), inv("SP", 8), inv("MP", 6), inv("HP", 4), inv("PO", 2)},
			fallback:  index,
			wantEntry: []mtgban.InventoryEntry{inv("NM", 0), inv("NM", 5), inv("SP", 8), inv("MP", 6), inv("HP", 4), inv("PO", 2)},
		},
		{
			name:      "a card the reference lacks",
			fallback:  index,
			wantEntry: []mtgban.InventoryEntry{inv("NM", 5), inv("SP", 5), inv("MP", 5), inv("HP", 5), inv("PO", 5)},
		},
		{
			name:      "a listing outside the grades stays, behind them",
			entries:   []mtgban.InventoryEntry{inv("INDEX", 9)},
			fallback:  []mtgban.InventoryEntry{inv("NM", 5)},
			wantEntry: []mtgban.InventoryEntry{inv("NM", 5), inv("SP", 5), inv("MP", 5), inv("HP", 5), inv("PO", 5), inv("INDEX", 9)},
		},
		{
			name:      "a priced index reference keeps its price",
			entries:   []mtgban.InventoryEntry{inv("INDEX", 9)},
			fallback:  index,
			isIndex:   true,
			wantEntry: []mtgban.InventoryEntry{inv("INDEX", 9)},
		},
		{
			name:      "an index reference without a price takes the fallback's",
			fallback:  index,
			isIndex:   true,
			wantEntry: []mtgban.InventoryEntry{inv("INDEX", 5)},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := customBuylistReference(tt.entries, tt.fallback, tt.isIndex)
			same := func(a, b mtgban.InventoryEntry) bool {
				return a.Conditions == b.Conditions && a.Price == b.Price
			}
			if !slices.EqualFunc(got, tt.wantEntry, same) {
				t.Errorf("got %v, want %v", got, tt.wantEntry)
			}
		})
	}
}

// Naming a fallback turns it on for search and arbit, and a fallback that is
// no price index, a store the reader may not see among them, prices nothing.
func TestCustomBuylistFallbackFollowsTheSetting(t *testing.T) {
	cardID := firstPlainCard(t)
	sealedID := backend().GetSealedUUIDs()[0]
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cardID:   {{Conditions: "NM", Price: 10, Quantity: 1}},
			sealedID: {{Conditions: "NM", Price: 10, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "REF"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cardID:   {{Conditions: "NM", Price: 4, Quantity: 1}},
			sealedID: {{Conditions: "NM", Price: 4, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "TCGLow", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cardID: {{Conditions: "NM", Price: 3, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "HIDDENSTORE"}),
	}, []mtgban.Vendor{})

	for _, tt := range []struct {
		name, fallback string
		wantSP         float64
	}{
		{"none", "", 0},
		{"an index", "TCGLow", 2},
		{"not an index", "HIDDENSTORE", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			for name, value := range map[string]string{
				"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5", "UploadCustomBuyer": "REF",
				"UploadCustomSealedBuyer": "REF", "UploadCustomSinglesFallback": tt.fallback,
				// What the old toggle's select saved, on or off, is not read
				"UploadCustomFallback": "TCGLow",
			} {
				r.AddCookie(&http.Cookie{Name: name, Value: value})
			}

			found := map[string]map[mtgban.Condition][]SearchEntry{}
			searchCustomBuylist(backend(), currentPrices(), r, []string{cardID, sealedID}, found)
			var got float64
			if entries := found[cardID]["SP"]; len(entries) > 0 {
				got = entries[0].Price
			}
			if got != tt.wantSP {
				t.Errorf("search pays %v at SP, want %v", got, tt.wantSP)
			}
			if entries := found[cardID]["NM"]; len(entries) != 1 || entries[0].Price != 5 {
				t.Errorf("search pays %v at NM, want the reference's 5", entries)
			}
			// Sealed products have no grades to fall back for
			if len(found[sealedID]) != 1 {
				t.Errorf("search pays %v on the sealed product, want its one price", found[sealedID])
			}

			source := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
				cardID: {{Conditions: "NM", Price: 10, Quantity: 1}},
			}, mtgban.ScraperInfo{Shorthand: "SRC"})
			vendor := newCustomBuylistVendor(backend(), currentPrices(), readCustomBuylistRules(r), source)
			got = 0
			for _, entry := range vendor.Buylist()[cardID] {
				if entry.Conditions == "SP" {
					got = entry.BuyPrice
				}
			}
			if got != tt.wantSP {
				t.Errorf("arbit pays %v at SP, want %v", got, tt.wantSP)
			}
		})
	}
}

// A product the sealed reference does not price takes the sealed fallback's
// price on search and arbit, and one it does price keeps it. A fallback that
// sells no sealed prices nothing. Search files each under its listing's
// condition, the singles rule's price index aside.
func TestCustomBuylistSealedFallback(t *testing.T) {
	sealedIDs := backend().GetSealedUUIDs()
	if len(sealedIDs) < 2 {
		t.Skip("needs two sealed products")
	}
	listed, missing := sealedIDs[0], sealedIDs[1]
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			listed: {{Conditions: "NM", Price: 10, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "REFSealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			listed:  {{Conditions: "NM", Price: 4, Quantity: 1}},
			missing: {{Conditions: "NM", Price: 6, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "ALTSealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			missing: {{Conditions: "NM", Price: 8, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "SINGLES"}),
	}, []mtgban.Vendor{})

	for _, tt := range []struct {
		name, fallback string
		wantMissing    float64
	}{
		{"none", "", 0},
		{"a sealed seller", "ALTSealed", 3},
		{"not a sealed seller", "SINGLES", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			for name, value := range map[string]string{
				"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5",
				"UploadCustomBuyer": "TCGLow", "UploadCustomSealedBuyer": "REFSealed", "UploadCustomSealedFallback": tt.fallback,
			} {
				r.AddCookie(&http.Cookie{Name: name, Value: value})
			}

			prices := map[string]float64{}
			for _, offer := range customBuylistOffers(backend(), currentPrices(), readCustomBuylistRules(r), []string{listed, missing}) {
				prices[offer.cardID] = offer.price
				if offer.condition != mtgban.NM {
					t.Errorf("search files %s under %s, want its listing's NM", offer.cardID, offer.condition)
				}
			}
			if prices[listed] != 5 || prices[missing] != tt.wantMissing {
				t.Errorf("search pays %v and %v, want 5 and %v", prices[listed], prices[missing], tt.wantMissing)
			}

			source := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
				listed:  {{Conditions: "NM", Price: 10, Quantity: 1}},
				missing: {{Conditions: "NM", Price: 10, Quantity: 1}},
			}, mtgban.ScraperInfo{Shorthand: "SRC", SealedMode: true})
			buylist := newCustomBuylistVendor(backend(), currentPrices(), readCustomBuylistRules(r), source).Buylist()
			var got float64
			if len(buylist[missing]) > 0 {
				got = buylist[missing][0].BuyPrice
			}
			if len(buylist[listed]) != 1 || buylist[listed][0].BuyPrice != 5 || got != tt.wantMissing {
				t.Errorf("arbit pays %v and %v, want 5 and %v", buylist[listed], got, tt.wantMissing)
			}
		})
	}
}

// The tooltip spells the rule the offers were priced by, on one line, with
// only what the rule actually applies.
func TestCustomBuylistRuleTip(t *testing.T) {
	inv := mtgban.InventoryRecord{}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "REF", Name: "Ref Store"}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "REFSealed", Name: "Ref Sealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "ALTSealed", Name: "Alt Sealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "TCGLow", Name: "TCG Low", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market", MetadataOnly: true}),
	}, []mtgban.Vendor{})

	for _, tt := range []struct {
		name string
		rule customBuylistRule
		want string
	}{
		{
			name: "the rate alone",
			rule: customBuylistRule{rate: 0.8, seller: "REF"},
			want: "80% of REF",
		},
		{
			name: "a fractional rate, and a minimum",
			rule: customBuylistRule{rate: 0.07, minPrice: 7, seller: "REF"},
			want: "7% of REF if ≥ $7.00",
		},
		{
			name: "every setting",
			rule: customBuylistRule{rate: 0.825, minPrice: 7, seller: "REF", fallback: "TCGLow"},
			want: "82.5% of REF (or TCG Low) if ≥ $7.00",
		},
		{
			name: "an index reference with another index behind it",
			rule: customBuylistRule{rate: 0.5, seller: "TCGLow", fallback: "TCGMarket"},
			want: "50% of TCG Low (or TCG Market)",
		},
		{
			name: "an index is no fallback for itself",
			rule: customBuylistRule{rate: 0.5, seller: "TCGLow", fallback: "TCGLow"},
			want: "50% of TCG Low",
		},
		{
			name: "a fallback that is no index is not applied",
			rule: customBuylistRule{rate: 0.5, seller: "TCGLow", fallback: "REF"},
			want: "50% of TCG Low",
		},
		{
			name: "a sealed rule, with another sealed seller behind it",
			rule: customBuylistRule{rate: 0.5, minPrice: 20, seller: "REFSealed", fallback: "ALTSealed", sealed: true},
			want: "50% of REFSealed (or ALTSealed) if ≥ $20.00",
		},
		{
			name: "a sealed fallback that sells no sealed is not applied",
			rule: customBuylistRule{rate: 0.5, seller: "REFSealed", fallback: "REF", sealed: true},
			want: "50% of REFSealed",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.tip(currentPrices()); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// Search shows the rule on the custom buylist's row, in its tooltip on
// desktop and in the row's details on the phone.
func TestSearchSpellsTheCustomBuylistRule(t *testing.T) {
	cards := closeVendors(t)
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	co, err := backend().GetUUID(cards[0])
	if err != nil {
		t.Fatal(err)
	}
	ref := mtgban.InventoryRecord{}
	ref.Add(co.UUID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA"))}, currentPrices().vendors)

	const rule = "50% of ZZA if ≥ $2.00"
	for _, tt := range []struct {
		name, mobile, want string
	}{
		{"desktop", "", `title="` + rule + `">Custom Buylist`},
		{"phone", "true", `title="` + rule + `">Custom Buylist`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(co.Name), nil)
			for name, value := range map[string]string{
				"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5",
				"UploadCustomBuyer": "ZZA", "UploadCustomMinPrice": "2",
				"MobileView": tt.mobile,
			} {
				req.AddCookie(&http.Cookie{Name: name, Value: value})
			}
			rec := httptest.NewRecorder()
			testSite.Search(rec, req)
			if page := rec.Body.String(); !strings.Contains(page, tt.want) {
				t.Errorf("no %q on the %d byte page", tt.want, len(page))
			}
		})
	}
}

// The rules after the first come from one cookie a kind, rate:min:seller:
// fallback items joined by commas: an item short of four fields or with no
// valid rate is dropped alone, fields past the fourth are ignored, and the
// chain stops at the tier's limit.
func TestParseCustomBuylistRules(t *testing.T) {
	first := [4]string{"0.8", "7", "CK", "TCGLow"}
	one := customBuylistRule{rate: 0.8, minPrice: 7, seller: "CK", fallback: "TCGLow"}
	two := customBuylistRule{rate: 0.6, minPrice: 2, seller: "TCGLow"}
	for _, tt := range []struct {
		name  string
		first [4]string
		extra string
		limit int
		want  []customBuylistRule
	}{
		{"the first rule alone", first, "", 5, []customBuylistRule{one}},
		{"a second rule", first, "0.6:2:TCGLow:", 5, []customBuylistRule{one, two}},
		{"a bad first rate keeps the rest", [4]string{"NaN"}, "0.6:2:TCGLow:", 5, []customBuylistRule{two}},
		{"a bad rate drops its item", first, "half:2:TCGLow:,0.6:2:TCGLow:", 5, []customBuylistRule{one, two}},
		{"a short item is dropped", first, "0.6:2:TCGLow,0.6:2:TCGLow:", 5, []customBuylistRule{one, two}},
		{"a long item keeps its first four", first, "0.6:2:TCGLow::TCGSealed:", 5, []customBuylistRule{one, two}},
		{"as many as the limit", first, strings.Repeat("0.6:2:TCGLow:,", 6), 5, []customBuylistRule{one, two, two, two, two}},
		{"a limit of one keeps the first", first, "0.6:2:TCGLow:", 1, []customBuylistRule{one}},
		{"a limit of one takes an extra for a bad first", [4]string{"NaN"}, "0.6:2:TCGLow:,0.6:2:TCGLow:", 1, []customBuylistRule{two}},
		{"ten at most", first, strings.Repeat("0.6:2:TCGLow:,", 12), maxCustomBuylistRules, append([]customBuylistRule{one}, slices.Repeat([]customBuylistRule{two}, 9)...)},
		{"none", [4]string{}, "", 5, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCustomBuylistRules(tt.first, tt.extra, tt.limit, false)
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				got[i].sealed = true
			}
			sealed := parseCustomBuylistRules(tt.first, tt.extra, tt.limit, true)
			if !slices.Equal(sealed, got) {
				t.Errorf("got sealed %+v, want %+v", sealed, got)
			}
		})
	}
}

// Singles and sealed have chains of their own on search, upload and arbit,
// each up to the tier's limit, and the first sealed rule takes the singles
// rate and minimum only where it has no rate of its own.
func TestCustomBuylistReadsSinglesAndSealedApart(t *testing.T) {
	sealedRules := func(rules ...customBuylistRule) []customBuylistRule {
		for i := range rules {
			rules[i].sealed = true
		}
		return rules
	}
	one := customBuylistRule{rate: 0.8, minPrice: 7, seller: "CK"}
	for _, tt := range []struct {
		name  string
		limit string
		set   map[string]string
		want  []customBuylistRule
	}{
		{
			name:  "one of each at a limit of one",
			limit: "1",
			set: map[string]string{
				"UploadCustomRules":      "0.6:2:TCGLow:",
				"UploadCustomSealedRate": "0.5", "UploadCustomSealedMinPrice": "40", "UploadCustomSealedRules": "0.4:20:SS:",
			},
			want: append([]customBuylistRule{one}, sealedRules(customBuylistRule{rate: 0.5, minPrice: 40, seller: "SS"})...),
		},
		{
			name:  "two of each at a limit of two",
			limit: "2",
			set: map[string]string{
				"UploadCustomRules":      "0.6:2:TCGLow:,0.5:1:TCGLow:",
				"UploadCustomSealedRate": "0.5", "UploadCustomSealedRules": "0.4:20:SS:,0.3:10:SS:",
			},
			want: append([]customBuylistRule{one, {rate: 0.6, minPrice: 2, seller: "TCGLow"}},
				sealedRules(customBuylistRule{rate: 0.5, seller: "SS"}, customBuylistRule{rate: 0.4, minPrice: 20, seller: "SS"})...),
		},
		{
			name: "no sealed rate takes the singles rate and minimum",
			want: append([]customBuylistRule{one}, sealedRules(customBuylistRule{rate: 0.8, minPrice: 7, seller: "SS"})...),
		},
		{
			name: "a bad sealed rate drops the sealed rule alone",
			set:  map[string]string{"UploadCustomSealedRate": "0"},
			want: []customBuylistRule{one},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			set := map[string]string{
				"UploadCustomRate": "0.8", "UploadCustomMinPrice": "7",
				"UploadCustomBuyer": "CK", "UploadCustomSealedBuyer": "SS",
			}
			maps.Copy(set, tt.set)

			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			form := url.Values{"custombuylist": {"true"}}
			post := httptest.NewRequest(http.MethodPost, "/upload", nil)
			sig := &http.Cookie{Name: signatureCookie, Value: testSig(map[string]string{"UploadCustomMax": tt.limit})}
			r.AddCookie(sig)
			r.AddCookie(&http.Cookie{Name: "UploadCustomOpts", Value: "enabled"})
			post.AddCookie(sig)
			fields := map[string]string{
				"UploadCustomRate": "customrate", "UploadCustomMinPrice": "customminprice", "UploadCustomBuyer": "customseller",
				"UploadCustomRules": "customrules", "UploadCustomSealedRate": "customsealedrate",
				"UploadCustomSealedMinPrice": "customsealedminprice", "UploadCustomSealedBuyer": "customsealedseller",
				"UploadCustomSealedRules": "customsealedrules",
			}
			for cookie, field := range fields {
				if set[cookie] != "" {
					r.AddCookie(&http.Cookie{Name: cookie, Value: set[cookie]})
				}
				form.Set(field, set[cookie])
			}
			post.Form = form

			got := readCustomBuylistRules(r)
			if !slices.Equal(got, tt.want) {
				t.Errorf("the cookies read %+v, want %+v", got, tt.want)
			}
			got = uploadCustomBuylistRules(post)
			if !slices.Equal(got, tt.want) {
				t.Errorf("the form reads %+v, want %+v", got, tt.want)
			}
			got = uploadCustomBuylistRules(r)
			if !slices.Equal(got, tt.want) {
				t.Errorf("upload reads %+v off the cookies, want %+v", got, tt.want)
			}
		})
	}
}

// plainCards returns n nonfoil singles the custom buylist prices.
func plainCards(t *testing.T, n int) []string {
	t.Helper()
	var ids []string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && !co.Sealed && !co.Foil && !co.Etched && !customBuylistSkips(backend(), co, time.Now().Add(-customBuylistMinAge)) {
			ids = append(ids, id)
			if len(ids) == n {
				return ids
			}
		}
	}
	t.Skip("no datastore")
	return nil
}

// Each card is priced by the first rule that applies to it, by each page's
// own reading of applies: a card a rule leaves unpriced, or prices under its
// minimum, falls through to the next rule. Arbit, which buys from NM only,
// falls through on a reference with no NM copy where search takes it.
func TestCustomBuylistChain(t *testing.T) {
	ids := plainCards(t, 4)
	high, low, cheap, spOnly := ids[0], ids[1], ids[2], ids[3]
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			high:   {{Conditions: "NM", Price: 30, Quantity: 1}},
			low:    {{Conditions: "NM", Price: 10, Quantity: 1}},
			spOnly: {{Conditions: "SP", Price: 60, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "REF"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			high:   {{Conditions: "NM", Price: 25, Quantity: 1}},
			low:    {{Conditions: "NM", Price: 8, Quantity: 1}},
			cheap:  {{Conditions: "NM", Price: 3, Quantity: 1}},
			spOnly: {{Conditions: "NM", Price: 40, Quantity: 1}},
		}, mtgban.ScraperInfo{Shorthand: "TCGLow", Name: "TCG Low", MetadataOnly: true}),
	}, []mtgban.Vendor{})

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.8", "UploadCustomMinPrice": "20",
		"UploadCustomBuyer": "REF", "UploadCustomRules": "0.5:5:TCGLow:",
		signatureCookie: testSig(map[string]string{"UploadCustomMax": "5"}),
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	found := map[string]map[mtgban.Condition][]SearchEntry{}
	searchCustomBuylist(backend(), currentPrices(), r, ids, found)
	for _, tt := range []struct {
		id        string
		condition mtgban.Condition
		price     float64
		tip       string
	}{
		{high, "NM", 24, "80% of REF if ≥ $20.00"},
		{low, "INDEX", 4, "50% of TCG Low if ≥ $5.00"},
		{spOnly, "SP", 48, "80% of REF if ≥ $20.00"},
	} {
		entries := found[tt.id][tt.condition]
		if len(found[tt.id]) != 1 || len(entries) != 1 || entries[0].Price != tt.price || entries[0].RuleTip != tt.tip {
			t.Errorf("search pays %+v on %s, want %v at %s by %q", found[tt.id], tt.id, tt.price, tt.condition, tt.tip)
		}
	}
	if found[cheap] != nil {
		t.Errorf("search pays %+v on %s, under every rule's minimum", found[cheap], cheap)
	}

	source := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		high: {{Conditions: "NM", Price: 1, Quantity: 1}}, low: {{Conditions: "NM", Price: 1, Quantity: 1}},
		cheap: {{Conditions: "NM", Price: 1, Quantity: 1}}, spOnly: {{Conditions: "NM", Price: 1, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SRC"})
	buylist := newCustomBuylistVendor(backend(), currentPrices(), readCustomBuylistRules(r), source).Buylist()
	got := map[string]float64{}
	for id, entries := range buylist {
		if len(entries) != 1 || entries[0].Conditions != "NM" {
			t.Errorf("arbit pays %+v on %s, want one NM price", entries, id)
		}
		got[id] = entries[0].BuyPrice
	}
	want := map[string]float64{high: 24, low: 4, spOnly: 20}
	if !maps.Equal(got, want) {
		t.Errorf("arbit pays %v, want %v", got, want)
	}

	tip := customBuylistTips(currentPrices(), readCustomBuylistRules(r), false)
	if tip != "80% of REF if ≥ $20.00\n50% of TCG Low if ≥ $5.00" {
		t.Errorf("the chain's tip is %q", tip)
	}
}

// A tier gets as many rules of each kind as its UploadCustomMax, one where it
// sets none, and never more than maxCustomBuylistRules; dev without signing
// gets them all.
func TestCustomBuylistRulesMax(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  int
	}{
		{"", 1},
		{"1", 1},
		{"5", 5},
		{"10", 10},
		{"50", maxCustomBuylistRules},
		{"0", 1},
		{"-3", 1},
		{"many", 1},
	} {
		sig := testSig(map[string]string{"UploadCustomMax": tt.value})
		got := customBuylistRulesMax(sig)
		if got != tt.want {
			t.Errorf("UploadCustomMax %q allows %d rules, want %d", tt.value, got, tt.want)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.8", "UploadCustomBuyer": "REF",
		"UploadCustomRules": "0.6:2:REF:,0.5:1:REF:",
		signatureCookie:     testSig(map[string]string{"UploadCustomMax": "2"}),
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	isSealed := func(rule customBuylistRule) bool { return rule.sealed }
	got := len(slices.DeleteFunc(readCustomBuylistRules(r), isSealed))
	if got != 2 {
		t.Errorf("a tier of two reads %d rules", got)
	}
	withSigMode(t, true, false)
	got = len(slices.DeleteFunc(readCustomBuylistRules(r), isSealed))
	if got != 3 {
		t.Errorf("dev without signing reads %d rules, want every one", got)
	}
}

// The custom buylist prices no oversized card, on upload or on search, and
// still prices a plain card off the same reference.
func TestCustomBuylistSkipsOversized(t *testing.T) {
	cards := closeVendors(t)
	releasedBy := time.Now().Add(-customBuylistMinAge)
	var oversized string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && co.IsOversized && !(EntryRule{ReleasedBy: releasedBy}).skips(backend(), co) {
			oversized = id
			break
		}
	}
	if oversized == "" {
		t.Fatal("no oversized card in the datastore")
	}
	var plain string
	for _, id := range cards {
		co, err := backend().GetUUID(id)
		if err == nil && !customBuylistSkips(backend(), co, releasedBy) {
			plain = id
			break
		}
	}
	if plain == "" {
		t.Fatalf("every one of %v is skipped by the custom buylist", cards)
	}

	ref := mtgban.InventoryRecord{}
	for _, id := range []string{oversized, plain} {
		ref[id] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}
	}
	withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA"))}, currentPrices().vendors)

	form := url.Values{
		"mode":          {"true"},
		"stores":        {"ZZV"},
		"rows":          {oversized + "\t1\t\t0\t\n" + plain + "\t1\t\t0\t\n"},
		"custombuylist": {"true"},
		"customseller":  {"ZZA"},
		"customrate":    {"0.5"},
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	testSite.Upload(rec, req)
	page := rec.Body.String()
	if strings.Contains(page, "/go/b/CUSTOM/"+oversized+`"`) {
		t.Errorf("upload priced the oversized card %s off the custom buylist", oversized)
	}
	if !strings.Contains(page, "/go/b/CUSTOM/"+plain+`"`) {
		t.Errorf("upload did not price the plain card %s off the custom buylist", plain)
	}

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5", "UploadCustomBuyer": "ZZA",
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	found := map[string]map[mtgban.Condition][]SearchEntry{}
	searchCustomBuylist(backend(), currentPrices(), r, []string{oversized, plain}, found)
	if found[oversized] != nil {
		t.Errorf("search priced the oversized card %s off the custom buylist", oversized)
	}
	if found[plain] == nil {
		t.Errorf("search did not price the plain card %s off the custom buylist", plain)
	}
}
