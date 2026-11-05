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
			return readCustomBuylistRule(r)
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

// The toggle turns the fallback on for search and arbit, and a fallback that
// is no price index, a store the reader may not see among them, prices nothing.
func TestCustomBuylistFallbackFollowsTheToggle(t *testing.T) {
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
		name, opts, fallback string
		wantSP               float64
	}{
		{"off", "enabled", "TCGLow", 0},
		{"on", "enabled,fallback", "TCGLow", 2},
		{"on, not an index", "enabled,fallback", "HIDDENSTORE", 0},
		{"on, unset", "enabled,fallback", "", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			for name, value := range map[string]string{
				"UploadCustomOpts": tt.opts, "UploadCustomRate": "0.5", "UploadCustomBuyer": "REF",
				"UploadCustomSealedBuyer": "REF", "UploadCustomFallback": tt.fallback,
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
			vendor := newCustomBuylistVendor(backend(), currentPrices(), readCustomBuylistRule(r), source)
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

// The tooltip spells the rule the offers were priced by, on one line, with
// only what the rule actually applies.
func TestCustomBuylistRuleTip(t *testing.T) {
	inv := mtgban.InventoryRecord{}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "REF", Name: "Ref Store"}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "REFSealed", Name: "Ref Sealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "TCGLow", Name: "TCG Low", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market", MetadataOnly: true}),
	}, []mtgban.Vendor{})

	for _, tt := range []struct {
		name   string
		rule   customBuylistRule
		sealed bool
		want   string
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
			name:   "sealed has its own reference and no fallback",
			rule:   customBuylistRule{rate: 0.5, minPrice: 20, seller: "REF", sealedSeller: "REFSealed", fallback: "TCGLow"},
			sealed: true,
			want:   "50% of REFSealed if ≥ $20.00",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.tip(currentPrices(), tt.sealed); got != tt.want {
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
		{"phone", "true", `<div class="m-detail-note">` + rule + `</div>`},
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
