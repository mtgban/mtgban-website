package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// offersPass reports whether a card's built offers on one side pass filter:
// empty wants one under a condition other than INDEX, any wants one of the
// named stores under a known condition.
func offersPass(offers map[mtgban.Condition][]SearchEntry, filter FilterPostElem) bool {
	for cond, entries := range offers {
		for _, entry := range entries {
			switch filter.Name {
			case "empty":
				if offersUnder(cond) {
					return true
				}
			case "any":
				if listsUnder(cond) && slices.Contains(filter.Values, strings.ToLower(entry.Shorthand)) {
					return true
				}
			}
		}
	}
	return false
}

// keptByOffers is what PostSearchFilter keeps of keys, judged on the offers
// collectOffers builds.
func keptByOffers(sellers, vendors map[string]map[mtgban.Condition][]SearchEntry, keys []string, filters []FilterPostElem) []string {
	var kept []string
	for _, cardID := range keys {
		skip := false
		for _, filter := range filters {
			seller := offersPass(sellers[cardID], filter)
			vendor := offersPass(vendors[cardID], filter)
			switch {
			case filter.OnlyForSeller:
				skip = !seller
			case filter.OnlyForVendor:
				skip = !vendor
			default:
				skip = !seller && !vendor
			}
			if skip {
				break
			}
		}
		if !skip {
			kept = append(kept, cardID)
		}
	}
	return kept
}

// withPostStores serves sellers and vendors and reads them as the post
// filters ask them.
func withPostStores(t *testing.T, sellers []mtgban.Seller, vendors []mtgban.Vendor, filters []FilterPostElem) *postStores {
	t.Helper()
	withPrices(t, sellers, vendors)
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	return newPostStores(nil, currentPrices(), req, nil, SearchConfig{PostFilters: filters})
}

// The empty filter counts an INDEX quote as no offer: a card with nothing,
// or an index price alone, is dropped, and one offer under any other
// condition keeps it, an index price beside it or not.
func TestPostFilterEmptyAsksStores(t *testing.T) {
	cards := []string{"missing", "index-only", "nm-only", "both", "odd"}
	index := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"index-only": {{Price: 1, Conditions: "NM"}},
		"both":       {{Price: 1, Conditions: "NM"}},
	}, mtgban.ScraperInfo{Shorthand: "TCGLow", MetadataOnly: true})
	retail := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"nm-only": {{Price: 1, Conditions: "NM", Quantity: 1}},
		"both":    {{Price: 1, Conditions: "NM", Quantity: 1}},
		"odd":     {{Price: 1, Conditions: "Sealed", Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "CK"})
	stores := withPostStores(t, []mtgban.Seller{index, retail}, nil, []FilterPostElem{{Name: "empty"}})

	got := postFilterEmpty(nil, slices.Clone(cards), stores, true)
	want := []string{"missing", "index-only"}
	if !slices.Equal(got, want) {
		t.Errorf("empty skips %v, want %v", got, want)
	}
}

// The any filter counts a store under any of the page's conditions, INDEX
// included, by the lower-case shorthand the filter arrives as; a condition
// the page does not list is not read.
func TestPostFilterAnyAsksStores(t *testing.T) {
	index := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"a": {{Price: 1, Conditions: "NM"}},
	}, mtgban.ScraperInfo{Shorthand: "TCGLow", MetadataOnly: true})
	retail := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"a": {{Price: 1, Conditions: "SP", Quantity: 1}},
		"b": {{Price: 1, Conditions: "Sealed", Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "CK"})
	stores := withPostStores(t, []mtgban.Seller{index, retail}, nil, nil)

	cards := []string{"a", "b", "missing"}
	for _, tc := range []struct {
		stores []string
		skips  []string
	}{
		{[]string{"tcglow"}, []string{"b", "missing"}},
		{[]string{"ck"}, []string{"b", "missing"}},
		{[]string{"scg", "ck"}, []string{"b", "missing"}},
		{[]string{"scg"}, cards},
		{[]string{"TCGLow"}, cards},
	} {
		got := postFilterAny(tc.stores, slices.Clone(cards), stores, true)
		if !slices.Equal(got, tc.skips) {
			t.Errorf("any %v skips %v, want %v", tc.stores, got, tc.skips)
		}
	}
}

// A filter bound to one side reads that side; one bound to neither drops a
// card only when both sides agree.
func TestPostSearchFilterSides(t *testing.T) {
	keys := []string{"retail-only", "buylist-only", "both", "neither"}
	seller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"retail-only": {{Price: 1, Conditions: "NM", Quantity: 1}},
		"both":        {{Price: 1, Conditions: "NM", Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "CK"})
	ck := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{
		"buylist-only": {{BuyPrice: 1, Conditions: "NM", Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "CK"})
	scg := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{
		"both": {{BuyPrice: 1, Conditions: "NM", Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SCG"})

	for _, tc := range []struct {
		name    string
		filters []FilterPostElem
		want    []string
	}{
		{"none", nil, keys},
		{"empty", []FilterPostElem{{Name: "empty"}}, []string{"retail-only", "buylist-only", "both"}},
		{"empty vendors", []FilterPostElem{{Name: "empty", OnlyForVendor: true}}, []string{"buylist-only", "both"}},
		{"empty sellers", []FilterPostElem{{Name: "empty", OnlyForSeller: true}}, []string{"retail-only", "both"}},
		{"any ck sellers", []FilterPostElem{{Name: "any", Values: []string{"ck"}, OnlyForSeller: true}}, []string{"retail-only", "both"}},
		{"any scg", []FilterPostElem{{Name: "any", Values: []string{"scg"}}}, []string{"both"}},
	} {
		stores := withPostStores(t, []mtgban.Seller{seller}, []mtgban.Vendor{ck, scg}, tc.filters)
		got := PostSearchFilter(SearchConfig{PostFilters: tc.filters}, keys, stores)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s kept %v, want %v", tc.name, got, tc.want)
		}
	}
}

// What the stores answer about each card is what the built offers show,
// with the store, condition and price filters and the custom buylist applied
// alike, so a search keeps the same cards whether or not it builds them.
func TestPostStoresMatchCollectedOffers(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	ds := currentDatastore()

	// Six cards: one at two retail stores and the index, one at the index
	// and a vendor, one at retail and a vendor index, one at a vendor alone,
	// one at the index and a sealed vendor index, and one nobody offers.
	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore holds too few plain cards for this test")
	}
	now := time.Now()
	index := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		uuids[0]: {{Price: 3, Conditions: "NM"}},
		uuids[1]: {{Price: 2, Conditions: "NM"}},
		uuids[4]: {{Price: 1, Conditions: "NM"}},
	}, mtgban.ScraperInfo{Name: "Presence Index", Shorthand: "PRESIDX", MetadataOnly: true, InventoryTimestamp: &now})
	retail := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		uuids[0]: {{Price: 5, Conditions: "NM", Quantity: 1}, {Price: 4, Conditions: "SP", Quantity: 2}},
		uuids[2]: {{Price: 0.5, Conditions: "MP", Quantity: 1}},
	}, mtgban.ScraperInfo{Name: "Presence Retail", Shorthand: "PRESNM", InventoryTimestamp: &now})
	vendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{
		uuids[1]: {{BuyPrice: 2, Conditions: "NM", Quantity: 1}},
		uuids[3]: {{BuyPrice: 1, Conditions: "NM", Quantity: 1}},
	}, mtgban.ScraperInfo{Name: "Presence Vendor", Shorthand: "PRESVEND", BuylistTimestamp: &now})
	vindex := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{
		uuids[2]: {{BuyPrice: 1, Conditions: "NM"}},
	}, mtgban.ScraperInfo{Name: "Presence Vendor Index", Shorthand: "PRESVIDX", MetadataOnly: true, BuylistTimestamp: &now})
	// A second retail store with the first's card, so the question stops at
	// the first of two stores offering it
	retail2 := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		uuids[0]: {{Price: 6, Conditions: "NM", Quantity: 1}},
	}, mtgban.ScraperInfo{Name: "Presence Retail Two", Shorthand: "PRESNM2", InventoryTimestamp: &now})
	// A sealed index keeps its conditions, so it counts as an offer
	sindex := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{
		uuids[4]: {{BuyPrice: 1, Conditions: "NM"}},
	}, mtgban.ScraperInfo{Name: "Presence Sealed Index", Shorthand: "PRESSIDX", MetadataOnly: true, SealedMode: true, BuylistTimestamp: &now})
	withPrices(t, []mtgban.Seller{index, retail, retail2}, []mtgban.Vendor{vendor, vindex, sindex})

	plain := httptest.NewRequest(http.MethodGet, "/search", nil)
	custom := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5", "UploadCustomBuyer": "PRESNM",
	} {
		custom.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	query := strings.Join(uuids, ",")
	// A decklist repeats a card once per copy, and each copy is judged; the
	// custom buylist prices the card once for both
	keys := append(slices.Clone(uuids), uuids[2])
	for _, tc := range []struct {
		name   string
		opts   string
		misc   searchMiscOpts
		req    *http.Request
		custom bool
	}{
		{name: "plain", req: plain},
		{name: "skip empty", misc: searchMiscOpts{"skipEmpty"}, req: plain},
		{name: "a store", opts: "store:presnm", req: plain},
		{name: "not a store", opts: "-store:presnm", req: plain},
		{name: "a vendor", opts: "vendor:presvend", req: plain},
		{name: "an index seller", opts: "seller:presidx", req: plain},
		{name: "no index", opts: "skip:index", misc: searchMiscOpts{"skipEmpty"}, req: plain},
		{name: "a condition", opts: "cond:NM", misc: searchMiscOpts{"skipEmpty"}, req: plain},
		{name: "a price", opts: "price>4", misc: searchMiscOpts{"skipEmpty"}, req: plain},
		{name: "a buy price", opts: "buy_price>1.5", misc: searchMiscOpts{"skipEmpty"}, req: plain},
		{name: "custom buylist", misc: searchMiscOpts{"skipEmpty"}, req: custom, custom: true},
		{name: "custom buylist alone", opts: "skip:emptybuylist", req: custom, custom: true},
		{name: "custom buylist vendors", opts: "vendor:custom", req: custom, custom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := parseSearchOptionsNG(b, query, nil, nil, nil)
			opts := parseSearchOptionsNG(b, NameToBeFound+" "+tc.opts, nil, nil, tc.misc)
			config.StoreFilters = opts.StoreFilters
			config.EntryFilters = opts.EntryFilters
			config.PriceFilters = opts.PriceFilters
			config.PostFilters = opts.PostFilters
			config.CustomBuylist = tc.custom

			stores := newPostStores(b, currentPrices(), tc.req, keys, config)
			foundSellers, foundVendors := collectOffers(b, currentPrices(), tc.req, config, keys)
			got := PostSearchFilter(config, keys, stores)
			want := keptByOffers(foundSellers, foundVendors, keys, config.PostFilters)
			if !slices.Equal(got, want) {
				t.Errorf("the stores keep %v, the offers keep %v", got, want)
			}

			result := runSearch(tc.req, ds, currentPrices(), config)
			if result.message != "" && len(result.keys) == 0 && len(config.PostFilters) == 0 {
				t.Fatalf("the search found nothing: %s", result.message)
			}
			got = slices.Sorted(slices.Values(result.keys))
			want = slices.Sorted(slices.Values(keptByOffers(foundSellers, foundVendors, uuids, config.PostFilters)))
			if !slices.Equal(got, want) {
				t.Errorf("search kept %v, the offers keep %v", got, want)
			}
			if len(config.PostFilters) > 0 && len(want) == len(uuids) {
				t.Errorf("%s dropped nothing; the fixture does not exercise it", tc.name)
			}
		})
	}
}
