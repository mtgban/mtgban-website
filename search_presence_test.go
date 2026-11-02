package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// presenceOfOffers reads built offers the way searchOfferPresence reads the
// stores, so the two can be compared.
func presenceOfOffers(found map[string]map[mtgban.Condition][]SearchEntry) offerPresences {
	p := offerPresences{}
	for cardID, conds := range found {
		for cond, entries := range conds {
			for _, entry := range entries {
				p.add(cardID, cond, entry.Shorthand)
			}
		}
	}
	return p
}

// samePresence reports whether two presences record the same cards, with the
// same offer flag and stores.
func samePresence(a, b offerPresences) bool {
	if len(a) != len(b) {
		return false
	}
	for cardID, pa := range a {
		pb := b[cardID]
		if pb == nil || pa.offer != pb.offer || !maps.Equal(pa.stores, pb.stores) {
			return false
		}
	}
	return true
}

// The empty filter counts an INDEX quote as no offer: a card with nothing,
// or an index price alone, is dropped, and one offer under any other
// condition keeps it, an index price beside it or not.
func TestPostFilterEmptyReadsPresence(t *testing.T) {
	p := offerPresences{}
	p.add("index-only", "INDEX", "TCGLow")
	p.add("nm-only", "NM", "CK")
	p.add("both", "INDEX", "TCGLow")
	p.add("both", "NM", "CK")
	p.add("odd", "Sealed", "CK")

	for card, want := range map[string]bool{
		"missing": true, "index-only": true, "nm-only": false, "both": false, "odd": false,
	} {
		if got := postFilterEmpty(nil, card, p); got != want {
			t.Errorf("empty skips %s: %v, want %v", card, got, want)
		}
	}
}

// The any filter counts a store under any of the page's conditions, INDEX
// included, by the lower-case shorthand the filter arrives as; a condition
// the page does not list is not read.
func TestPostFilterAnyReadsPresence(t *testing.T) {
	p := offerPresences{}
	p.add("a", "INDEX", "TCGLow")
	p.add("a", "SP", "CK")
	p.add("b", "Sealed", "CK")

	for _, tc := range []struct {
		card   string
		stores []string
		skip   bool
	}{
		{"a", []string{"tcglow"}, false},
		{"a", []string{"ck"}, false},
		{"a", []string{"scg", "ck"}, false},
		{"a", []string{"scg"}, true},
		{"a", []string{"TCGLow"}, true},
		{"b", []string{"ck"}, true},
		{"missing", []string{"ck"}, true},
	} {
		if got := postFilterAny(tc.stores, tc.card, p); got != tc.skip {
			t.Errorf("any %v skips %s: %v, want %v", tc.stores, tc.card, got, tc.skip)
		}
	}
}

// A filter bound to one side reads that side; one bound to neither drops a
// card only when both sides agree.
func TestPostSearchFilterSides(t *testing.T) {
	sellers, vendors := offerPresences{}, offerPresences{}
	sellers.add("retail-only", "NM", "CK")
	vendors.add("buylist-only", "NM", "CK")
	sellers.add("both", "NM", "CK")
	vendors.add("both", "NM", "SCG")
	keys := []string{"retail-only", "buylist-only", "both", "neither"}

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
		got := PostSearchFilter(SearchConfig{PostFilters: tc.filters}, keys, sellers, vendors)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s kept %v, want %v", tc.name, got, tc.want)
		}
	}
}

// What the pre-pass records of each card is what the built offers show,
// with the store, condition and price filters and the custom buylist applied
// alike, so a search keeps the same cards whether or not it builds them.
func TestOfferPresenceMatchesCollectedOffers(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	ds := currentDatastore()

	// Six cards: one at a retail store and the index, one at the index and
	// a vendor, one at retail and a vendor index, one at a vendor alone, one
	// at the index alone, and one nobody offers.
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
	publishStores(t, []mtgban.Seller{index, retail}, []mtgban.Vendor{vendor, vindex})

	plain := httptest.NewRequest(http.MethodGet, "/search", nil)
	custom := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5", "UploadCustomBuyer": "PRESNM",
	} {
		custom.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	query := strings.Join(uuids, ",")
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

			sellers, vendors := searchOfferPresence(b, tc.req, uuids, config)
			foundSellers, foundVendors := collectOffers(b, tc.req, config, uuids)
			if !samePresence(sellers, presenceOfOffers(foundSellers)) {
				t.Errorf("seller presence %v, offers show %v", sellers, presenceOfOffers(foundSellers))
			}
			if !samePresence(vendors, presenceOfOffers(foundVendors)) {
				t.Errorf("vendor presence %v, offers show %v", vendors, presenceOfOffers(foundVendors))
			}

			result := runSearch(tc.req, ds, config)
			if result.message != "" && len(result.keys) == 0 && len(config.PostFilters) == 0 {
				t.Fatalf("the search found nothing: %s", result.message)
			}
			got := slices.Sorted(slices.Values(result.keys))
			want := slices.Sorted(slices.Values(PostSearchFilter(config, uuids, presenceOfOffers(foundSellers), presenceOfOffers(foundVendors))))
			if !slices.Equal(got, want) {
				t.Errorf("search kept %v, the offers keep %v", got, want)
			}
			if len(config.PostFilters) > 0 && len(want) == len(uuids) {
				t.Errorf("%s dropped nothing; the fixture does not exercise it", tc.name)
			}
		})
	}
}
