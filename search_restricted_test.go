package main

import (
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A store the default blocklist hides renders its name in italics on both
// pages, on seller and buyer rows alike, and an open store does not.
func TestRestrictedStoreRendersItalic(t *testing.T) {
	const id = "card"
	rows := func() []SearchEntry {
		return []SearchEntry{
			{ScraperName: "Hidden", Shorthand: "HID", Price: 5, URL: "https://example.com/h", Restricted: true},
			{ScraperName: "Open", Shorthand: "OPN", Price: 4, URL: "https://example.com/o"},
		}
	}
	for _, mobile := range []bool{false, true} {
		v := PageVars{
			UserNav:  &NavElem{Short: "b"},
			IsMobile: mobile,
			SearchVars: SearchVars{
				SearchRan:    true,
				AllKeys:      []string{id},
				CondKeys:     []mtgban.Condition{"INDEX", "NM"},
				FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{id: {"NM": rows()}},
				FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{id: {"NM": rows()}},
				SearchQuery:  "a card",
			},
			Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
		}
		out := renderPage(t, "search.html", mobile, v)

		class := `class="store-name store-restricted"`
		if mobile {
			class = `class="m-vendor-name m-vendor-restricted"`
		}
		if n := strings.Count(out, class); n != 2 {
			t.Errorf("mobile=%v: %d names carry %s, want 2 (seller and buyer)", mobile, n, class)
		}
	}
}

// Sellers read the retail blocklist and vendors the buylist one, each
// marking only the stores on its own list.
func TestSearchMarksRestrictedStores(t *testing.T) {
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"RHID"}
	Config().Stores.SearchBuylistBlockList = []string{"BHID"}

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	now := time.Now()
	inv := mtgban.InventoryRecord{"card": {{Conditions: "NM", Price: 5}}}
	bl := mtgban.BuylistRecord{"card": {{Conditions: "NM", BuyPrice: 3}}}
	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor
	for _, short := range []string{"RHID", "BHID", "OPN"} {
		info := mtgban.ScraperInfo{Name: short, Shorthand: short, InventoryTimestamp: &now, BuylistTimestamp: &now}
		sellers = append(sellers, mtgban.NewSellerFromInventory(inv, info))
		vendors = append(vendors, mtgban.NewVendorFromBuylist(bl, info))
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	for _, tc := range []struct {
		kind string
		rows []SearchEntry
		want string
	}{
		{"seller", searchSellersNG([]string{"card"}, SearchConfig{})["card"]["NM"], "RHID"},
		{"vendor", searchVendorsNG([]string{"card"}, SearchConfig{})["card"]["NM"], "BHID"},
	} {
		if len(tc.rows) != 3 {
			t.Fatalf("%s: got %d rows, want 3", tc.kind, len(tc.rows))
		}
		for _, row := range tc.rows {
			if row.Restricted != (row.Shorthand == tc.want) {
				t.Errorf("%s %s: Restricted = %v", tc.kind, row.Shorthand, row.Restricted)
			}
		}
	}
}
