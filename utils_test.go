package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestTCGSKU2UUID(t *testing.T) {
	// Swap in a known infos snapshot, restore the real one afterwards.
	prev := infosPtr.Load()
	t.Cleanup(func() { infosPtr.Store(prev) })

	infos := map[string]mtgban.InventoryRecord{
		"tcgskuid": {
			"12345": {{OriginalID: "uuid-aaa"}},
			// Multiple entries for one SKU: the first one wins.
			"67890": {{OriginalID: "uuid-bbb"}, {OriginalID: "uuid-ccc"}},
		},
	}
	infosPtr.Store(&infos)

	cases := []struct {
		name string
		sku  string
		want string
	}{
		{"known sku", "12345", "uuid-aaa"},
		{"first entry wins", "67890", "uuid-bbb"},
		{"unknown sku", "99999", ""},
		{"empty sku", "", ""},
		{"unavailable sentinel", "Unavailable", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcgSKU2UUID(tc.sku); got != tc.want {
				t.Errorf("tcgSKU2UUID(%q) = %q, want %q", tc.sku, got, tc.want)
			}
		})
	}
}

func TestTCGSKU2UUIDNoInfos(t *testing.T) {
	prev := infosPtr.Load()
	t.Cleanup(func() { infosPtr.Store(prev) })

	// No snapshot published yet: must not panic and returns "".
	infosPtr.Store(nil)
	if got := tcgSKU2UUID("12345"); got != "" {
		t.Errorf("tcgSKU2UUID with no infos = %q, want empty string", got)
	}
}

// A page names a store the way scraperName does, which the Go side still
// calls: the first seller, then the first vendor, carrying the shorthand,
// renamed by its override, and failing both, the shorthand's own override.
func TestStoreNamesMatchScraperName(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevOverrides := Config.ScraperConfig.NameOverride
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		Config.ScraperConfig.NameOverride = prevOverrides
	})

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"}),
		mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Name: "Dup Seller", Shorthand: "DUP"}),
		mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Name: "Box Shop", Shorthand: "BOX", SealedMode: true}),
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(nil, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"}),
		mtgban.NewVendorFromBuylist(nil, mtgban.ScraperInfo{Name: "Dup Vendor", Shorthand: "DUP", SealedMode: true}),
		mtgban.NewVendorFromBuylist(nil, mtgban.ScraperInfo{Name: "Box Buyer", Shorthand: "BUY", SealedMode: true}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	Config.ScraperConfig.NameOverride = map[string]string{
		"Card Kingdom": "Card Kingdom (renamed)",
		"GHOST":        "A store no scraper serves",
		// Overrides go by name, so a shorthand's own entry is only a fallback
		"BUY": "Not the buyer's name",
	}

	names := newStoreNames(GetSellers(), GetVendors(), Config.ScraperConfig.NameOverride)
	for _, tc := range []struct {
		shorthand string
		sealed    bool
	}{
		{"CK", false},
		{"DUP", false}, // the seller's, since sellers come first
		{"BOX", true},
		{"BUY", true},
		{"GHOST", false},
		{"NONE", false},
	} {
		got, want := names.Name(tc.shorthand), scraperName(tc.shorthand)
		if got != want {
			t.Errorf("%s: named %q, scraperName says %q", tc.shorthand, got, want)
		}
		sealed := names.Sealed(tc.shorthand)
		if sealed != tc.sealed {
			t.Errorf("%s: sealed = %v, want %v", tc.shorthand, sealed, tc.sealed)
		}
	}
}
