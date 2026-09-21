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

// seedMkmSellers publishes the Cardmarket sellers shaped the way the scrapers
// leave them - the two singles indexes and the sealed one - keyed by uuid,
// with the product each entry priced in OriginalID.
func seedMkmSellers(t *testing.T, trend, low, sealed map[string]string) {
	t.Helper()

	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	build := func(byUUID map[string]string) mtgban.InventoryRecord {
		inv := mtgban.InventoryRecord{}
		for uuid, mkmID := range byUUID {
			inv.Add(uuid, &mtgban.InventoryEntry{OriginalID: mkmID, Price: 1})
		}
		return inv
	}

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(build(trend), mtgban.ScraperInfo{
			Name: "Cardmarket Trend", Shorthand: "MKMTrend", MetadataOnly: true,
		}),
		mtgban.NewSellerFromInventory(build(low), mtgban.ScraperInfo{
			Name: "Cardmarket Low", Shorthand: "MKMLow", MetadataOnly: true,
		}),
		mtgban.NewSellerFromInventory(build(sealed), mtgban.ScraperInfo{
			Name: "Cardmarket Sealed", Shorthand: "MKMSealed", SealedMode: true,
		}),
	}
	sellersPtr.Store(&sellers)
}

func TestMkmID2UUID(t *testing.T) {
	seedMkmSellers(t,
		map[string]string{
			"uuid-aaa": "265854",
			"uuid-bbb": "300001",
			"uuid-ddd": "400001",
			"uuid-eee": "400002",
		},
		map[string]string{
			// The same card priced by the other index: an agreement, not a
			// collision.
			"uuid-aaa": "265854",
			// Two printings Cardmarket shelves under one product: the id
			// names neither.
			"uuid-ccc": "300001",
			// The same printing's other finish. Cardmarket sells a
			// printing's finishes as one product, which is half the Magic
			// shelves, and the upload's foil column says which is meant.
			"uuid-ddd_f": "400001",
			// Etched is filed under its own suffix too, and is the same
			// card for the same reason.
			"uuid-eee_e": "400002",
		},
		map[string]string{
			// A sealed product, published by the sealed scraper rather than
			// either singles index.
			"uuid-box": "500001",
		},
	)

	for _, tc := range []struct {
		name  string
		mkmID string
		want  string
	}{
		{"a product one printing answers to", "265854", "uuid-aaa"},
		{"a product two printings answer to", "300001", ""},
		{"a product's two finishes", "400001", "uuid-ddd"},
		{"a product's etched twin", "400002", "uuid-eee"},
		{"a sealed product", "500001", "uuid-box"},
		{"unknown product", "999999", ""},
		{"empty id", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mkmID2UUID(tc.mkmID); got != tc.want {
				t.Errorf("mkmID2UUID(%q) = %q, want %q", tc.mkmID, got, tc.want)
			}
		})
	}
}

func TestMkmID2UUIDNoSellers(t *testing.T) {
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	// A deployment of a game Cardmarket does not sell has no such seller:
	// the lookup answers nothing rather than failing.
	sellersPtr.Store(nil)
	if got := mkmID2UUID("265854"); got != "" {
		t.Errorf("mkmID2UUID with no sellers = %q, want empty string", got)
	}
}
