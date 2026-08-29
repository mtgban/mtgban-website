package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestLoadSummary(t *testing.T) {
	tests := []struct {
		name   string
		loaded int
		failed []string
		want   string
	}{
		{
			name:   "all loaded",
			loaded: 3,
			want:   "Server loaded 3/3 scrapers",
		},
		{
			name:   "unloaded scrapers still count towards the total",
			loaded: 1,
			failed: []string{"a/retail/A: no such object"},
			want: "Server loaded 1/2 scrapers\n" +
				"not loaded (1): a/retail/A: no such object",
		},
		{
			name:   "listed in a stable order whatever order they finished in",
			loaded: 0,
			failed: []string{"c/retail/C: timeout", "a/retail/A: timeout"},
			want: "Server loaded 0/2 scrapers\n" +
				"not loaded (2): a/retail/A: timeout; c/retail/C: timeout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := loadSummary(test.loaded, test.failed)
			if got != test.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, test.want)
			}
		})
	}
}

// buylistOf builds a vendor holding n cards, stamped at ts so the freshness
// check has something to compare.
func buylistOf(shorthand string, n int, ts time.Time) mtgban.Vendor {
	bl := mtgban.BuylistRecord{}
	for i := range n {
		bl[fmt.Sprintf("uuid-%d", i)] = []mtgban.BuylistEntry{{BuyPrice: 1}}
	}
	return mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, BuylistTimestamp: &ts,
	})
}

func inventoryOf(shorthand string, n int, ts time.Time) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for i := range n {
		inv[fmt.Sprintf("uuid-%d", i)] = []mtgban.InventoryEntry{{Price: 1}}
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, InventoryTimestamp: &ts,
	})
}

// An empty dump is the case the shrink check cannot see - it asks for half the
// previous size, and zero is not half of anything - so it gets its own test on
// both paths a scraper can arrive by.
func TestBuildNextVendorsRejectsEmpty(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	now := time.Now()

	t.Run("first registration", func(t *testing.T) {
		next, err := buildNextVendors(nil, buylistOf("CK", 0, now), -1)
		if err == nil {
			t.Fatalf("empty buylist registered %d vendors, want an error", len(next))
		}
	})

	t.Run("replacing a loaded one", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		_, err := buildNextVendors(current, buylistOf("CK", 0, now), 0)
		if err == nil {
			t.Fatal("empty buylist replaced 500 entries, want an error")
		}
	})

	t.Run("a full one still replaces", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		next, err := buildNextVendors(current, buylistOf("CK", 500, now), 0)
		if err != nil {
			t.Fatalf("full buylist rejected: %s", err)
		}
		if len(next[0].Buylist()) != 500 {
			t.Errorf("got %d entries, want 500", len(next[0].Buylist()))
		}
	})

	t.Run("a halved one is still rejected", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		_, err := buildNextVendors(current, buylistOf("CK", 100, now), 0)
		if err == nil {
			t.Fatal("buylist missing 80% of its entries accepted, want an error")
		}
	})
}

func TestBuildNextSellersRejectsEmpty(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	now := time.Now()

	t.Run("first registration", func(t *testing.T) {
		next, err := buildNextSellers(nil, inventoryOf("CK", 0, now), -1)
		if err == nil {
			t.Fatalf("empty inventory registered %d sellers, want an error", len(next))
		}
	})

	t.Run("replacing a loaded one", func(t *testing.T) {
		current := []mtgban.Seller{inventoryOf("CK", 500, old)}
		_, err := buildNextSellers(current, inventoryOf("CK", 0, now), 0)
		if err == nil {
			t.Fatal("empty inventory replaced 500 entries, want an error")
		}
	})

	t.Run("a full one still replaces", func(t *testing.T) {
		current := []mtgban.Seller{inventoryOf("CK", 500, old)}
		next, err := buildNextSellers(current, inventoryOf("CK", 500, now), 0)
		if err != nil {
			t.Fatalf("full inventory rejected: %s", err)
		}
		if len(next[0].Inventory()) != 500 {
			t.Errorf("got %d entries, want 500", len(next[0].Inventory()))
		}
	})
}
