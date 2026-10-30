package main

import (
	"maps"
	"math"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// TestCustomBuylistEntries pins what the custom buylist pays on arbit: the
// reference's best price of each grade at the rate, NM first, gated on the
// best price.
func TestCustomBuylistEntries(t *testing.T) {
	rule := customBuylistRule{rate: 0.5, minPrice: 5}
	inv := func(grade mtgban.Condition, price float64) mtgban.InventoryEntry {
		return mtgban.InventoryEntry{Conditions: grade, Price: price}
	}
	bl := func(grade mtgban.Condition, price float64) mtgban.BuylistEntry {
		return mtgban.BuylistEntry{Conditions: grade, BuyPrice: price}
	}

	tests := []struct {
		name      string
		inventory []mtgban.InventoryEntry
		isIndex   bool
		want      []mtgban.BuylistEntry
	}{
		{
			name:      "best of each grade at the rate",
			inventory: []mtgban.InventoryEntry{inv("NM", 10), inv("NM", 12), inv("SP", 8), inv("MP", 6)},
			want:      []mtgban.BuylistEntry{bl("NM", 5), bl("SP", 4), bl("MP", 3)},
		},
		{
			name:      "unpriced listings are skipped",
			inventory: []mtgban.InventoryEntry{inv("NM", 0), inv("NM", math.NaN()), inv("NM", 10)},
			want:      []mtgban.BuylistEntry{bl("NM", 5)},
		},
		{
			name:      "below the minimum price",
			inventory: []mtgban.InventoryEntry{inv("NM", 4.99), inv("SP", 4)},
		},
		{
			name:      "no NM copy listed",
			inventory: []mtgban.InventoryEntry{inv("SP", 10)},
		},
		{
			name:      "an index buys at NM only, whatever grade it files under",
			inventory: []mtgban.InventoryEntry{inv("INDEX", 10), inv("SP", 8)},
			isIndex:   true,
			want:      []mtgban.BuylistEntry{bl("NM", 5)},
		},
		{
			name: "nothing listed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := customBuylistEntries(tt.inventory, rule, tt.isIndex)
			same := func(a, b mtgban.BuylistEntry) bool {
				return a.Conditions == b.Conditions && a.BuyPrice == b.BuyPrice
			}
			if !slices.EqualFunc(got, tt.want, same) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewCustomBuylistVendor pins what the vendor is priced off: the sealed
// reference for a sealed source, the skipped sets for singles only, the index
// rule for the reference in use, and no vendor without a loaded reference.
func TestNewCustomBuylistVendor(t *testing.T) {
	cardID := firstPlainCard(t)
	var skippedID, sealedID string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && !co.Sealed && slices.Contains(customBuylistSkipSets, co.SetCode) {
			skippedID = id
			break
		}
	}
	for _, id := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) {
			sealedID = id
			break
		}
	}
	if skippedID == "" || sealedID == "" {
		t.Fatal("no card or sealed product of a skipped set in the datastore")
	}

	graded := func(ids ...string) mtgban.InventoryRecord {
		inv := mtgban.InventoryRecord{}
		for _, id := range ids {
			inv.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
			inv.Add(id, &mtgban.InventoryEntry{Conditions: "SP", Price: 8, Quantity: 1})
		}
		return inv
	}
	singles := mtgban.NewSellerFromInventory(graded(cardID, skippedID), mtgban.ScraperInfo{Shorthand: "SRC"})
	sealed := mtgban.NewSellerFromInventory(graded(sealedID), mtgban.ScraperInfo{Shorthand: "SRCSealed", SealedMode: true})
	publishStores(t, []mtgban.Seller{
		singles, sealed,
		mtgban.NewSellerFromInventory(graded(cardID, skippedID), mtgban.ScraperInfo{Shorthand: "REF"}),
		mtgban.NewSellerFromInventory(graded(cardID, skippedID), mtgban.ScraperInfo{Shorthand: "TCGLow", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(graded(sealedID), mtgban.ScraperInfo{Shorthand: "REFSealed", SealedMode: true}),
	}, []mtgban.Vendor{})

	tests := []struct {
		name      string
		rule      customBuylistRule
		source    mtgban.Seller
		shorthand string
		want      map[string]int // grades bought per id
	}{
		{
			name:      "singles off the retail reference, skipped sets dropped",
			rule:      customBuylistRule{rate: 0.5, seller: "REF", sealedSeller: "REFSealed"},
			source:    singles,
			shorthand: customStore,
			want:      map[string]int{cardID: 2},
		},
		{
			name:      "an index reference buys at NM only",
			rule:      customBuylistRule{rate: 0.5, seller: "TCGLow", sealedSeller: "REFSealed"},
			source:    singles,
			shorthand: customStore,
			want:      map[string]int{cardID: 1},
		},
		{
			name:      "sealed off the sealed reference, skipped sets kept",
			rule:      customBuylistRule{rate: 0.5, seller: "TCGLow", sealedSeller: "REFSealed"},
			source:    sealed,
			shorthand: customSealedStore,
			want:      map[string]int{sealedID: 2},
		},
		{
			name:   "no reference loaded",
			rule:   customBuylistRule{rate: 0.5, seller: "REF", sealedSeller: "GONE"},
			source: sealed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor := newCustomBuylistVendor(backend(), tt.rule, tt.source)
			if tt.want == nil {
				if vendor != nil {
					t.Fatalf("got a vendor without a reference: %v", vendor.Info())
				}
				return
			}
			if vendor == nil {
				t.Fatal("got no vendor")
			}
			info := vendor.Info()
			if info.Shorthand != tt.shorthand || info.SealedMode != tt.source.Info().SealedMode {
				t.Errorf("got %s sealed=%v, want %s sealed=%v", info.Shorthand, info.SealedMode, tt.shorthand, tt.source.Info().SealedMode)
			}
			got := map[string]int{}
			for id, entries := range vendor.Buylist() {
				got[id] = len(entries)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
