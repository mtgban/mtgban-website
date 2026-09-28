package main

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A store's singles and sealed scrapers share its name: CK and CKSealed are
// both "Card Kingdom". The guide gathers its stores in a map, and sorting by
// name alone left tied ones in the map's order, which changes per render, so
// a hundred renders all but ensure a wrong one if the tie is not broken.
func TestGuideStoresBreakNameTiesByShorthand(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	store := func(name, shorthand string, sealed bool) mtgban.Seller {
		return mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{
			Name:       name,
			Shorthand:  shorthand,
			SealedMode: sealed,
		})
	}
	sellers := []mtgban.Seller{
		store("Card Kingdom", "CK", false),
		store("Card Kingdom", "CKSealed", true),
		store("Star City Games", "SCG", false),
		store("Star City Games", "SCGSealed", true),
	}
	vendors := []mtgban.Vendor{}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	want := []string{"CK", "CKSealed", "SCG", "SCGSealed"}
	for range 100 {
		var stores []GuideStore
		err := json.Unmarshal([]byte(guideStoresJSON()), &stores)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, s := range stores {
			got = append(got, s.Code)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("stores in order %v, want %v", got, want)
		}
	}
}
