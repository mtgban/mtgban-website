package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

func alertTestStores(t *testing.T) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	ck := mtgban.BuylistRecord{"card-1": {
		{Conditions: "NM", BuyPrice: 12, Quantity: 4},
		{Conditions: "SP", BuyPrice: 9, Quantity: 0},
	}}
	scg := mtgban.BuylistRecord{"card-1": {{Conditions: "NM", BuyPrice: 14, Quantity: 1}}}
	idx := mtgban.BuylistRecord{"card-1": {{Conditions: "NM", BuyPrice: 99, Quantity: 1}}}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewVendorFromBuylist(scg, mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}),
		mtgban.NewVendorFromBuylist(idx, mtgban.ScraperInfo{Shorthand: "IDX", Name: "Index", MetadataOnly: true}),
	}
	inv := mtgban.InventoryRecord{"card-1": {{Conditions: "NM", Price: 20, Quantity: 2}, {Conditions: "HP", Price: 8, Quantity: 1}}}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

func TestAlertStorePricesSkipsIndexBlockedAndEmpty(t *testing.T) {
	alertTestStores(t)
	got := alertStorePrices("card-1", alerts.SideBuylist, []string{"SCG"})
	if len(got) != 1 || got[0].Shorthand != "CK" {
		t.Fatalf("stores = %+v, want CK only", got)
	}
	if got[0].Prices["NM"] != 12 {
		t.Fatalf("CK NM = %v, want 12", got[0].Prices["NM"])
	}
	_, has := got[0].Prices["SP"]
	if has {
		t.Fatal("a zero-quantity offer was kept")
	}
	retail := alertStorePrices("card-1", alerts.SideRetail, nil)
	if len(retail) != 1 || retail[0].Prices["HP"] != 8 {
		t.Fatalf("retail = %+v", retail)
	}
}
