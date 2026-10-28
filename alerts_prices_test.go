package main

import (
	"slices"
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
	scg := mtgban.BuylistRecord{"card-1": {{Conditions: "NM", BuyPrice: 14}}}
	idx := mtgban.BuylistRecord{"card-1": {{Conditions: "NM", BuyPrice: 99, Quantity: 1}}}
	abu := mtgban.BuylistRecord{"card-2": {{Conditions: "NM", BuyPrice: 3}}}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewVendorFromBuylist(scg, mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}),
		mtgban.NewVendorFromBuylist(idx, mtgban.ScraperInfo{Shorthand: "IDX", Name: "Index", MetadataOnly: true}),
		mtgban.NewVendorFromBuylist(abu, mtgban.ScraperInfo{Shorthand: "ABU", Name: "ABU Games"}),
		mtgban.NewVendorFromBuylist(abu, mtgban.ScraperInfo{Shorthand: "ABUSealed", Name: "ABU Games", SealedMode: true}),
	}
	inv := mtgban.InventoryRecord{"card-1": {{Conditions: "NM", Price: 20, Quantity: 2}, {Conditions: "HP", Price: 8, Quantity: 1}}}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

func TestAlertStorePricesSkipsIndexBlockedAndOtherKind(t *testing.T) {
	alertTestStores(t)
	got := alertStorePrices("card-1", false, alerts.SideBuylist, []string{"SCG"})
	if len(got) != 2 || got[0].Shorthand != "CK" || got[1].Shorthand != "ABU" {
		t.Fatalf("stores = %+v, want CK and ABU", got)
	}
	if len(got[1].Prices) != 0 {
		t.Fatalf("ABU = %+v, want listed without an offer", got[1])
	}
	if got[0].Prices["NM"] != 12 {
		t.Fatalf("CK NM = %v, want 12", got[0].Prices["NM"])
	}
	all := alertStorePrices("card-1", false, alerts.SideBuylist, nil)
	if len(all) != 3 || all[1].Shorthand != "SCG" || all[1].Prices["NM"] != 14 {
		t.Fatalf("stores = %+v, want SCG's offer, which carries no quantity", all)
	}
	sealed := alertStorePrices("card-1", true, alerts.SideBuylist, nil)
	if len(sealed) != 1 || sealed[0].Shorthand != "ABUSealed" {
		t.Fatalf("sealed stores = %+v, want ABUSealed only", sealed)
	}
	retail := alertStorePrices("card-1", false, alerts.SideRetail, nil)
	if len(retail) != 1 || retail[0].Prices["HP"] != 8 {
		t.Fatalf("retail = %+v", retail)
	}
}

func TestAlertStorePricesMarksPickedOnly(t *testing.T) {
	alertTestStores(t)
	net := mtgban.BuylistRecord{"card-1": {{Conditions: "NM", BuyPrice: 15}}}
	vendors := append(slices.Clip(GetVendors()),
		mtgban.NewVendorFromBuylist(net, mtgban.ScraperInfo{Shorthand: "TCGDirectNet", Name: "TCG Direct (net)"}),
		mtgban.NewVendorFromBuylist(net, mtgban.ScraperInfo{Shorthand: "CKBLLast", Name: "Card Kingdom (last)"}))
	vendorsPtr.Store(&vendors)
	for _, s := range alertStorePrices("card-1", false, alerts.SideBuylist, nil) {
		if s.PickedOnly != (s.Shorthand == "TCGDirectNet" || s.Shorthand == "CKBLLast") {
			t.Fatalf("%s PickedOnly = %v", s.Shorthand, s.PickedOnly)
		}
	}
}
