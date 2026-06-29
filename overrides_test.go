package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestApplyOverridesByKind(t *testing.T) {
	ov := KeyOverrides{
		"CK": {
			overrideKindRetail:  {"wrongR": "rightR"},
			overrideKindBuylist: {"wrongB": "rightB"},
		},
	}
	keyOverridesPtr.Store(&ov)
	t.Cleanup(func() { empty := KeyOverrides{}; keyOverridesPtr.Store(&empty) })

	// Retail overrides apply to a seller's inventory.
	inv := mtgban.InventoryRecord{"wrongR": {{Price: 1}}, "wrongB": {{Price: 9}}}
	seller := applyInventoryOverrides(mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "CK"}))
	got := seller.Inventory()
	if _, ok := got["wrongR"]; ok {
		t.Error("retail wrong key should have been remapped away")
	}
	if _, ok := got["rightR"]; !ok {
		t.Error("retail correct key missing after remap")
	}
	// The buylist override must not touch the inventory.
	if _, ok := got["wrongB"]; !ok {
		t.Error("buylist override leaked into retail apply")
	}

	// Buylist overrides apply to a vendor's buylist.
	bl := mtgban.BuylistRecord{"wrongB": {{}}, "wrongR": {{}}}
	vendor := applyBuylistOverrides(mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Shorthand: "CK"}))
	gotbl := vendor.Buylist()
	if _, ok := gotbl["wrongB"]; ok {
		t.Error("buylist wrong key should have been remapped away")
	}
	if _, ok := gotbl["rightB"]; !ok {
		t.Error("buylist correct key missing after remap")
	}
	if _, ok := gotbl["wrongR"]; !ok {
		t.Error("retail override leaked into buylist apply")
	}
}
