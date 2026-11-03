package main

import (
	"fmt"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func storeIndexFixture(t testing.TB) {
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"a": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"b": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom Twice"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "CKSealed", Name: "Card Kingdom", SealedMode: true}),
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom Buylist"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "ABU", Name: "ABU Games"}),
	}
	withPrices(t, sellers, vendors)
}

// The index answers as the scans it replaced did: the name lookups match the
// shorthand exactly and a seller before a vendor, the inventory lookups fold
// case, and the first of two stores sharing a shorthand wins.
func TestStoreIndexMatchesTheScans(t *testing.T) {
	storeIndexFixture(t)

	if got := currentPrices().scraperName("CK"); got != "Card Kingdom" {
		t.Errorf("currentPrices().scraperName(CK) = %q, want the first seller", got)
	}
	if got := currentPrices().scraperName("ABU"); got != "ABU Games" {
		t.Errorf("currentPrices().scraperName(ABU) = %q, want the vendor", got)
	}
	if got := currentPrices().scraperName("ck"); got != "" {
		t.Errorf("currentPrices().scraperName(ck) = %q, want nothing: the name lookup is exact", got)
	}
	if !currentPrices().isSealedScraper("CKSealed") || currentPrices().isSealedScraper("CK") || currentPrices().isSealedScraper("cksealed") {
		t.Error("isSealedScraper should match the exact shorthand only")
	}
	inv, err := currentPrices().sellerInventory("ck")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inv["a"]; !ok {
		t.Error("currentPrices().sellerInventory(ck) should fold case and return the first CK seller")
	}
	if _, err := currentPrices().vendorBuylist("abu"); err != nil {
		t.Errorf("currentPrices().vendorBuylist(abu) = %v, want the vendor", err)
	}
	if _, err := currentPrices().vendorBuylist("CKSealed"); err == nil {
		t.Error("currentPrices().vendorBuylist(CKSealed) should not find a seller")
	}
}

// Two stores whose shorthands differ only by case are told apart by the exact
// lookups and folded together by the case-insensitive ones, as the scans did.
func TestStoreIndexCaseOnlyCollision(t *testing.T) {
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"first": nil}, mtgban.ScraperInfo{Shorthand: "Ck", Name: "Mixed Case"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"second": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Upper Case", SealedMode: true}),
	}
	withPrices(t, sellers, currentPrices().vendors)

	if got := currentPrices().scraperName("CK"); got != "Upper Case" {
		t.Errorf("currentPrices().scraperName(CK) = %q, want the exact match listed second", got)
	}
	if got := currentPrices().scraperName("Ck"); got != "Mixed Case" {
		t.Errorf("currentPrices().scraperName(Ck) = %q, want the exact match listed first", got)
	}
	if !currentPrices().isSealedScraper("CK") || currentPrices().isSealedScraper("Ck") {
		t.Error("isSealedScraper should tell the two apart")
	}
	inv, err := currentPrices().sellerInventory("ck")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inv["first"]; !ok {
		t.Error("currentPrices().sellerInventory(ck) should fold to the first listed")
	}
}

// A snapshot stored anywhere, the tests included, is seen by the next lookup,
// and one that drops a store takes it out of the index.
func TestStoreIndexFollowsTheSnapshot(t *testing.T) {
	storeIndexFixture(t)
	if _, err := currentPrices().sellerInventory("TCG"); err == nil {
		t.Fatal("TCG should not be loaded yet")
	}

	withTCG := append(slices.Clone(currentPrices().sellers), mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCG", Name: "TCGplayer"}))
	withPrices(t, withTCG, currentPrices().vendors)
	if got := currentPrices().scraperName("TCG"); got != "TCGplayer" {
		t.Errorf("after a new snapshot, currentPrices().scraperName(TCG) = %q", got)
	}

	withoutTCG := slices.Clone(withTCG[:len(withTCG)-1])
	withPrices(t, withoutTCG, currentPrices().vendors)
	if got := currentPrices().scraperName("TCG"); got != "" {
		t.Errorf("after a snapshot without it, currentPrices().scraperName(TCG) = %q", got)
	}

	withPrices(t, nil, nil)
	if got := currentPrices().scraperName("CK"); got != "" {
		t.Errorf("with no snapshot, currentPrices().scraperName(CK) = %q", got)
	}
}

func BenchmarkScraperName(b *testing.B) {
	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor
	for i := range 60 {
		sh := fmt.Sprintf("S%02d", i)
		sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: sh, Name: "Seller " + sh}))
	}
	for i := range 40 {
		sh := fmt.Sprintf("V%02d", i)
		vendors = append(vendors, mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: sh, Name: "Vendor " + sh}))
	}
	withPrices(b, sellers, vendors)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if currentPrices().scraperName("V39") == "" {
			b.Fatal("V39 not found")
		}
		if _, err := currentPrices().sellerInventory("s59"); err != nil {
			b.Fatal(err)
		}
	}
}
