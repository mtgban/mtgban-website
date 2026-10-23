package main

import (
	"fmt"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func storeIndexFixture(t testing.TB) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"a": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"b": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom Twice"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "CKSealed", Name: "Card Kingdom", SealedMode: true}),
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom Buylist"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "ABU", Name: "ABU Games"}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

// The index answers as the scans it replaced did: the name lookups match the
// shorthand exactly and a seller before a vendor, the inventory lookups fold
// case, and the first of two stores sharing a shorthand wins.
func TestStoreIndexMatchesTheScans(t *testing.T) {
	storeIndexFixture(t)

	if got := scraperName("CK"); got != "Card Kingdom" {
		t.Errorf("scraperName(CK) = %q, want the first seller", got)
	}
	if got := scraperName("ABU"); got != "ABU Games" {
		t.Errorf("scraperName(ABU) = %q, want the vendor", got)
	}
	if got := scraperName("ck"); got != "" {
		t.Errorf("scraperName(ck) = %q, want nothing: the name lookup is exact", got)
	}
	if !isSealedScraper("CKSealed") || isSealedScraper("CK") || isSealedScraper("cksealed") {
		t.Error("isSealedScraper should match the exact shorthand only")
	}
	inv, err := findSellerInventory("ck")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inv["a"]; !ok {
		t.Error("findSellerInventory(ck) should fold case and return the first CK seller")
	}
	if _, err := findVendorBuylist("abu"); err != nil {
		t.Errorf("findVendorBuylist(abu) = %v, want the vendor", err)
	}
	if _, err := findVendorBuylist("CKSealed"); err == nil {
		t.Error("findVendorBuylist(CKSealed) should not find a seller")
	}
}

// Two stores whose shorthands differ only by case are told apart by the exact
// lookups and folded together by the case-insensitive ones, as the scans did.
func TestStoreIndexCaseOnlyCollision(t *testing.T) {
	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"first": nil}, mtgban.ScraperInfo{Shorthand: "Ck", Name: "Mixed Case"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"second": nil}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Upper Case", SealedMode: true}),
	}
	sellersPtr.Store(&sellers)

	if got := scraperName("CK"); got != "Upper Case" {
		t.Errorf("scraperName(CK) = %q, want the exact match listed second", got)
	}
	if got := scraperName("Ck"); got != "Mixed Case" {
		t.Errorf("scraperName(Ck) = %q, want the exact match listed first", got)
	}
	if !isSealedScraper("CK") || isSealedScraper("Ck") {
		t.Error("isSealedScraper should tell the two apart")
	}
	inv, err := findSellerInventory("ck")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inv["first"]; !ok {
		t.Error("findSellerInventory(ck) should fold to the first listed")
	}
}

// A snapshot stored anywhere, the tests included, is seen by the next lookup,
// whether it is a new slice or the same variable grown in place.
func TestStoreIndexFollowsTheSnapshot(t *testing.T) {
	storeIndexFixture(t)
	if _, err := findSellerInventory("TCG"); err == nil {
		t.Fatal("TCG should not be loaded yet")
	}

	sellers := append(GetSellers(), mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCG", Name: "TCGplayer"}))
	sellersPtr.Store(&sellers)
	if got := scraperName("TCG"); got != "TCGplayer" {
		t.Errorf("after a new snapshot, scraperName(TCG) = %q", got)
	}

	sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}))
	if got := scraperName("SCG"); got != "Star City Games" {
		t.Errorf("after the same variable grew, scraperName(SCG) = %q", got)
	}

	sellersPtr.Store(nil)
	vendorsPtr.Store(nil)
	if got := scraperName("CK"); got != "" {
		t.Errorf("with no snapshot, scraperName(CK) = %q", got)
	}
}

func BenchmarkScraperName(b *testing.B) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	b.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
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
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if scraperName("V39") == "" {
			b.Fatal("V39 not found")
		}
		if _, err := findSellerInventory("s59"); err != nil {
			b.Fatal(err)
		}
	}
}
