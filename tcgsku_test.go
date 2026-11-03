package main

import (
	"maps"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tcgskuparser"
)

// tcgShelf is one TCGplayer seller, keyed by uuid with each offer's SKU
// and condition - the shape the scrapers publish. Entries are
// {uuid, sku, condition}.
func tcgShelf(shorthand string, entries [][3]string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for _, entry := range entries {
		inv.Add(entry[0], &mtgban.InventoryEntry{InstanceID: entry[1], Conditions: mtgban.Condition(entry[2]), Price: 1})
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, MetadataOnly: true,
	})
}

// The SKU index is built with the TCGplayer sellers it describes and read
// off the published snapshot: a buylist publish carries it across as it is,
// and an upload resolves from the one published, not from a walk of its own.
func TestUploadResolvesTCGSKUFromThePublishedSnapshot(t *testing.T) {
	quietUploadLog(t)
	b := fixtureBackend("FIXTURETCG", "Fixture TCGplayer", "2020-01-01", [][2]string{
		{"Fixture TCGplayer Card", "1"},
	})

	sellers := []mtgban.Seller{tcgShelf("TCGPlayer", [][3]string{{"FIXTURETCG-1", "7001", "SP"}})}
	withPrices(t, sellers, currentPrices().vendors)

	// A mark a rebuild would not carry, so "was it rebuilt" is answerable
	// without timing anything. It is published as a snapshot of its own:
	// nothing in a published value is changed in place.
	marked := *currentPrices()
	marked.tcgSKUs = maps.Clone(marked.tcgSKUs)
	marked.tcgSKUs["sentinel"] = tcgskuparser.SKU{UUID: "kept", Condition: "HP"}
	testSite.pricesPtr.Store(&marked)

	// A buylist-only publish, the way a buylist load does it: the sellers,
	// and the index, are carried across. The withPrices above restores it.
	vendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "CK", Shorthand: "CK"})
	vendors := []mtgban.Vendor{vendor}
	testSite.pricesPtr.Store(withVendors(currentPrices(), vendors))
	if got := currentPrices().tcgSKUs.Resolve("sentinel"); got != "kept" {
		t.Errorf("a buylist publish rebuilt the index: sentinel = %q", got)
	}

	parser := newUploadParser(b, currentPrices())
	if got := parser.TCGSkuToUUID("sentinel"); got != "kept" {
		t.Errorf("the parser resolves from an index of its own, not the published one: %q", got)
	}
	if got := parser.TCGSkuToCondition("sentinel"); got != "HP" {
		t.Errorf("the parser's condition comes from an index of its own: %q", got)
	}

	entries, err := loadCsv(parser, strings.NewReader("Name,TCGplayer Id\nNot Its Name,7001\n"), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].CardID != "FIXTURETCG-1" {
		t.Errorf("CardID = %q, want FIXTURETCG-1 (MismatchError %v)", entries[0].CardID, entries[0].MismatchError)
	}
	if entries[0].OriginalCondition != "SP" {
		t.Errorf("OriginalCondition = %q, want SP from the SKU", entries[0].OriginalCondition)
	}
}

// A retail publish keeps the SKU index while the TCGplayer sellers are the
// ones it was built from, and builds it again as soon as one is new. Each
// publish here builds from the snapshot it replaces, as a load does.
func TestTCGSKUIndexFollowsItsSellers(t *testing.T) {
	singles := tcgShelf("TCGPlayer", [][3]string{{"uuid-aaa", "100", "NM"}})
	other := tcgShelf("CK", [][3]string{{"uuid-aaa", "ck-1", "NM"}})
	withPrices(t, []mtgban.Seller{singles}, currentPrices().vendors)
	marked := *currentPrices()
	marked.tcgSKUs = maps.Clone(marked.tcgSKUs)
	marked.tcgSKUs["sentinel"] = tcgskuparser.SKU{UUID: "kept"}
	testSite.pricesPtr.Store(&marked)

	// Another store published: a new slice, the same TCGplayer seller.
	withPrices(t, []mtgban.Seller{singles, other}, currentPrices().vendors)
	if got := currentPrices().tcgSKUs.Resolve("sentinel"); got != "kept" {
		t.Errorf("a publish of another store rebuilt the index: sentinel = %q", got)
	}
	if got := currentPrices().tcgSKUs.Resolve("ck-1"); got != "" {
		t.Errorf("another store's SKU resolves: %q", got)
	}

	// The TCGplayer seller published again: its index is new.
	withPrices(t, []mtgban.Seller{tcgShelf("TCGPlayer", [][3]string{{"uuid-bbb", "200", "NM"}}), other}, currentPrices().vendors)
	if got := currentPrices().tcgSKUs.Resolve("sentinel"); got != "" {
		t.Errorf("a new TCGplayer seller kept the old index: sentinel = %q", got)
	}
	if got := currentPrices().tcgSKUs.Resolve("200"); got != "uuid-bbb" {
		t.Errorf("UUID(200) = %q, want uuid-bbb", got)
	}
	if got := currentPrices().tcgSKUs.Resolve("100"); got != "" {
		t.Errorf("the replaced seller's SKU still resolves: %q", got)
	}

	// Dropped: the index goes with it.
	withPrices(t, []mtgban.Seller{other}, currentPrices().vendors)
	if idx := currentPrices().tcgSKUs; idx != nil {
		t.Errorf("no TCGplayer seller, yet an index of %d SKUs", len(idx))
	}
}
