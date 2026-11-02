package main

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/simplecloud"
)

// mkmShelf is one Cardmarket shelf, keyed by uuid with the product each
// entry priced carried alongside it - the shape the scrapers publish.
func mkmShelf(shorthand string, byUUID map[string]string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for uuid, mkmID := range byUUID {
		inv.Add(uuid, &mtgban.InventoryEntry{OriginalID: mkmID, Price: 1})
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, MetadataOnly: true,
	})
}

// The Cardmarket id map is built with the sellers it describes and read off
// the published snapshot: a buylist publish carries it across, and an upload
// resolves from the one published, not from a walk of its own.
func TestUploadResolvesCardmarketIDFromThePublishedSnapshot(t *testing.T) {
	quietUploadLog(t)
	b := fixtureBackend("FIXTUREMKM", "Fixture Cardmarket", "2020-01-01", [][2]string{
		{"Fixture Cardmarket Card", "1"},
	})

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{mkmShelf("MKMTrend", map[string]string{"FIXTUREMKM-1": "265854"})}
	sellersPtr.Store(&sellers)

	// A buylist-only publish: the sellers are copied across unchanged.
	vendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "CK", Shorthand: "CK"})
	vendors := []mtgban.Vendor{vendor}
	vendorsPtr.Store(&vendors)

	// A mark a rebuild would not carry, so "was it rebuilt" is answerable
	// without timing anything.
	currentPrices().mkmIDs["sentinel"] = "kept"

	parser := newUploadParser(b)
	if got := parser.MKMIDToUUID("sentinel"); got != "kept" {
		t.Errorf("the parser resolves from a map of its own, not the published one: %q", got)
	}

	entries, err := loadCsv(parser, strings.NewReader("Name,Cardmarket ID\nNot Its Name,265854\n"), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].CardID != "FIXTUREMKM-1" {
		t.Errorf("CardID = %q, want FIXTUREMKM-1 (MismatchError %v)", entries[0].CardID, entries[0].MismatchError)
	}
}

// benchDump reads one store's dump out of the directory MTGBAN_BENCH_DUMPS
// names, flat, as <shorthand>.json.xz; the benchmark skips when it is unset.
func benchDump(b *testing.B, shorthand string) mtgban.Seller {
	b.Helper()
	dir := os.Getenv("MTGBAN_BENCH_DUMPS")
	if dir == "" {
		b.Skip("MTGBAN_BENCH_DUMPS not set")
	}
	reader, err := simplecloud.InitReader(context.Background(), &simplecloud.FileBucket{Root: dir}, shorthand+"."+dumpFormat)
	if err != nil {
		b.Fatal(err)
	}
	defer reader.Close()
	seller, err := mtgban.ReadSellerFromJSON(reader)
	if err != nil {
		b.Fatal(err)
	}
	return seller
}

// The two inverted indexes over the retail side, each over the real dumps
// it reads, so the cost of building one at every publish can be set against
// the other's twelve-hourly build.
func BenchmarkBuildMKMIDIndex(b *testing.B) {
	sellers := []mtgban.Seller{benchDump(b, "MKMTrend"), benchDump(b, "MKMLow"), benchDump(b, "MKMSealed")}
	b.ResetTimer()
	for range b.N {
		// The dumps in memory make a collection a large share of a run,
		// so each build starts from a collected heap.
		b.StopTimer()
		runtime.GC()
		b.StartTimer()
		newPrices(sellers, nil, *newScraperIndex())
	}
	b.ReportMetric(float64(len(newPrices(sellers, nil, *newScraperIndex()).mkmIDs)), "ids")
}

func BenchmarkBuildTCGSKUIndex(b *testing.B) {
	tcgPlayer := benchDump(b, "TCGPlayer").Inventory()
	tcgSealed := benchDump(b, "TCGSealed").Inventory()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		runtime.GC()
		b.StartTimer()
		buildTCGSKUIndex(tcgPlayer, tcgSealed)
	}
	b.ReportMetric(float64(len(buildTCGSKUIndex(tcgPlayer, tcgSealed))), "skus")
}
