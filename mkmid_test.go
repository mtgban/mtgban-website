package main

import (
	"context"
	"maps"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tcgskuparser"
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
// the published snapshot: a buylist publish carries it across as it is, and
// an upload resolves from the one published, not from a walk of its own.
func TestUploadResolvesCardmarketIDFromThePublishedSnapshot(t *testing.T) {
	quietUploadLog(t)
	b := fixtureBackend("FIXTUREMKM", "Fixture Cardmarket", "2020-01-01", [][2]string{
		{"Fixture Cardmarket Card", "1"},
	})
	sellers := []mtgban.Seller{mkmShelf("MKMTrend", map[string]string{"FIXTUREMKM-1": "265854"})}
	withPrices(t, sellers, currentPrices().vendors)

	// A mark a rebuild would not carry, so "was it rebuilt" is answerable
	// without timing anything. It is published as a snapshot of its own:
	// nothing in a published value is changed in place.
	marked := *currentPrices()
	marked.mkmIDs = maps.Clone(marked.mkmIDs)
	marked.mkmIDs["sentinel"] = "kept"
	testSite.pricesPtr.Store(&marked)

	// A buylist-only publish, the way a buylist load does it: the sellers,
	// and the map, are carried across. The withPrices above restores it.
	vendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "CK", Shorthand: "CK"})
	vendors := []mtgban.Vendor{vendor}
	testSite.pricesPtr.Store(withVendors(currentPrices(), vendors))
	if got := currentPrices().mkmIDs["sentinel"]; got != "kept" {
		t.Errorf("a buylist publish rebuilt the map: sentinel = %q", got)
	}

	parser := newUploadParser(b, currentPrices())
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

// A retail publish keeps the Cardmarket id map while the shelves are the
// ones it was built from, and builds it again as soon as one is new. Each
// publish here builds from the snapshot it replaces, as a load does.
func TestMKMIDIndexFollowsItsShelves(t *testing.T) {
	shelf := mkmShelf("MKMTrend", map[string]string{"uuid-aaa": "100"})
	other := mkmShelf("CK", map[string]string{"uuid-aaa": "ck-1"})
	withPrices(t, []mtgban.Seller{shelf}, currentPrices().vendors)
	marked := *currentPrices()
	marked.mkmIDs = maps.Clone(marked.mkmIDs)
	marked.mkmIDs["sentinel"] = "kept"
	testSite.pricesPtr.Store(&marked)

	// Another store published: a new slice, the same shelf.
	withPrices(t, []mtgban.Seller{shelf, other}, currentPrices().vendors)
	if got := currentPrices().mkmIDs.Resolve("sentinel"); got != "kept" {
		t.Errorf("a publish of another store rebuilt the map: sentinel = %q", got)
	}
	if got := currentPrices().mkmIDs.Resolve("ck-1"); got != "" {
		t.Errorf("another store's id resolves: %q", got)
	}

	// The shelf published again: its map is new.
	withPrices(t, []mtgban.Seller{mkmShelf("MKMTrend", map[string]string{"uuid-bbb": "200"}), other}, currentPrices().vendors)
	if got := currentPrices().mkmIDs.Resolve("sentinel"); got != "" {
		t.Errorf("a new shelf kept the old map: sentinel = %q", got)
	}
	if got := currentPrices().mkmIDs.Resolve("200"); got != "uuid-bbb" {
		t.Errorf("Resolve(200) = %q, want uuid-bbb", got)
	}
	if got := currentPrices().mkmIDs.Resolve("100"); got != "" {
		t.Errorf("the replaced shelf's id still resolves: %q", got)
	}

	// Dropped: the map goes with it.
	withPrices(t, []mtgban.Seller{other}, currentPrices().vendors)
	if ids := currentPrices().mkmIDs; ids != nil {
		t.Errorf("no shelf, yet a map of %d ids", len(ids))
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
// it reads: what a publish of one of their sellers pays to build each.
// Every other publish carries both across.
func BenchmarkBuildMKMIDIndex(b *testing.B) {
	sellers := []mtgban.Seller{benchDump(b, "MKMTrend"), benchDump(b, "MKMLow"), benchDump(b, "MKMSealed")}
	b.ResetTimer()
	for range b.N {
		// The dumps in memory make a collection a large share of a run,
		// so each build starts from a collected heap.
		b.StopTimer()
		runtime.GC()
		b.StartTimer()
		newPrices(nil, sellers, nil, *newScraperIndex())
	}
	b.ReportMetric(float64(len(newPrices(nil, sellers, nil, *newScraperIndex()).mkmIDs)), "ids")
}

func BenchmarkBuildTCGSKUIndex(b *testing.B) {
	sellers := []mtgban.Seller{benchDump(b, "TCGPlayer"), benchDump(b, "TCGSealed")}
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		runtime.GC()
		b.StartTimer()
		tcgskuparser.Build(sellers)
	}
	b.ReportMetric(float64(len(tcgskuparser.Build(sellers))), "skus")
}
