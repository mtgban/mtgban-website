package main

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The retail and buylist searches evaluate a shared filter concurrently (the
// noSussy guard spans TCGDirect retail and TCGDirectNet buylist), so the cache
// must stay race-free under exactly that pattern. Meaningful under -race.
func TestPriceFilterCacheConcurrent(t *testing.T) {
	scrapers := []string{"SCR0", "SCR1", "SCR2"}
	filter := &FilterPriceElem{
		Name:        "price_greater_than",
		Price4Store: benchPrice4Store(scrapers),
		Stores:      []string{"SCR1"},
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runPriceFilterRequest(500, filter)
	}()
	go func() {
		defer wg.Done()
		filters := []*FilterPriceElem{filter}
		for c := range 500 {
			cardId := "bench-card-" + strconv.Itoa(c)
			shouldSkipPriceNG(cardId, mtgban.BuylistEntry{BuyPrice: 6.0, Conditions: "NM"}, filters, "SCR050")
		}
	}()
	wg.Wait()
}

// benchStoreLookups counts Price4Store invocations across a benchmark run, so
// the report shows how much redundant recomputation the cache absorbs.
var benchStoreLookups atomic.Int64

// benchPrice4Store stands in for price4seller: findSellerInventory linear-scans
// every scraper with EqualFold before the map lookup, so model that cost with a
// same-sized scan over fake shorthands.
func benchPrice4Store(scrapers []string) func(string, string) float64 {
	return func(cardId, shorthand string) float64 {
		benchStoreLookups.Add(1)
		for _, code := range scrapers {
			if strings.EqualFold(code, shorthand) {
				return 10.0
			}
		}
		return 0
	}
}

// runPriceFilterRequest pushes one search-request-shaped workload through
// shouldSkipPriceNG: nCards cards with four condition entries each, all
// evaluated against a single price filter, mirroring searchSellersNG's loop.
func runPriceFilterRequest(nCards int, filter *FilterPriceElem) {
	filters := []*FilterPriceElem{filter}
	entries := []mtgban.InventoryEntry{
		{Price: 5.0, Conditions: "NM"},
		{Price: 4.0, Conditions: "SP"},
		{Price: 3.0, Conditions: "MP"},
		{Price: 2.0, Conditions: "HP"},
	}
	for c := range nCards {
		cardId := "bench-card-" + strconv.Itoa(c)
		for _, entry := range entries {
			shouldSkipPriceNG(cardId, entry, filters, "SCR050")
		}
	}
}

// A store-backed filter (e.g. "arb_price>CK" or the noSussy guard): every cache
// miss pays a Price4Store lookup per configured store.
func BenchmarkPriceFilterStoreLookup(b *testing.B) {
	scrapers := make([]string, 100)
	for i := range scrapers {
		scrapers[i] = "SCR" + strconv.Itoa(i)
	}
	benchStoreLookups.Store(0)
	b.ReportAllocs()
	for b.Loop() {
		filter := &FilterPriceElem{
			Name:        "price_greater_than",
			Price4Store: benchPrice4Store(scrapers),
			Stores:      []string{"SCR050"},
		}
		runPriceFilterRequest(5000, filter)
	}
	b.ReportMetric(float64(benchStoreLookups.Load())/float64(b.N), "storeLookups/req")
}

// A constant-value filter (e.g. "price>10"): no store lookups, so this isolates
// the cache-write machinery itself.
func BenchmarkPriceFilterConstantValue(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		filter := &FilterPriceElem{
			Name:  "price_greater_than",
			Value: 10.0,
		}
		runPriceFilterRequest(5000, filter)
	}
}
