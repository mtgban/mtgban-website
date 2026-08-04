package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// Benchmarks comparing the two price pipelines on the same logical query:
// "every card of one set" (see todo/unify-price-pipelines.md). The search
// pipeline resolves the set to uuids first and then does map lookups per
// store; the API scans every store's whole inventory and filters by edition
// per entry. The ByHash variant runs the API walk with pre-resolved uuids —
// what the API could do after unification.
//
// Run with:
//
//	go test -run xxx -bench BenchmarkSetPrices -benchmem .

var (
	benchSeedOnce  sync.Once
	benchSetCode   string
	benchSetUUIDs  []string
	benchPoolUUIDs []string
	benchSellers   []mtgban.Seller
	benchVendors   []mtgban.Vendor
)

// buildBenchData picks a mid-sized real set and builds synthetic records at a
// realistic scale: every card of the chosen set plus a sample of the wider
// pool, so the edition filter has plenty of non-matching entries to reject.
func buildBenchData() {
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		if len(set.Cards) >= 200 && len(set.Cards) <= 400 {
			benchSetCode = code
			break
		}
	}
	if benchSetCode == "" {
		return
	}

	uuids := mtgmatcher.GetUUIDs()
	// Sample the pool down to ~50k cards per store.
	step := len(uuids) / 50000
	if step < 1 {
		step = 1
	}

	var pool []string
	for i := 0; i < len(uuids); i += step {
		pool = append(pool, uuids[i])
	}
	benchPoolUUIDs = pool
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
		if err == nil && co.SetCode == benchSetCode && !co.Sealed {
			benchSetUUIDs = append(benchSetUUIDs, u)
		}
	}

	for n := 0; n < 3; n++ {
		inv := mtgban.InventoryRecord{}
		for i, u := range pool {
			inv.Add(u, &mtgban.InventoryEntry{
				Conditions: "NM", Price: float64(1 + (i+n)%40), Quantity: 1 + i%4, URL: "u",
			})
		}
		for i, u := range benchSetUUIDs {
			inv.Add(u, &mtgban.InventoryEntry{
				Conditions: "SP", Price: float64(1 + (i+n)%30), Quantity: 1, URL: "u",
			})
		}
		benchSellers = append(benchSellers, mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
			Name: fmt.Sprintf("Bench Seller %d", n), Shorthand: fmt.Sprintf("BENCHS%d", n),
		}))
	}
	for n := 0; n < 2; n++ {
		bl := mtgban.BuylistRecord{}
		for i, u := range pool {
			bl.Add(u, &mtgban.BuylistEntry{
				Conditions: "NM", BuyPrice: float64(1 + (i+n)%25), Quantity: 1, URL: "u",
			})
		}
		benchVendors = append(benchVendors, mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
			Name: fmt.Sprintf("Bench Vendor %d", n), Shorthand: fmt.Sprintf("BENCHV%d", n),
		}))
	}
}

func seedBenchScrapers(b *testing.B) (stores []string) {
	b.Helper()
	if len(mtgmatcher.GetUUIDs()) == 0 {
		b.Skip("mtgmatcher data not loaded")
	}
	benchSeedOnce.Do(buildBenchData)
	if benchSetCode == "" || len(benchSetUUIDs) == 0 {
		b.Skip("no suitable set found for benchmarking")
	}

	prev := scrapersPtr.Load()
	b.Cleanup(func() { scrapersPtr.Store(prev) })
	sellers := benchSellers
	vendors := benchVendors
	scrapersPtr.Store(newScraperSnapshot(sellers, vendors))

	for _, seller := range sellers {
		stores = append(stores, seller.Info().Shorthand)
	}
	for _, vendor := range vendors {
		stores = append(stores, vendor.Info().Shorthand)
	}
	return stores
}

// The full website path: query parsing, set resolution (a scan of the whole
// uuid pool), then per-uuid map lookups across the stores.
func BenchmarkSetPricesSearchQuery(b *testing.B) {
	seedBenchScrapers(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := parseSearchOptionsNG("s:"+benchSetCode, nil, nil, nil)
		uuids, err := searchAndFilter(config)
		if err != nil {
			b.Fatal(err)
		}
		foundSellers := searchSellersNG(uuids, config)
		foundVendors := searchVendorsNG(uuids, config)
		if len(foundSellers) == 0 || len(foundVendors) == 0 {
			b.Fatal("no results")
		}
	}
}

// The API path for an edition dump: scan every inventory entry of every
// store and filter by set code per card.
func BenchmarkSetPricesAPIEdition(b *testing.B) {
	stores := seedBenchScrapers(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		retail := getSellerPrices("", stores, benchSetCode, nil, "", true, true, false, "")
		buylist := getVendorPrices("", stores, benchSetCode, nil, "", true, true, false, "")
		if len(retail) == 0 || len(buylist) == 0 {
			b.Fatal("no results")
		}
	}
}

// The API walk driven by pre-resolved uuids — the shape the API could take
// after unification (resolve the edition once, then do map lookups).
func BenchmarkSetPricesAPIByHash(b *testing.B) {
	stores := seedBenchScrapers(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		retail := getSellerPrices("", stores, "", benchSetUUIDs, "", true, true, false, "")
		buylist := getVendorPrices("", stores, "", benchSetUUIDs, "", true, true, false, "")
		if len(retail) == 0 || len(buylist) == 0 {
			b.Fatal("no results")
		}
	}
}

// The search walk alone, driven by pre-resolved uuids — the fair counterpart
// of the API ByHash variant (no text->uuid resolution included).
func BenchmarkSetPricesSearchByHash(b *testing.B) {
	seedBenchScrapers(b)
	config := parseSearchOptionsNG(benchSetUUIDs[0], nil, nil, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		foundSellers := searchSellersNG(benchSetUUIDs, config)
		foundVendors := searchVendorsNG(benchSetUUIDs, config)
		if len(foundSellers) == 0 || len(foundVendors) == 0 {
			b.Fatal("no results")
		}
	}
}

// The search walk touching every inventory entry of every store — the fair
// counterpart of the API edition dump's full scan. Note it does not narrow
// to one set (the search pipeline has no in-walk card filter); it measures
// what the search machinery costs when nothing is pre-filtered.
func BenchmarkSetPricesSearchScan(b *testing.B) {
	seedBenchScrapers(b)
	config := parseSearchOptionsNG(benchSetUUIDs[0], nil, nil, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		foundSellers := searchSellersNG(benchPoolUUIDs, config)
		foundVendors := searchVendorsNG(benchPoolUUIDs, config)
		if len(foundSellers) == 0 || len(foundVendors) == 0 {
			b.Fatal("no results")
		}
	}
}
