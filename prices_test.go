package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// withPrices publishes sellers and vendors as the served snapshot, keeping
// the dumps listing, and puts the snapshot it replaced back when the test
// ends. It publishes the way a load does, newPrices then one Store, but
// without scrapersWriteMu, which a test may hold.
func withPrices(tb testing.TB, sellers []mtgban.Seller, vendors []mtgban.Vendor) {
	tb.Helper()
	prev := currentPrices()
	tb.Cleanup(func() { pricesPtr.Store(prev) })
	pricesPtr.Store(newPrices(sellers, vendors, prev.scrapers))
}

// keepPrices puts the snapshot served now back when the test ends, for a
// test that registers its stores through updateSellers or updateVendors.
func keepPrices(tb testing.TB) {
	tb.Helper()
	prev := currentPrices()
	tb.Cleanup(func() { pricesPtr.Store(prev) })
}

// withScraperIndex publishes idx as the dumps listing, keeping both sides,
// and puts the snapshot it replaced back when the test ends.
func withScraperIndex(tb testing.TB, idx *scraperIndex) {
	tb.Helper()
	prev := currentPrices()
	tb.Cleanup(func() { pricesPtr.Store(prev) })
	next := *prev
	next.scrapers = *idx
	pricesPtr.Store(&next)
}
