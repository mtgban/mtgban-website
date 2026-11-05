package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// withPrices publishes sellers and vendors as testSite's served snapshot,
// keeping the dumps listing, and puts the snapshot it replaced back when
// the test ends. Never from a test that calls t.Parallel().
func withPrices(tb testing.TB, sellers []mtgban.Seller, vendors []mtgban.Vendor) {
	tb.Helper()
	sitePrices(tb, testSite, sellers, vendors)
}

// sitePrices publishes sellers and vendors as s's served snapshot, keeping
// its dumps listing, and puts the snapshot it replaced back when the test
// ends. It publishes the way a load does, newPrices then one Store, but
// without scrapersMu, which a test may hold. Never from a test that calls
// t.Parallel().
func sitePrices(tb testing.TB, s *site, sellers []mtgban.Seller, vendors []mtgban.Vendor) {
	tb.Helper()
	prev := s.prices()
	tb.Cleanup(func() { s.pricesPtr.Store(prev) })
	s.pricesPtr.Store(newPrices(prev, sellers, vendors, prev.scrapers))
}

// keepPrices puts the snapshot testSite serves now back when the test ends,
// for a test that registers its stores through updateSellers or
// updateVendors. Never from a test that calls t.Parallel().
func keepPrices(tb testing.TB) {
	tb.Helper()
	keepSitePrices(tb, testSite)
}

// keepSitePrices is keepPrices for a site of the test's own.
func keepSitePrices(tb testing.TB, s *site) {
	tb.Helper()
	prev := s.prices()
	tb.Cleanup(func() { s.pricesPtr.Store(prev) })
}

// withScraperIndex publishes idx as testSite's dumps listing, an empty one
// for nil, keeping both sides, and puts the snapshot it replaced back when
// the test ends. Never from a test that calls t.Parallel().
func withScraperIndex(tb testing.TB, idx *scraperIndex) {
	tb.Helper()
	if idx == nil {
		idx = newScraperIndex()
	}
	prev := testSite.prices()
	tb.Cleanup(func() { testSite.pricesPtr.Store(prev) })
	next := *prev
	next.scrapers = *idx
	testSite.pricesPtr.Store(&next)
}
