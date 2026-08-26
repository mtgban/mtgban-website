package main

import (
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// The axis used to come from a query of its own, asking the archive for a
// card's oldest date. The rows already say it, so it is read off them - and
// what it answers has to match what that query answered, boundary included.
func TestEarliestChartedDate(t *testing.T) {
	const lb = timeseries.Lookback(365)

	t.Run("oldest date in the series", func(t *testing.T) {
		results := map[string]timeseries.ProviderPrices{
			"2026-03-04": {1: 2.50},
			"2025-11-30": {1: 2.00},
			"2026-01-01": {1: 2.25},
		}
		got := earliestChartedDate(results, lb)
		if want := "2025-11-30"; got.Format("2006-01-02") != want {
			t.Errorf("earliest = %s, want %s", got.Format("2006-01-02"), want)
		}
	})

	// An empty series is what a card with no history in the window returns, and
	// the archive answered the boundary for it rather than the zero time.
	t.Run("empty falls back to the boundary", func(t *testing.T) {
		got := earliestChartedDate(nil, lb)
		if delta := got.Sub(lb.Since()); delta > time.Second || delta < -time.Second {
			t.Errorf("earliest = %v, want the lookback boundary %v", got, lb.Since())
		}
	})

	t.Run("a key that is not a date falls back too", func(t *testing.T) {
		got := earliestChartedDate(map[string]timeseries.ProviderPrices{"nonsense": {1: 1}}, lb)
		if delta := got.Sub(lb.Since()); delta > time.Second || delta < -time.Second {
			t.Errorf("earliest = %v, want the lookback boundary %v", got, lb.Since())
		}
	})
}
