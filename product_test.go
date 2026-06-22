package main

import (
	"math"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestAllEditionsByCategoryCoversAllEditions(t *testing.T) {
	editions := GetEditions()
	if len(editions.AllEditionsKeys) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	categorized := 0
	for _, entries := range editions.AllEditionsByCategory {
		categorized += len(entries)
	}
	if categorized != len(editions.AllEditionsKeys) {
		t.Fatalf("AllEditionsByCategory covers %d sets but AllEditionsKeys has %d",
			categorized, len(editions.AllEditionsKeys))
	}
}

func TestAllEditionsByCategoryHasKnownCategories(t *testing.T) {
	editions := GetEditions()
	if len(editions.AllEditionsByCategory) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	wanted := []string{"Expansions", "Commander Decks", "Core Sets"}
	for _, w := range wanted {
		if _, ok := editions.AllEditionsByCategory[w]; !ok {
			t.Errorf("expected category %q in AllEditionsByCategory", w)
		}
	}
}

// TestHotlistReducer covers the hotlist rule: keep cards whose current buylist
// price ties or beats every price stored in the window, and report the lowest
// price seen so the UI can show how far it has climbed.
func TestHotlistReducer(t *testing.T) {
	stats := timeseries.AggregatePriceStats{Max: 5, Min: 2, Count: 10}

	cases := []struct {
		name    string
		stats   timeseries.AggregatePriceStats
		current float64
		want    float64
		ok      bool
	}{
		{"current below window max", stats, 4, 0, false},
		{"current matches window max", stats, 5, 2, true},
		{"current beats window max", stats, 6, 2, true},
		{"current zero (not buying)", stats, 0, 0, false},
		{"no data (count zero)", timeseries.AggregatePriceStats{}, 5, 0, false},
		{"flat window", timeseries.AggregatePriceStats{Max: 4, Min: 4, Count: 4}, 4, 4, true},
	}
	for _, tc := range cases {
		got, ok := hotlistReducer(tc.stats, tc.current)
		if ok != tc.ok || !almostEqual(got, tc.want) {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestHighestBuylistPrice covers the absolute-peak metric: it reports stats.Max
// whenever the card has any buying days in the window.
func TestHighestBuylistPrice(t *testing.T) {
	cases := []struct {
		name  string
		stats timeseries.AggregatePriceStats
		want  float64
		ok    bool
	}{
		{"no data", timeseries.AggregatePriceStats{}, 0, false},
		{"single buying day", timeseries.AggregatePriceStats{Max: 7, Min: 7, Count: 1}, 7, true},
		{"flat window", timeseries.AggregatePriceStats{Max: 5, Min: 5, Count: 30}, 5, true},
		{"includes a spike", timeseries.AggregatePriceStats{Max: 100, Min: 2, Count: 31}, 100, true},
	}
	for _, tc := range cases {
		got, ok := highestBuylistPrice(tc.stats, 0)
		if ok != tc.ok || !almostEqual(got, tc.want) {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
