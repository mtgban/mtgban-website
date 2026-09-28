package main

import (
	"math"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestAllEditionsByCategoryCoversAllEditions(t *testing.T) {
	editions := currentDatastore().editions
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
	editions := currentDatastore().editions
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

// TestEditionCategoriesTiedOnDateSortByName gives three categories the same
// newest release date and an older one a name that sorts first. Both category
// lists must rank by date, then by name, and do so on every build: the tied
// ones used to come out in map order.
func TestEditionCategoriesTiedOnDateSortByName(t *testing.T) {
	b := &mtgmatcher.Backend{Sets: map[string]*mtgmatcher.Set{}}
	for _, set := range []*mtgmatcher.Set{
		{Code: "EXP", Type: "expansion", ReleaseDate: "2026-11-13"},
		{Code: "CMD", Type: "commander", ReleaseDate: "2026-11-13"},
		{Code: "FUN", Type: "funny", ReleaseDate: "2026-11-13"},
		{Code: "BOX", Type: "box", ReleaseDate: "2017-11-24"},
	} {
		set.Name = set.Code
		set.SealedProduct = []mtgmatcher.SealedProduct{{UUID: set.Code + "-box"}}
		b.Sets[set.Code] = set
		b.AllSets = append(b.AllSets, set.Code)
	}

	want := []string{"Commander Decks", "Expansions", "Funny Sets", "Boxed Sets"}
	for range 20 {
		sealed, _ := getSealedEditions(b)
		all, _ := getAllEditionsByCategory(b)
		if !slices.Equal(sealed, want) || !slices.Equal(all, want) {
			t.Fatalf("sealed categories %v, all categories %v, want %v", sealed, all, want)
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

// TestNewHighReducer covers the new-high rule: keep cards whose current
// buylist price beats every price before today, and report that high.
func TestNewHighReducer(t *testing.T) {
	stats := timeseries.AggregatePriceStats{Max: 6, Min: 2, Count: 10, PriorMax: 5}

	cases := []struct {
		name    string
		stats   timeseries.AggregatePriceStats
		current float64
		want    float64
		ok      bool
	}{
		{"below the prior high", stats, 4, 0, false},
		{"ties the prior high", stats, 5, 0, false},
		{"beats the prior high", stats, 6, 5, true},
		{"not buying", stats, 0, 0, false},
		{"only today's row", timeseries.AggregatePriceStats{Max: 6, Min: 6, Count: 1}, 6, 0, false},
		{"flat window", timeseries.AggregatePriceStats{Max: 4, Min: 4, Count: 30, PriorMax: 4}, 4, 0, false},
	}
	for _, tc := range cases {
		got, ok := newHighReducer(tc.stats, tc.current)
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

// TestGoodBuylistPrice covers the P90 metric. The actual percentile math runs
// in Postgres; this reducer is just a field selector with a sample-count gate,
// so the cases pin the gate boundaries and the field selection.
func TestGoodBuylistPrice(t *testing.T) {
	minSamples := int64(minNumberDays)

	cases := []struct {
		name  string
		stats timeseries.AggregatePriceStats
		want  float64
		ok    bool
	}{
		{"no data", timeseries.AggregatePriceStats{}, 0, false},
		{"one below the minimum", timeseries.AggregatePriceStats{P90: 5, Count: minSamples - 1}, 0, false},
		{"exactly the minimum", timeseries.AggregatePriceStats{P90: 5, Count: minSamples}, 5, true},
		{"well above the minimum", timeseries.AggregatePriceStats{P90: 12, Count: 90}, 12, true},
		// The selector reports P90, not Max — the metric IS the percentile.
		{"reports P90, ignores Max", timeseries.AggregatePriceStats{Max: 100, P90: 5, Count: 30}, 5, true},
	}
	for _, tc := range cases {
		got, ok := goodBuylistPrice(tc.stats, 0)
		if ok != tc.ok || !almostEqual(got, tc.want) {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
