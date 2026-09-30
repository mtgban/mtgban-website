package main

import (
	"slices"
	"sort"
	"testing"
)

// The credit market sort ranks a store with no credit, or no market rate
// for its credit, by its cash offer rather than sinking it to the bottom.
func TestBuylistMarketSortFallsBackToCash(t *testing.T) {
	entries := []SearchEntry{
		{ScraperName: "Cool Stuff Inc", Price: 14, Credit: 17.50, MarketCredit: 15.40},
		{ScraperName: "Card Kingdom", Price: 14, Credit: 18.20, MarketCredit: 14.92},
		{ScraperName: "ABU Games (credit)", Price: 24, Credit: 24, MarketCredit: 14.88},
		{ScraperName: "Star City Games", Price: 12, Credit: 15.60, MarketCredit: 13.26},
		{ScraperName: "ABU Games", Price: 12.40},
		{ScraperName: "Game Nerdz", Price: 20.81, Credit: 26.01},
		{ScraperName: "Hareruya", Price: 9.51},
		{ScraperName: "Strike Zone", Price: 15},
		{ScraperName: "TCG Direct (net)", Price: 30.94},
		{ScraperName: "Vegas Singles", Price: 22.06},
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].marketValue() > entries[j].marketValue()
	})

	var got []string
	for _, entry := range entries {
		got = append(got, entry.ScraperName)
	}
	want := []string{
		"TCG Direct (net)", "Vegas Singles", "Game Nerdz", "Cool Stuff Inc",
		"Strike Zone", "Card Kingdom", "ABU Games (credit)", "Star City Games",
		"ABU Games", "Hareruya",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
