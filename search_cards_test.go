package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestEdgeOffer(t *testing.T) {
	locked := SearchEntry{ScraperName: "Locked", Price: 9, Locked: true}
	want := SearchEntry{ScraperName: "Want", Price: 0, Quantity: 4, PriceUnit: PriceUnitCount}
	nm := SearchEntry{ScraperName: "NM store", Price: 5}
	sp := SearchEntry{ScraperName: "SP store", Price: 4}
	index := SearchEntry{ScraperName: "Market", Price: 3}

	tests := []struct {
		name  string
		found map[mtgban.Condition][]SearchEntry
		want  string
	}{
		{"nothing", nil, ""},
		{"index rows are references, not offers", map[mtgban.Condition][]SearchEntry{"INDEX": {index}}, ""},
		{"the best grade wins over a cheaper worse one", map[mtgban.Condition][]SearchEntry{"INDEX": {index}, mtgban.NM: {nm}, mtgban.SP: {sp}}, "NM store"},
		{"locked and unpriced rows are skipped", map[mtgban.Condition][]SearchEntry{mtgban.NM: {locked, want, nm}}, "NM store"},
		{"a grade with no priced row passes to the next", map[mtgban.Condition][]SearchEntry{mtgban.NM: {locked}, mtgban.SP: {sp}}, "SP store"},
		{"only locked rows", map[mtgban.Condition][]SearchEntry{mtgban.NM: {locked}}, ""},
	}
	for _, tc := range tests {
		got := edgeOffer(AllConditions, tc.found)
		name := ""
		if got != nil {
			name = got.ScraperName
		}
		if name != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, name, tc.want)
		}
	}
}
