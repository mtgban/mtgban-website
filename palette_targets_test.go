package main

import (
	"encoding/json"
	"html/template"
	"maps"
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/palette"
)

// TestPaletteArbitTargets pins the sorts the palette offers on the
// arbitrage pages to the ones those pages know: one they do not is a jump
// that lands unsorted.
func TestPaletteArbitTargets(t *testing.T) {
	build, ok := funcMap["palette_arbit_targets"].(func() template.JS)
	if !ok {
		t.Fatal("palette_arbit_targets is not a func() template.JS")
	}
	var targets palette.ArbitTargets
	err := json.Unmarshal([]byte(build()), &targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets.Sorts) == 0 {
		t.Fatal("the palette offers no sorts")
	}
	for _, sort := range targets.Sorts {
		if arbitLess(backend(), nil, sort.Value, false) == nil {
			t.Errorf("the palette offers %q, which the pages do not sort by", sort.Value)
		}
	}
}

// TestPaletteNewspaperTargets pins the newspaper pages the palette offers
// in each game to the ones the newspaper shows there: the three built on a
// buylist are Magic's alone. The SYP list is not among them: it is a nav
// entry, which the palette offers wherever the nav does.
func TestPaletteNewspaperTargets(t *testing.T) {
	prev := Config().Game
	t.Cleanup(func() { Config().Game = prev })

	magic := []string{"combined_spike_score", "spike_score",
		"greatest_increase_listings", "greatest_decrease_listings",
		"greatest_increase_buylist", "greatest_decrease_buylist"}
	others := []string{"spike_score", "greatest_increase_listings",
		"greatest_decrease_listings"}
	for _, game := range slices.Sorted(maps.Keys(gameMap)) {
		Config().Game = game
		var targets []palette.NavTarget
		err := json.Unmarshal([]byte(palette.NewspaperTargetsJSON(paletteNewspaperPages())), &targets)
		if err != nil {
			t.Fatalf("%s: %v", game, err)
		}
		var got []string
		for _, target := range targets {
			got = append(got, target.Value)
		}
		want := others
		if game == DefaultGame {
			want = magic
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s offers %v\nwant %v", game, got, want)
		}
	}
}
