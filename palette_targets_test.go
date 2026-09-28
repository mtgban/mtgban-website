package main

import (
	"encoding/json"
	"html/template"
	"maps"
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/palette"
)

// TestPaletteArbitTargets pins the filters the palette offers on each
// arbitrage page to the ones that page shows some reader, for either source.
// A jump to one the page hides lands with the filter applied and no chip to
// turn it off by, or with the filter dropped. Arbit and reverse hide the
// global-only filters, arbit and global the reverse-only one, and global
// hides the arbit-only ones and the beta ones, which no global reader gets.
func TestPaletteArbitTargets(t *testing.T) {
	arbit := []string{"nocond", "nofoil", "onlyfoil", "nocomm", "nononrl",
		"nononabu4h", "onlyprof", "noposi", "nopenny", "nobuypenny", "nolow",
		"nodiff", "nodiffplus", "noqty", "norand"}
	for _, tt := range []struct {
		name string
		want []string
	}{
		{"palette_arbit_targets", arbit},
		{"palette_reverse_targets", append(slices.Clone(arbit), "noindex")},
		{"palette_global_targets", []string{"nocond", "nofoil", "onlyfoil",
			"nocomm", "nopenny", "nolow", "nodiff", "nodiffplus", "norand",
			"nosyp", "nostock", "nosus", "novolatile"}},
	} {
		build, ok := funcMap[tt.name].(func() template.JS)
		if !ok {
			t.Fatalf("%s is not a func() template.JS", tt.name)
		}
		var targets palette.ArbitTargets
		err := json.Unmarshal([]byte(build()), &targets)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		var got []string
		for _, filter := range targets.Filters {
			got = append(got, filter.Value)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s offers %v\nwant %v", tt.name, got, tt.want)
		}
	}
}

// TestPaletteNewspaperTargets pins the newspaper pages the palette offers
// in each game to the ones the newspaper shows there: the three built on a
// buylist are Magic's alone. The SYP list is not among them: it is a nav
// entry, which the palette offers wherever the nav does.
func TestPaletteNewspaperTargets(t *testing.T) {
	prev := Config.Game
	t.Cleanup(func() { Config.Game = prev })

	magic := []string{"combined_spike_score", "spike_score",
		"greatest_increase_listings", "greatest_decrease_listings",
		"greatest_increase_buylist", "greatest_decrease_buylist"}
	others := []string{"spike_score", "greatest_increase_listings",
		"greatest_decrease_listings"}
	for _, game := range slices.Sorted(maps.Keys(gameMap)) {
		Config.Game = game
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
