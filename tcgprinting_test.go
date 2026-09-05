package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TCGplayer's Printing filter takes TCGplayer's own name for the printing.
// Magic is priced under "Normal" and "Foil", so the flags answer; every other
// game is priced under its treatment or print run, and asserting "Foil" there
// filters the product down to a printing it does not have.
func TestTCGPrintingForCard(t *testing.T) {
	savedGame, savedDB := Config.Game, PricesArchiveDB
	t.Cleanup(func() { Config.Game, PricesArchiveDB = savedGame, savedDB })
	PricesArchiveDB = nil

	card := func(foil, etched bool) *mtgmatcher.CardObject {
		return &mtgmatcher.CardObject{Foil: foil, Etched: etched}
	}

	Config.Game = DefaultGame
	magic := []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"nonfoil", card(false, false), "Normal"},
		{"foil", card(true, false), "Foil"},
		{"etched", card(false, true), "Foil"},
	}
	for _, test := range magic {
		t.Run("magic/"+test.name, func(t *testing.T) {
			if got := tcgPrintingForCard(test.co); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}

	// Without the product's sub-types there is no name to give, and the filter
	// has to come off rather than be guessed at.
	Config.Game = "fleshandblood"
	for _, test := range magic {
		t.Run("fleshandblood/"+test.name, func(t *testing.T) {
			if got := tcgPrintingForCard(test.co); got != "" {
				t.Errorf("got %q, want no printing filter", got)
			}
		})
	}
}
