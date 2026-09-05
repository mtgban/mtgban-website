package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func legendCard(finish string, foil, etched bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{Foil: foil, Etched: etched}
	co.Name = "War Machine"
	co.SetCode = "EVO"
	co.Number = "EVO056"
	co.Finish = finish
	return co
}

// Two printings of one card have to read differently in the legend, which is
// the whole reason the finish is in it. The flags cannot do that for a game
// with more than one foil: they say "Foil" twice.
func TestChartLegendName(t *testing.T) {
	tests := []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"rainbow foil", legendCard("rainbowfoil", true, false), "War Machine (EVO) #EVO056 Rainbow Foil"},
		{"cold foil", legendCard("coldfoil", true, false), "War Machine (EVO) #EVO056 Cold Foil"},
		{"the plain printing", legendCard("normal", false, false), "War Machine (EVO) #EVO056"},

		// Magic names no finish of its own, so the flags still answer and the
		// legend reads exactly as it did.
		{"magic foil", legendCard(mtgmatcher.FinishFoil, true, false), "War Machine (EVO) #EVO056 Foil"},
		{"magic etched", legendCard(mtgmatcher.FinishEtched, false, true), "War Machine (EVO) #EVO056 Etched"},
		{"magic nonfoil", legendCard(mtgmatcher.FinishNonfoil, false, false), "War Machine (EVO) #EVO056"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := chartLegendName(test.co)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// A sealed product carries no finish and no collector number, and its name is
// the whole of what the legend says.
func TestChartLegendNameSealed(t *testing.T) {
	co := &mtgmatcher.CardObject{Sealed: true}
	co.Name = "Bright Lights Booster Box"
	co.SetCode = "EVO"
	if got := chartLegendName(co); got != "Bright Lights Booster Box" {
		t.Errorf("got %q, want the bare name", got)
	}
}
