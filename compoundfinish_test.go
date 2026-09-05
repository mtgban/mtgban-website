package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// fabFinish is a printing as mtgmatcher/fleshandblood stores one: the finish
// is the print run and the treatment run together into a single word, and the
// bare treatments the product is sold in are registered as spellings it
// answers to. These are the eight finishes that datastore actually ships.
func fabFinish(finish string, aliases ...string) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{}
	co.Finish = finish
	co.FinishAliases = map[string]string{}
	for _, alias := range aliases {
		// The value names whichever printing that spelling reaches, which is a
		// sibling as often as this one; only the key is read.
		co.FinishAliases[alias] = "some-sibling"
	}
	return co
}

// A finish carrying a print run is spelled as its two halves. Spelling the
// word whole gave "1Steditionrainbow Foil", which is worse than the plain
// "Foil" it replaced, and left a plain 1st Edition printing labelled
// "1Steditionnormal".
func TestSplitCompoundFinish(t *testing.T) {
	tests := []struct {
		name           string
		co             *mtgmatcher.CardObject
		run, treatment string
		label          string
	}{
		{"bare plain", fabFinish("normal"), "", "normal", ""},
		{"bare treatment", fabFinish("rainbowfoil"), "", "rainbowfoil", "Rainbow Foil"},
		{"bare cold", fabFinish("coldfoil"), "", "coldfoil", "Cold Foil"},

		{"run with a plain printing", fabFinish("1steditionnormal", "normal"),
			"1stedition", "normal", "1st Edition"},
		{"run with a treatment", fabFinish("1steditionrainbowfoil", "normal", "rainbowfoil"),
			"1stedition", "rainbowfoil", "1st Edition Rainbow Foil"},
		{"the other run", fabFinish("unlimitededitionrainbowfoil", "coldfoil", "rainbowfoil"),
			"unlimitededition", "rainbowfoil", "Unlimited Edition Rainbow Foil"},
		{"run with cold", fabFinish("1steditioncoldfoil", "coldfoil", "rainbowfoil"),
			"1stedition", "coldfoil", "1st Edition Cold Foil"},
		{"the other run, plain", fabFinish("unlimitededitionnormal", "normal"),
			"unlimitededition", "normal", "Unlimited Edition"},

		// Yu-Gi-Oh sells print runs with no treatment at all, so the whole
		// finish is the run's name and there is no alias to split on.
		{"a print run alone", fabFinish("1stedition"), "", "1stedition", "1st Edition"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, treatment := splitFinish(test.co)
			if run != test.run || treatment != test.treatment {
				t.Errorf("splitFinish = (%q, %q), want (%q, %q)", run, treatment, test.run, test.treatment)
			}
			if got := finishLabel(test.co); got != test.label {
				t.Errorf("finishLabel = %q, want %q", got, test.label)
			}
		})
	}
}

// The treatment is what says whether anything was done to the card, so a plain
// printing of a named run is still plain — it used to land among the foils and
// join the positional sub-type pairing.
func TestPlainTreatmentOfANamedRun(t *testing.T) {
	co := fabFinish("1steditionnormal", "normal")
	_, treatment := splitFinish(co)
	if !isPlainTreatment(treatment) {
		t.Error("1steditionnormal treated as a treatment, not a plain printing")
	}
	if isPlainTreatment("rainbowfoil") {
		t.Error("rainbowfoil treated as plain")
	}
}
