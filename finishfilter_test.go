package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// finishCard builds a printing carrying a game's own finish name.
func finishCard(uuid, finish string, foil bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{Foil: foil}
	co.UUID = uuid
	co.Finish = finish
	return co
}

// matches runs the filter the way the search does, through fixupFinishNG, and
// reports whether the card survives (cardFilterFinish returns "skip this one").
func matches(query string, co *mtgmatcher.CardObject) bool {
	return !cardFilterFinish(fixupFinishNG(query), co)
}

// A game with no finishes of its own is answered by the three shared names
// exactly as before: its Finish is one of them, so the new comparison agrees
// with the case rather than adding to it.
func TestFinishFilterKeepsTheSharedNames(t *testing.T) {
	nonfoil := finishCard("m-1", mtgmatcher.FinishNonfoil, false)
	foil := finishCard("m-1_f", mtgmatcher.FinishFoil, true)
	etched := &mtgmatcher.CardObject{Foil: true, Etched: true}
	etched.UUID = "m-1_e"
	etched.Finish = mtgmatcher.FinishEtched

	tests := []struct {
		query string
		co    *mtgmatcher.CardObject
		want  bool
	}{
		{"foil", foil, true},
		{"f", foil, true},
		{"foil", nonfoil, false},
		{"nonfoil", nonfoil, true},
		{"nf", nonfoil, true},
		{"r", nonfoil, true},
		{"nonfoil", foil, false},
		{"etched", etched, true},
		{"e", etched, true},
		{"etched", foil, false},
	}
	for _, test := range tests {
		if got := matches(test.query, test.co); got != test.want {
			t.Errorf("f:%s against %q = %t, want %t", test.query, test.co.UUID, got, test.want)
		}
	}
}

// Yu-Gi-Oh prices print runs, so the run is the whole distinction between two
// printings and no foilness can express it.
func TestFinishFilterReachesPrintRuns(t *testing.T) {
	first := finishCard("hac1-en105_265004_1e", "1stedition", false)
	unlimited := finishCard("hac1-en105_265004_unl", "unlimited", false)

	if !matches("1stedition", first) {
		t.Error("f:1stedition did not match the 1st edition printing")
	}
	if matches("1stedition", unlimited) {
		t.Error("f:1stedition matched the unlimited printing")
	}
	if !matches("unlimited", unlimited) {
		t.Error("f:unlimited did not match the unlimited printing")
	}
	if matches("unlimited", first) {
		t.Error("f:unlimited matched the 1st edition printing")
	}
}

// Flesh and Blood names its treatments, and both of them are foil - so f:foil
// still reaches either and only the treatment separates them.
func TestFinishFilterSeparatesTreatments(t *testing.T) {
	rainbow := finishCard("omn071_695162_rainbow", "rainbowfoil", true)
	cold := finishCard("omn071_695162_cold", "coldfoil", true)

	for _, co := range []*mtgmatcher.CardObject{rainbow, cold} {
		if !matches("foil", co) {
			t.Errorf("f:foil stopped matching %q", co.UUID)
		}
	}
	if !matches("rainbowfoil", rainbow) || matches("rainbowfoil", cold) {
		t.Error("f:rainbowfoil did not pick out the rainbow printing alone")
	}
	if !matches("coldfoil", cold) || matches("coldfoil", rainbow) {
		t.Error("f:coldfoil did not pick out the cold printing alone")
	}
}

// The query is spelled the way a finish is stored, so the separators and case
// a person writes make no difference.
func TestFinishFilterNormalizesTheQuery(t *testing.T) {
	rainbow := finishCard("omn071_695162_rainbow", "rainbowfoil", true)
	for _, query := range []string{"rainbowfoil", "Rainbow Foil", "rainbow-foil", "RAINBOWFOIL"} {
		if !matches(query, rainbow) {
			t.Errorf("f:%s did not match a rainbowfoil printing", query)
		}
	}
}

// A bare treatment name is registered as a spelling reaching the qualified
// finish a product is actually sold under, and has to resolve to this printing
// rather than merely be known to the card.
func TestFinishFilterFollowsAnAlias(t *testing.T) {
	co := finishCard("evo056_517297_unlrainbow", "unlrainbowfoil", true)
	co.FoilUUIDs = map[string]string{
		"unlrainbowfoil": "evo056_517297_unlrainbow",
		"1srainbowfoil":  "evo056_517297_1erainbow",
	}
	co.FinishAliases = map[string]string{"rainbowfoil": "unlrainbowfoil"}

	if !matches("rainbowfoil", co) {
		t.Error("f:rainbowfoil did not follow the alias to this printing")
	}

	// The sibling knows the same alias, but it names the other printing.
	other := finishCard("evo056_517297_1erainbow", "1srainbowfoil", true)
	other.FoilUUIDs = co.FoilUUIDs
	other.FinishAliases = co.FinishAliases
	if matches("rainbowfoil", other) {
		t.Error("f:rainbowfoil matched a printing the alias does not name")
	}
}
