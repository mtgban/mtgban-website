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

// A treatment reaches every printing sold in it, whichever print run: f:
// rainbowfoil finds a product whose only rainbow is the Unlimited printing,
// while the run's own name still picks out that run alone.
func TestFinishFilterMatchesTheTreatment(t *testing.T) {
	unlimited := finishCard("evo056_517297_unlimitededitionrainbowfoil", "unlimitededitionrainbowfoil", true)
	first := finishCard("evo056_517297_1steditionrainbowfoil", "1steditionrainbowfoil", true)
	plain := finishCard("evo056_517297_unlimitededitionnormal", "unlimitededitionnormal", false)

	if !matches("rainbowfoil", unlimited) || !matches("rainbowfoil", first) {
		t.Error("f:rainbowfoil did not reach both runs' rainbow")
	}
	if matches("rainbowfoil", plain) {
		t.Error("f:rainbowfoil matched a plain printing")
	}
	if !matches("1steditionrainbowfoil", first) || matches("1steditionrainbowfoil", unlimited) {
		t.Error("f:1steditionrainbowfoil did not pick out the first edition alone")
	}
}

// A print run reaches every printing sold in it, whichever treatment:
// f:unlimited finds Flesh and Blood's Unlimited Edition and Pokemon's
// Unlimited Holofoil, and never another run or a set printed once.
func TestFinishFilterMatchesThePrintRun(t *testing.T) {
	first := finishCard("wtr006_225017_1steditionnormal", "1steditionnormal", false)
	firstRainbow := finishCard("wtr006_225017_1steditionrainbowfoil", "1steditionrainbowfoil", true)
	unlimitedRainbow := finishCard("wtr006_225017_unlimitededitionrainbowfoil", "unlimitededitionrainbowfoil", true)
	printedOnce := finishCard("omn015_682847_rainbowfoil", "rainbowfoil", true)
	firstHolo := finishCard("01-62_44418_1steditionholofoil", "1steditionholofoil", true)
	unlimitedHolo := finishCard("01-62_44418_unlimitedholofoil", "unlimitedholofoil", true)

	tests := []struct {
		query string
		co    *mtgmatcher.CardObject
		want  bool
	}{
		{"1stedition", first, true},
		{"1stedition", firstRainbow, true},
		{"1stedition", unlimitedRainbow, false},
		{"unlimited", unlimitedRainbow, true},
		{"unlimited", first, false},
		{"unlimited", firstRainbow, false},
		{"1stedition", firstHolo, true},
		{"unlimited", firstHolo, false},
		{"unlimited", unlimitedHolo, true},
		{"1stedition", unlimitedHolo, false},
		{"unlimited", printedOnce, false},
		{"limited", unlimitedRainbow, false},
		// The trailing comma leaves an empty value, which names no run
		{"unlimited,", printedOnce, false},
	}
	for _, test := range tests {
		got := matches(test.query, test.co)
		if got != test.want {
			t.Errorf("f:%s against %q = %t, want %t", test.query, test.co.UUID, got, test.want)
		}
	}
}

// Magic files its foil treatments as promo types, not finishes - its only
// finishes are nonfoil, foil and etched - so the treatment has to be reached
// there or a galaxy foil is only ever f:foil.
func TestFinishFilterReachesMagicTreatments(t *testing.T) {
	galaxy := finishCard("m-2_f", mtgmatcher.FinishFoil, true)
	galaxy.PromoTypes = []string{"galaxyfoil"}

	if !matches("galaxyfoil", galaxy) {
		t.Error("f:galaxyfoil did not match a card carrying that treatment")
	}
	if !matches("galaxy", galaxy) {
		t.Error("f:galaxy did not expand the way is:galaxy does")
	}
	if matches("surgefoil", galaxy) {
		t.Error("f:surgefoil matched a galaxy foil")
	}
	if !matches("foil", galaxy) {
		t.Error("f:foil stopped reaching a treated foil")
	}
}

// f: means the finish, so a promo type that names something else stays out of
// reach even though it is a promo type like the treatments are.
func TestFinishFilterIgnoresNonFoilPromoTypes(t *testing.T) {
	prerelease := finishCard("m-3_f", mtgmatcher.FinishFoil, true)
	prerelease.PromoTypes = []string{"prerelease"}

	if matches("prerelease", prerelease) {
		t.Error("f:prerelease matched: f: reaches foilings, not every promo type")
	}
}
