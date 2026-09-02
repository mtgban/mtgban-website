package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type paletteFinish struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

func fetchFinishes(t *testing.T) []paletteFinish {
	t.Helper()
	rec := httptest.NewRecorder()
	paletteService.Finishes(rec, httptest.NewRequest("GET", "/api/palette/finishes.json", nil))

	var finishes []paletteFinish
	if err := json.Unmarshal(rec.Body.Bytes(), &finishes); err != nil {
		t.Fatal(err)
	}
	return finishes
}

// The list is read off the loaded datastore rather than from a table, so it is
// whatever this game prints - which on Magic is the three shared finishes plus
// the treatments its printings actually wear.
func TestFinishesCacheComesFromTheDatastore(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	paletteService.BuildFinishesCache()
	finishes := fetchFinishes(t)

	if len(finishes) < 4 {
		t.Fatalf("got %d finishes, want the shared ones and some treatments", len(finishes))
	}

	byValue := map[string]paletteFinish{}
	for _, finish := range finishes {
		byValue[finish.Value] = finish
	}
	for _, want := range []string{mtgmatcher.FinishNonfoil, mtgmatcher.FinishFoil} {
		if _, found := byValue[want]; !found {
			t.Errorf("%q is missing from the list", want)
		}
	}

	// A treatment Magic files as a promo type rather than a finish has to be
	// here too, or the list disagrees with what f: accepts.
	treatments := 0
	for _, finish := range finishes {
		if slices.Contains(altFoilTags, finish.Value) {
			treatments++
		}
	}
	if treatments == 0 {
		t.Error("no foil treatment reached the list")
	}

	// Every entry says how many printings wear it, and is spelled for reading.
	for _, finish := range finishes {
		if finish.Count <= 0 {
			t.Errorf("%q has count %d", finish.Value, finish.Count)
		}
		if finish.Label == "" {
			t.Errorf("%q has no label", finish.Value)
		}
	}

	// Commonest first, so a caller showing the head shows what the game mostly
	// wears.
	if !slices.IsSortedFunc(finishes, func(a, b paletteFinish) int { return b.Count - a.Count }) {
		t.Error("the list is not ordered by how common each finish is")
	}
}

// A game spells its own treatments better than any rule can, so where it has a
// spelling the list uses it rather than title-casing the token.
func TestFinishesCacheUsesTheGamesSpelling(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	paletteService.BuildFinishesCache()

	for _, finish := range fetchFinishes(t) {
		if finish.Value != "doublerainbow" {
			continue
		}
		if finish.Label != "Double Rainbow" {
			t.Errorf("doublerainbow is labelled %q, want Magic's own %q",
				finish.Label, "Double Rainbow")
		}
		return
	}
	t.Skip("this datastore has no doublerainbow printing")
}

// Foil is capitalised throughout. The game's map spells fifteen treatments
// "X foil" and seven "X Foil"; a list has to pick one, and this is the
// spelling the finishes a game names itself already use - Cold Foil, Rainbow
// Foil - so every row reads the same whichever half it came from.
func TestFinishListLabelCapitalisesFoil(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	tests := []struct{ finish, want string }{
		// The fifteen the game spells lowercase.
		{"surgefoil", "Surge Foil"},
		{"galaxyfoil", "Galaxy Foil"},
		{"embossed", "Embossed Foil"},
		{"oilslick", "Oil Slick Foil"},
		// The seven it already capitalises, unchanged.
		{"firstplacefoil", "First Place Foil"},
		{"dragonscalefoil", "Dragon Scale Foil"},
		// The words are still the game's: only a trailing foil moves, and a
		// treatment that is not "something foil" keeps its own shape.
		{"doublerainbow", "Double Rainbow"},
		{"stepandcompleat", "Step-and-Compleat"},
		{"neonink", "Neon Ink"},
		// Not a treatment: the finish rule spells it, as it does for the games
		// that name their finishes rather than filing them as promo types -
		// and it already capitalises Foil, which is why this is the spelling
		// the rest were brought to.
		{"coldfoil", "Cold Foil"},
		{"1stedition", "1st Edition"},
	}
	for _, test := range tests {
		if got := finishListLabel(test.finish); got != test.want {
			t.Errorf("finishListLabel(%q) = %q, want %q", test.finish, got, test.want)
		}
	}
}

// Whatever the source, no row in the served list may spell it the other way.
func TestFinishesCacheCapitalisesFoil(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	paletteService.BuildFinishesCache()

	for _, finish := range fetchFinishes(t) {
		if strings.HasSuffix(finish.Label, " foil") {
			t.Errorf("%q is labelled %q, which spells Foil the other way",
				finish.Value, finish.Label)
		}
	}
}
