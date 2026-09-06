package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// productWithBothKinds finds a product that holds a fixed list and cards it
// might come with, which is the only shape any of this is for. Chosen by
// scanning rather than pinned, so the test fails for being wrong instead of
// for a product having been reprinted.
func productWithBothKinds(t *testing.T) *mtgmatcher.CardObject {
	t.Helper()
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !mtgmatcher.SealedHasDecklist(code, product.UUID) ||
				!mtgmatcher.SealedIsRandom(code, product.UUID) {
				continue
			}
			co, err := mtgmatcher.GetUUID(product.UUID)
			if err == nil {
				return co
			}
		}
	}
	return nil
}

// What the reading is for: such a product lists a great deal more than it
// always holds, so what it might hold is worth asking for on its own.
func TestAProductHoldsMoreThanItGuarantees(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}

	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s has no fixed list after all: %v", co.Name, err)
	}
	picks, err := mtgmatcher.GetPicksForSealed(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s opens into nothing: %v", co.Name, err)
	}
	if len(picks) <= len(deck) {
		t.Errorf("%s picks %d cards from a guaranteed %d, so there is nothing to separate",
			co.Name, len(picks), len(deck))
	}
}

// The variable reading is the contents with the fixed list taken back out, so
// it is two filters composed rather than a list built.
func TestVariableIsTheContentsWithoutTheFixedList(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}
	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil {
		t.Fatal(err)
	}

	config := parseSearchOptionsNG(`variable:"`+co.Name+`"`, nil, nil, nil)

	var holdsContents, dropsTheDeck bool
	for _, filter := range config.CardFilters {
		if filter.Name == "contents" && !filter.Negate &&
			len(filter.Values) == 1 && filter.Values[0] == co.UUID {
			holdsContents = true
		}
		if filter.Name == "idlookup" && filter.Negate && len(filter.Values) == len(deck) {
			dropsTheDeck = true
		}
	}
	if !holdsContents {
		t.Error("the variable reading does not start from the product's contents")
	}
	if !dropsTheDeck {
		t.Error("the variable reading does not take the fixed list back out")
	}

	// And the cards it keeps are the ones the product does not guarantee.
	for _, uuid := range deck {
		if !shouldSkipCardNG(uuid, config.CardFilters) {
			card, _ := mtgmatcher.GetUUID(uuid)
			t.Errorf("%s is guaranteed but survives the variable reading", card)
			break
		}
	}
}
