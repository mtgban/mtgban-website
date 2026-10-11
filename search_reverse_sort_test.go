package main

import (
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestReverseSortKeepsNonfoilFirst is the is:promopack case from the site:
// reversing a sort reverses the editions and numbers, but each printing
// still lists its nonfoil before its foil, whatever the sort.
func TestReverseSortKeepsNonfoilFirst(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	var keys []string
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || !slices.Contains(co.PromoTypes, "promopack") {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) < 2 {
		t.Skip("no promo pack printings in the datastore")
	}

	for _, sortMode := range []string{"chrono", "alpha", "hybrid", "number", "retail", "buylist", "odds"} {
		t.Run(sortMode, func(t *testing.T) {
			forward := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, forward, nil, sortMode)
			reversed := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search?reverse=true", nil), ds, reversed, nil, sortMode)

			if forward[0] == reversed[0] {
				t.Errorf("%s leads both directions: the list was not reversed", forward[0])
			}

			sortData := resolveSortingData(backend(), reversed)
			seen := map[string]bool{}
			var foils int
			for _, uuid := range reversed {
				co := sortData[uuid].co
				printing := co.Card.Number
				if sortMode != "number" {
					printing = co.Edition + "|" + printing
				}
				if !co.Foil && !co.Etched {
					seen[printing] = true
					continue
				}
				foils++
				nonfoil := co.UUID[:len(co.UUID)-2]
				_, hasNonfoil := sortData[nonfoil]
				if hasNonfoil && !seen[printing] {
					t.Errorf("%s %s #%s: the foil sorts ahead of the nonfoil", co.Name, co.Edition, co.Card.Number)
				}
			}
			if foils == 0 {
				t.Error("no foil promo pack printings, so this set no longer covers the case")
			}
		})
	}
}

// TestReverseOddsSortKeepsUncoveredLast: reversing the drop-rate sort turns
// the known rates around, and the cards no rate covers stay at the end.
func TestReverseOddsSortKeepsUncoveredLast(t *testing.T) {
	ds := &datastore{backend: &mtgmatcher.Backend{}}
	odds := map[string]float64{"low": 0.5, "zero": 0, "high": 2}

	for query, want := range map[string][]string{
		"":              {"zero", "low", "high"},
		"?reverse=true": {"high", "low", "zero"},
	} {
		keys := []string{"none", "high", "missing", "zero", "low"}
		sortSearchKeys(httptest.NewRequest("GET", "/search"+query, nil), ds, keys, odds, "odds")
		if !slices.Equal(keys[:3], want) {
			t.Errorf("%q: covered cards sorted %v, want %v", query, keys[:3], want)
		}
		if !slices.Contains(keys[3:], "none") || !slices.Contains(keys[3:], "missing") {
			t.Errorf("%q: uncovered cards are not last: %v", query, keys)
		}
	}
}

// TestReverseSortKeepsEveryGamesFinishOrder: the finishes the flags read
// alike, Pokemon's holofoils, Yu-Gi-Oh's runs and Flesh and Blood's foils,
// keep their order within a card when the sort is reversed, as the
// nonfoil and foil of a Magic card do.
func TestReverseSortKeepsEveryGamesFinishOrder(t *testing.T) {
	b := &mtgmatcher.Backend{Sets: map[string]*mtgmatcher.Set{}, UUIDs: map[string]*mtgmatcher.CardObject{}}
	var keys []string
	for setCode, finishes := range map[string][]string{
		"PKM": {"nonfoil", "holofoil", "reverseholofoil"},
		"YGO": {"1stedition", "unlimited", "1steditionholofoil"},
		"FAB": {"nonfoil", "foil", "rainbowfoil", "coldfoil"},
	} {
		b.Sets[setCode] = &mtgmatcher.Set{Code: setCode, Name: setCode + " Set"}
		for _, number := range []string{"001", "002"} {
			card := &mtgmatcher.Card{Name: setCode + number, Number: number, SetCode: setCode}
			for _, finish := range finishes {
				uuid := setCode + number + "_" + finish
				b.AddPrinting(card, uuid, finish)
				keys = append(keys, uuid)
			}
		}
	}
	b.IndexSets()
	ds := testSite.newDatastore(b, time.Now())

	for _, sortMode := range []string{"chrono", "alpha", "hybrid", "number"} {
		t.Run(sortMode, func(t *testing.T) {
			forward := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, forward, nil, sortMode)
			reversed := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search?reverse=true", nil), ds, reversed, nil, sortMode)

			// Each card's finishes in the order shown, and the cards in theirs
			finishesOf := func(sorted []string) (map[string][]string, []string) {
				finishes := map[string][]string{}
				var cards []string
				for _, uuid := range sorted {
					co := b.UUIDs[uuid]
					if len(finishes[co.Name]) == 0 {
						cards = append(cards, co.Name)
					}
					finishes[co.Name] = append(finishes[co.Name], co.Finish)
				}
				return finishes, cards
			}
			forwardFinishes, forwardCards := finishesOf(forward)
			reversedFinishes, reversedCards := finishesOf(reversed)

			for card, want := range forwardFinishes {
				if !slices.Equal(reversedFinishes[card], want) {
					t.Errorf("%s: reversed lists %v, forward %v", card, reversedFinishes[card], want)
				}
			}
			if sortMode != "number" {
				slices.Reverse(forwardCards)
				if !slices.Equal(reversedCards, forwardCards) {
					t.Errorf("the cards are not reversed: %v", reversedCards)
				}
			}
		})
	}
}
