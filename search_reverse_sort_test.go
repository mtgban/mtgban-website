package main

import (
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

// TestReverseSortKeepsNonfoilFirst is the is:promopack case from the site:
// reversing a sort reverses the editions and numbers, but each printing
// still lists its nonfoil before its foil, in every sort that reads both
// finishes alike. A price sort parts them by price.
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

	// A printing's finishes share one expected count, so the odds sort
	// orders the printings and leaves its finishes to the tie-break
	odds := map[string]float64{}
	printings := map[string]float64{}
	for _, uuid := range keys {
		co, _ := backend().GetUUID(uuid)
		printing := co.Edition + "|" + co.Card.Number
		value, found := printings[printing]
		if !found {
			value = float64(len(printings))
			printings[printing] = value
		}
		odds[uuid] = value
	}

	for _, sortMode := range []string{"chrono", "alpha", "hybrid", "number", "odds"} {
		t.Run(sortMode, func(t *testing.T) {
			forward := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, currentPrices(), forward, odds, nil, sortMode, false)
			reversed := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, currentPrices(), reversed, odds, nil, sortMode, true)

			if forward[0] == reversed[0] {
				t.Errorf("%s leads both directions: the list was not reversed", forward[0])
			}
			if sortMode == "odds" {
				for i := 1; i < len(keys); i++ {
					if odds[forward[i-1]] > odds[forward[i]] {
						t.Fatalf("forward: odds %v sorts ahead of %v", odds[forward[i-1]], odds[forward[i]])
					}
					if odds[reversed[i-1]] < odds[reversed[i]] {
						t.Fatalf("reversed: odds %v sorts ahead of %v", odds[reversed[i-1]], odds[reversed[i]])
					}
				}
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
	ds := &datastore{backend: &matcher.Backend{}}
	odds := map[string]float64{"low": 0.5, "zero": 0, "high": 2}

	for reversed, want := range map[bool][]string{
		false: {"zero", "low", "high"},
		true:  {"high", "low", "zero"},
	} {
		keys := []string{"none", "high", "missing", "zero", "low"}
		sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, currentPrices(), keys, odds, nil, "odds", reversed)
		if !slices.Equal(keys[:3], want) {
			t.Errorf("reversed %v: covered cards sorted %v, want %v", reversed, keys[:3], want)
		}
		if !slices.Contains(keys[3:], "none") || !slices.Contains(keys[3:], "missing") {
			t.Errorf("reversed %v: uncovered cards are not last: %v", reversed, keys)
		}
	}
}

// TestReverseSortKeepsEveryGamesFinishOrder: the finishes the flags read
// alike, Pokemon's holofoils, Yu-Gi-Oh's runs and Flesh and Blood's foils,
// keep their order within a card when the sort is reversed, as the
// nonfoil and foil of a Magic card do.
func TestReverseSortKeepsEveryGamesFinishOrder(t *testing.T) {
	b := &matcher.Backend{Sets: map[string]*matcher.Set{}, UUIDs: map[string]*matcher.CardObject{}}
	var keys []string
	for setCode, finishes := range map[string][]string{
		"PKM": {"nonfoil", "holofoil", "reverseholofoil"},
		"YGO": {"1stedition", "unlimited", "1steditionholofoil"},
		"FAB": {"nonfoil", "foil", "rainbowfoil", "coldfoil"},
	} {
		b.Sets[setCode] = &matcher.Set{Code: setCode, Name: setCode + " Set"}
		for _, number := range []string{"001", "002"} {
			card := &matcher.Card{Name: setCode + number, Number: number, SetCode: setCode}
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
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, currentPrices(), forward, nil, nil, sortMode, false)
			reversed := slices.Clone(keys)
			sortSearchKeys(httptest.NewRequest("GET", "/search", nil), ds, currentPrices(), reversed, nil, nil, sortMode, true)

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

// TestReverseSortFromSyntax: -sort: takes the same orders as sort: and runs
// them backwards, while the order it names is the one used.
func TestReverseSortFromSyntax(t *testing.T) {
	b := &matcher.Backend{}
	for _, c := range []struct {
		query, target string
		sort          string
		reversed      bool
	}{
		{"sort:retail", "/search", "retail", false},
		{"-sort:retail", "/search", "retail", true},
		{"-sort:Retail", "/search", "retail", true},
		{"sort:retail", "/search?reverse=true", "retail", true},
		{"-sort:retail", "/search?reverse=false", "retail", true},
		{"-sort:nope", "/search", "", false},
		// Velocity unlocked by no handler leaves the parameter's order, forwards
		{"-sort:velocity", "/search?sort=alpha", "alpha", false},
	} {
		config := parseSearchOptionsNG(b, currentPrices(), c.query, nil, nil, nil)
		r := httptest.NewRequest("GET", c.target, nil)
		if got := readSearchSort(r, config); got != c.sort {
			t.Errorf("%s at %s: sort %q, want %q", c.query, c.target, got, c.sort)
		}
		if got := readSearchReverse(r, config); got != c.reversed {
			t.Errorf("%s at %s: reversed %v, want %v", c.query, c.target, got, c.reversed)
		}
	}
}
