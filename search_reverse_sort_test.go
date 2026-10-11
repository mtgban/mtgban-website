package main

import (
	"net/http/httptest"
	"slices"
	"testing"

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
