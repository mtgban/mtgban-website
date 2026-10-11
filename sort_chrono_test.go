package main

import (
	"os"
	"slices"
	"sort"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestChronoSortIsOneOrderInEverySet sorts every set of every game's
// datastore, both ways round, and checks each pair of the result in turn: a
// comparison that loops on any three printings leaves some pair inverted.
// Magic runs whenever the suite loads it; the other games when the
// variable naming their datastore is set.
func TestChronoSortIsOneOrderInEverySet(t *testing.T) {
	t.Run("magic", func(t *testing.T) {
		skipWithoutDatastore(t)
		checkSetOrders(t, backend())
	})
	for game, envVar := range gameDatastores {
		t.Run(string(game), func(t *testing.T) {
			path := os.Getenv(envVar)
			if path == "" {
				t.Skip(envVar + " is not set")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			loaded, err := mtgmatcher.Open(game, f)
			if err != nil {
				t.Fatal(err)
			}
			checkSetOrders(t, loaded)
		})
	}
}

// Three printings shaped like the ones of Pokemon's MCAP that looped: 1
// and 001 in English, the latter with a promo type, and 001 in Japanese,
// each pair ordered by a different field. And One Piece numbers read after
// their set code, so OP01-005 precedes OP01-021 whatever their languages.
func TestChronoSortReadsEqualValuesOneWay(t *testing.T) {
	printing := func(uuid, number, language string, promos ...string) *SortingData {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Number: number, Language: language, PromoTypes: promos}}
		return &SortingData{co: co, numberPrefix: setCodePrefix(number)}
	}
	for _, want := range [][]*SortingData{
		{printing("a", "001", "English", "promo"), printing("b", "1", "English"), printing("c", "001", "Japanese")},
		{printing("d", "OP01-005", "Japanese"), printing("e", "OP01-021", "English")},
	} {
		for i, a := range want {
			for _, b := range want[i+1:] {
				if !cmpNumberAndFinish(a, b, true) || cmpNumberAndFinish(b, a, true) {
					t.Errorf("%s %s should come before %s %s", a.co.Number, a.co.Language, b.co.Number, b.co.Language)
				}
			}
		}
	}
}

func checkSetOrders(t *testing.T, b *mtgmatcher.Backend) {
	t.Helper()
	chrono := cmpSets
	number := func(a, b *SortingData) bool { return cmpNumberAndFinish(a, b, false) }
	for _, code := range b.GetAllSets() {
		keys := b.GetUUIDsInSet(code)
		for _, reversed := range []bool{false, true} {
			sortData := resolveSortingData(b, keys)
			if reversed {
				negateFinishes(sortData)
			}
			for mode, less := range map[string]func(a, b *SortingData) bool{"chrono": chrono, "number": number} {
				sorted := slices.Clone(keys)
				sort.Slice(sorted, func(i, j int) bool {
					return less(sortData[sorted[i]], sortData[sorted[j]])
				})
				var inverted int
				var first [2]*SortingData
				for i := range sorted {
					for j := i + 1; j < len(sorted); j++ {
						a, b := sortData[sorted[i]], sortData[sorted[j]]
						if less(a, b) && !less(b, a) {
							continue
						}
						if inverted == 0 {
							first = [2]*SortingData{a, b}
						}
						inverted++
					}
				}
				if inverted > 0 {
					t.Errorf("%s %s reversed=%v: %d pairs out of order, first %s %s (%s) before %s %s (%s)",
						code, mode, reversed, inverted,
						first[0].co.Number, first[0].co.Language, first[0].co.Finish,
						first[1].co.Number, first[1].co.Language, first[1].co.Finish)
				}
			}
		}
	}
}
