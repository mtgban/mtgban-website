package main

import (
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
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
		{printing("c", "001", "Japanese"), printing("a", "001", "English", "promo"), printing("b", "1", "English")},
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

// Printings that share a number go by finish before language: every
// nonfoil, then every foil, each in language order.
func TestNumberSortPutsFinishBeforeLanguage(t *testing.T) {
	printing := func(uuid, language string, finish int) *SortingData {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Number: "12", Language: language}}
		return &SortingData{co: co, finish: finish}
	}
	want := []*SortingData{printing("a", "English", 0), printing("b", "Japanese", 0), printing("c", "English", 1), printing("d", "Japanese", 1)}
	for _, strip := range []bool{false, true} {
		for i, a := range want {
			for _, b := range want[i+1:] {
				if !cmpNumberAndFinish(a, b, strip) || cmpNumberAndFinish(b, a, strip) {
					t.Errorf("strip=%v: %s finish %d should come before %s finish %d", strip, a.co.Language, a.finish, b.co.Language, b.finish)
				}
			}
		}
	}
}

// Numbers that only share a digit value, like WAR's 1 and 1★ or UST's 3a
// and 3b, each keep their finishes together.
func TestNumberSortKeepsEachNumbersFinishesTogether(t *testing.T) {
	printing := func(number string, finish int) *SortingData {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: number + strconv.Itoa(finish), Number: number, Language: "English"}}
		return &SortingData{co: co, finish: finish, numberPrefix: setCodePrefix(number)}
	}
	for _, want := range [][]*SortingData{
		{printing("1", 0), printing("1", 1), printing("1★", 0), printing("1★", 1)},
		{printing("3a", 0), printing("3a", 1), printing("3b", 0), printing("3b", 1)},
	} {
		for _, strip := range []bool{false, true} {
			for i, a := range want {
				for _, b := range want[i+1:] {
					if !cmpNumberAndFinish(a, b, strip) || cmpNumberAndFinish(b, a, strip) {
						t.Errorf("strip=%v: %s finish %d should come before %s finish %d", strip, a.co.Number, a.finish, b.co.Number, b.finish)
					}
				}
			}
		}
	}
}

func checkSetOrders(t *testing.T, b *mtgmatcher.Backend) {
	t.Helper()
	chrono := cmpSets
	number := func(a, b *SortingData) bool { return cmpNumberAndFinish(a, b, false) }
	ds := &datastore{backend: b}
	for _, code := range b.GetAllSets() {
		keys := b.GetUUIDsInSet(code)
		for _, reversed := range []bool{false, true} {
			sortData := resolveSortingData(b, keys)
			if reversed {
				negateFinishes(sortData)
			}
			r := httptest.NewRequest("GET", "/search?reverse="+strconv.FormatBool(reversed), nil)
			for mode, less := range map[string]func(a, b *SortingData) bool{"chrono": chrono, "number": number} {
				sorted := slices.Clone(keys)
				sortSearchKeys(r, ds, sorted, nil, mode)
				var inverted int
				var first [2]*SortingData
				for i := range sorted {
					for j := i + 1; j < len(sorted); j++ {
						a, b := sortData[sorted[i]], sortData[sorted[j]]
						// A reversed sort puts b first wherever less does
						x, y := a, b
						if reversed {
							x, y = b, a
						}
						if less(x, y) && !less(y, x) {
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
