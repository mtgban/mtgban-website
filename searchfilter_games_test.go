package main

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// gameDatastores names each game by the variable its datastore path lives in.
// They are local builds, so a run without them skips rather than bundling a
// trimmed copy of any of them.
var gameDatastores = map[mtgmatcher.Game]string{
	"lorcana":       "LORCANA_PATH",
	"riftbound":     "RIFTBOUND_PATH",
	"onepiece":      "ONEPIECE_PATH",
	"pokemon":       "POKEMON_PATH",
	"yugioh":        "YUGIOH_PATH",
	"fleshandblood": "FLESHANDBLOOD_PATH",
	"gundam":        "GUNDAM_PATH",
	"palworld":      "PALWORLD_PATH",
}

// Whenever the shorthand tightens a number, the tightened query has to reach
// the printing it named - in every game the site is deployed for, not only
// the one the suite loads.
//
// The tightening hands the number to a filter comparing it against the number
// as the catalog writes it, and a miss there is not a wider answer but no
// answer at all. That is why the token is asked for as typed: ExtractNumberAny
// strips a catalog's padding (Pokemon's 074a becomes 74a) and reduces a
// number rather than trimming it (One Piece's ST01-001 becomes ST01-1), and
// neither is a number the catalog writes.
//
// Only the printings this change tightens are checked, because they are the
// only ones it answers for - Palworld's shorthand, for one, already reaches
// nothing on master. And it runs the real queries rather than reasoning about
// the predicate, because a check written against the predicate passed while
// the search was broken.
func TestShorthandTighteningReachesItsPrintingInEveryGame(t *testing.T) {
	var ran int
	for game, envVar := range gameDatastores {
		path := os.Getenv(envVar)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s: %v", game, err)
			continue
		}
		loaded, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		ran++

		t.Run(string(game), func(t *testing.T) {
			ds := testSite.newDatastore(loaded, time.Now())

			var tightened int
			for _, uuid := range ds.backend.GetUUIDs() {
				co, err := ds.backend.GetUUID(uuid)
				if err != nil || co.Sealed || co.SetCode == "" || co.Number == "" {
					continue
				}
				if mtgmatcher.ExtractNumberAny(co.Number) == "" ||
					!strings.ContainsFunc(co.Number, isNotDigit) {
					continue
				}
				_, err = ds.backend.GetSet(co.SetCode)
				if err != nil {
					continue
				}
				tightened++

				query := co.SetCode + " " + co.Number
				keys, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, query, nil, nil, nil))
				if err != nil {
					t.Errorf("%s: %q: %v", game, query, err)
					continue
				}
				if len(keys) == 0 {
					t.Errorf("%s: %q was tightened and reaches no printing", game, query)
				}
				if tightened >= 50 {
					break
				}
			}
			// A number typed without its padding is not checked: no printing
			// carries it, so it reaches nothing, the same answer "neo 30a"
			// gets and for the same reason. 54 of Pokemon's numbers and 88 of
			// Palworld's can be typed that way.
			t.Logf("%-14s %d tightened numbers checked", game, tightened)
		})
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}

// A lettered cn: number names a printing, in every game: it reaches the card
// numbered that way and nothing numbered otherwise. Flesh and Blood's
// cn:HNT222 used to be reduced to 222 and reach every set's card 222.
func TestLetteredNumberReachesItsPrintingInEveryGame(t *testing.T) {
	var ran int
	for game, envVar := range gameDatastores {
		path := os.Getenv(envVar)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s: %v", game, err)
			continue
		}
		loaded, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		ran++

		t.Run(string(game), func(t *testing.T) {
			ds := testSite.newDatastore(loaded, time.Now())

			var checked int
			for _, uuid := range ds.backend.GetUUIDs() {
				co, err := ds.backend.GetUUID(uuid)
				// A query ending in & * ~ or ` asks for a finish, so
				// Riftbound's 227* is read as 227 in foil.
				if err != nil || co.Sealed || co.Number == "" ||
					!strings.ContainsFunc(co.Number, isNotDigit) ||
					strings.ContainsAny(co.Number, ",: ") ||
					strings.ContainsAny(co.Number[len(co.Number)-1:], "&*~`") {
					continue
				}
				checked++

				query := "cn:" + co.Number
				keys, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, query, nil, nil, nil))
				if err != nil {
					t.Errorf("%s: %q: %v", game, query, err)
					continue
				}
				if !slices.Contains(keys, uuid) {
					t.Errorf("%s: %q does not reach its printing", game, query)
				}
				for _, key := range keys {
					other, err := ds.backend.GetUUID(key)
					if err != nil {
						continue
					}
					if !strings.EqualFold(other.Number, co.Number) &&
						!strings.EqualFold(other.PlainNumber, co.Number) {
						t.Errorf("%s: %q reached #%s", game, query, other.Number)
						break
					}
				}
				if checked >= 50 {
					break
				}
			}
			t.Logf("%-14s %d lettered numbers checked", game, checked)
		})
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}

// A number typed with the set total its card prints, "222/236", reaches that
// printing and only printings carrying both, in every game whose cards print
// a total.
func TestNumberWithTotalReachesItsPrintingInEveryGame(t *testing.T) {
	var ran int
	for game, envVar := range gameDatastores {
		path := os.Getenv(envVar)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s: %v", game, err)
			continue
		}
		loaded, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		ran++

		t.Run(string(game), func(t *testing.T) {
			ds := testSite.newDatastore(loaded, time.Now())

			var checked int
			for _, uuid := range ds.backend.GetUUIDs() {
				co, err := ds.backend.GetUUID(uuid)
				if err != nil || co.Sealed || co.Number == "" || co.SetTotal == "" ||
					strings.Contains(co.Number+co.SetTotal, "/") {
					continue
				}
				checked++

				// Bare only where it has a digit, so a word with a slash in
				// it is still read as a name.
				query := co.Number + "/" + co.SetTotal
				if !strings.ContainsAny(query, "0123456789") {
					query = "cn:" + query
				}
				keys, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, query, nil, nil, nil))
				if err != nil {
					t.Errorf("%q: %v", query, err)
					continue
				}
				if !slices.Contains(keys, uuid) {
					t.Errorf("%q does not reach %s %s", query, co.SetCode, co.Name)
				}
				for _, key := range keys {
					hit, err := ds.backend.GetUUID(key)
					if err != nil {
						continue
					}
					sameNumber := strings.EqualFold(hit.Number, co.Number) ||
						strings.EqualFold(hit.PlainNumber, co.PlainNumber)
					if !sameNumber || plainTotal(hit.SetTotal) != plainTotal(co.SetTotal) {
						t.Errorf("%q reaches %s %s #%s/%s", query, hit.SetCode, hit.Name, hit.Number, hit.SetTotal)
					}
				}
			}
			t.Logf("%-14s %d numbers with a total checked", game, checked)
		})
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}

// A number typed the way its card prints it, "INFO-EN067", reaches that
// printing and no other in every game whose numbers carry their set's code:
// LOB-E027 is not LOB-027, though both are ordinal 27. Typed without its
// region, "info-067", it reaches the printing too, unless a card of the set
// carries that very number. A number carrying another set's code, as Magic's
// List and One Piece's promos do, is read as that other set's card and is not
// checked.
func TestPrintedNumberReachesItsPrintingInEveryGame(t *testing.T) {
	// The printings each number has to reach, and nothing else.
	examples := map[mtgmatcher.Game]map[string]string{
		"yugioh":   {"LOB-E027": "The Furious Sea King", "LOB-027": "Aqua Madoor", "info-067": "That's 10!"},
		"gundam":   {"GD01-001": "Gundam"},
		"onepiece": {"OP03-003": "Izo"},
	}

	var ran int
	for game, envVar := range gameDatastores {
		path := os.Getenv(envVar)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s: %v", game, err)
			continue
		}
		loaded, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		ran++

		t.Run(string(game), func(t *testing.T) {
			ds := testSite.newDatastore(loaded, time.Now())

			for query, name := range examples[game] {
				_, hits := searchHits(t, ds, query)
				if len(hits) == 0 {
					t.Errorf("%q reaches nothing", query)
				}
				for _, hit := range hits {
					if hit.Name != name {
						t.Errorf("%q reaches %s %s %s, not %s", query, hit.SetCode, hit.Number, hit.Name, name)
					}
				}
			}

			var checked int
			for _, uuid := range ds.backend.GetUUIDs() {
				co, err := ds.backend.GetUUID(uuid)
				if err != nil || co.Sealed {
					continue
				}
				split, printed := splitPrintedNumber(ds.backend, co.Number)
				if !printed || !strings.EqualFold(split[0], co.SetCode) ||
					mtgmatcher.ExtractNumberAny(split[1]) == "" {
					continue
				}
				checked++

				keys, hits := searchHits(t, ds, co.Number)
				if !slices.Contains(keys, uuid) {
					t.Errorf("%q does not reach %s", co.Number, co.Name)
				}
				for _, hit := range hits {
					if !strings.EqualFold(hit.Number, co.Number) {
						t.Errorf("%q reaches %s %s %s", co.Number, hit.SetCode, hit.Number, hit.Name)
					}
				}

				ordinal := split[0] + "-" + split[1]
				if setPrintsNumber(ds.backend, split[0], ordinal) {
					continue
				}
				keys, _ = searchHits(t, ds, ordinal)
				if !slices.Contains(keys, uuid) {
					t.Errorf("%q does not reach %s", ordinal, co.Name)
				}
			}
			t.Logf("%-14s %d printed numbers checked", game, checked)
		})
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}

// searchHits runs a query and returns the keys it reaches with their cards.
func searchHits(t *testing.T, ds *datastore, query string) ([]string, []*mtgmatcher.CardObject) {
	t.Helper()
	keys, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, query, nil, nil, nil))
	if err != nil {
		t.Errorf("%q: %v", query, err)
	}
	var hits []*mtgmatcher.CardObject
	for _, key := range keys {
		hit, err := ds.backend.GetUUID(key)
		if err == nil {
			hits = append(hits, hit)
		}
	}
	return keys, hits
}

// A number typed alone or after a name reaches what cn: does in every game,
// padded the way Pokemon pads it or not, unless a card is named by it:
// Yu-Gi-Oh's "7".
func TestBareNumberInEveryGame(t *testing.T) {
	// The cn: query each number reaches what, or "" for a name.
	examples := map[mtgmatcher.Game]map[string]string{
		"pokemon": {"017": "cn:17", "17": "cn:17", "#123": "cn:123", "charizard 4": "charizard cn:4"},
		"lorcana": {"204": "cn:204"},
		"yugioh":  {"7": ""},
	}
	var ran int
	for game, queries := range examples {
		path := os.Getenv(gameDatastores[game])
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s: %v", game, err)
			continue
		}
		loaded, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		ran++

		t.Run(string(game), func(t *testing.T) {
			ds := testSite.newDatastore(loaded, time.Now())
			checkBareNumbersAgreeWithSeed(t, ds)
			checkNumberedNamesStayNames(t, ds)
			for query, as := range queries {
				config := parseSearchQuery(ds, query, nil, nil, nil)
				if as == "" {
					if config.CleanQuery != query || len(config.CardFilters) != 0 {
						t.Errorf("%q is not read as a name: %+v", query, config.CardFilters)
					}
					continue
				}
				got, err := searchAndFilter(ds, config)
				if err != nil {
					t.Fatalf("%q: %v", query, err)
				}
				want, err := searchAndFilter(ds, parseSearchQuery(ds, as, nil, nil, nil))
				if err != nil || len(want) == 0 {
					t.Fatalf("%q reaches nothing: %v", as, err)
				}
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("%q reaches %d cards, %q reaches %d", query, len(got), as, len(want))
				}
			}
		})
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}
