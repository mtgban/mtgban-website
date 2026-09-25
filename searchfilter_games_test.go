package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// gameDatastores names each game by the variable its datastore path lives in.
// They are local builds, so a run without them skips rather than bundling a
// trimmed copy of any of them.
var gameDatastores = map[string]string{
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
	saved := backend()
	t.Cleanup(func() { matcherBackend.Store(saved) })

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
		datastore, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		matcherBackend.Store(datastore)
		ran++

		var tightened int
		for _, uuid := range backend().GetUUIDs() {
			co, err := backend().GetUUID(uuid)
			if err != nil || co.Sealed || co.SetCode == "" || co.Number == "" {
				continue
			}
			if mtgmatcher.ExtractNumberAny(co.Number) == "" ||
				!strings.ContainsFunc(co.Number, isNotDigit) {
				continue
			}
			if _, err := backend().GetSet(co.SetCode); err != nil {
				continue
			}
			tightened++

			query := co.SetCode + " " + co.Number
			keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
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
	}

	if ran == 0 {
		t.Skip("no non-Magic datastore paths in the environment")
	}
}
