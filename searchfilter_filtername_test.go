package main

import (
	"os"
	"sort"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// Which words are a set filter and which are a card's name, decided against
// the datastore the suite already has loaded.
func TestSetFilterNamesNothing(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	if _, err := backend().GetSet("LEA"); err != nil {
		t.Skip("this datastore has no LEA")
	}

	for _, tc := range []struct {
		field string
		want  bool
		why   string
	}{
		{"s:LEA", false, "a set that exists is a filter"},
		{"e:LEA", false, "under either spelling of the key"},
		{"edition:LEA", false, "or the long one"},
		{"s:LEA,ARN", false, "and a list of them"},
		{"s:LEA,NOPE", false, "one real code is enough to keep the filter"},
		{"s:P", true, "a set that does not exist is not a filter"},
		{"S:P", true, "whatever case it is written in"},
		{"-s:P", false, "a negated one still answers - it excludes nothing"},
		{"cns:LEA", false, "another key's value is not a set code"},
		{"f:foil", false, "nor is a finish"},
		{"r:mythic", false, "nor a rarity"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			if got := setFilterNamesNothing(tc.field); got != tc.want {
				t.Errorf("setFilterNamesNothing(%q) = %v, want %v", tc.field, got, tc.want)
			}
		})
	}

	// The parse asks it too: the words stay in the query rather than
	// becoming an edition filter no printing is in.
	config := parseSearchOptionsNG("S:P Little Knight", nil, nil, nil)
	for _, filter := range config.CardFilters {
		if filter.Name == "edition" {
			t.Errorf("S:P was read as an edition filter %v", filter.Values)
		}
	}
}

// A card whose name is filter syntax is reached by every route that names it.
//
// Yu-Gi-Oh names a card S:P Little Knight. The parser took its opening for
// s:P, an edition no printing is in, and lifted it out of the query - so the
// name a person typed found nothing, and so did the query the site writes for
// each result, which is that same name with the card's own filters after it.
//
// The queries are run rather than the predicate asked, because a check written
// against the predicate passes while the search is broken.
//
// Loading a datastore replaces the one TestMain loaded, so this runs by name:
//
//	YUGIOH_PATH=... go test -run NameThatIsFilterSyntaxIsStillFound
func TestNameThatIsFilterSyntaxIsStillFound(t *testing.T) {
	var games []string
	for game := range gameDatastores {
		games = append(games, game)
	}
	sort.Strings(games)

	var checked int
	for _, game := range games {
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

		t.Run(game, func(t *testing.T) {
			useDatastore(t, newDatastore(loaded, time.Now()))

			for _, uuid := range backend().GetUUIDs() {
				co, err := backend().GetUUID(uuid)
				if err != nil || co.Sealed || !re.MatchString(co.Name) {
					continue
				}
				checked++

				// The name alone, the way a person searches for it, and the
				// query the site writes to link this very printing.
				//
				// A printing with no number is left to the first of those: its
				// genQuery carries a bare "cns:" that no filter matches, so the
				// two characters stay in the query and spoil the name. That is
				// genQuery's own fault and predates this - 136 Yu-Gi-Oh
				// printings are numberless - and is not what this fixes.
				queries := []string{co.Name}
				if co.Number != "" {
					queries = append(queries, genQuery(co))
				}
				for _, query := range queries {
					keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
					if err != nil {
						t.Errorf("%q does not run: %v", query, err)
						continue
					}
					var found bool
					for _, key := range keys {
						if key == uuid {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("%q does not find %s, %s #%s (%d results)",
							query, uuid, co.SetCode, co.Number, len(keys))
					}
				}
			}
		})
	}

	if checked == 0 {
		t.Skip("no datastore on hand names a card the filter syntax can read")
	}
	t.Logf("%d printings named like a filter, every route to them answering", checked)
}
