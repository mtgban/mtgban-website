package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The rule itself, with no datastore behind it. The game that breaks it is not
// the game the suite loads, so the names live here as strings rather than as a
// datastore to go and find them in.
func TestNameReadsAsAName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"Black Lotus", true},
		{"Marlynn // Treasure Island", true},
		{"Official Judge Field Center Token: Dark Magician Girl", true},
		{"S:P Little Knight", false},
		{"Little Knight s:P", false},
		{"Official Judge Field Center Token: S:P Little Knight", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nameReadsAsAName(tc.name); got != tc.want {
				t.Errorf("nameReadsAsAName(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// And against the game that names a card this way: every printing whose name
// the filter syntax can read still has a link that reaches it.
//
// Before, the query opened with the name and the parser took s:P out of it,
// leaving a search for an edition no printing is in - not a wider answer but
// no answer at all. Checked by running the real query rather than by asking
// the predicate, which would pass either way.
//
// Loading a datastore replaces the one TestMain loaded, so this runs by name:
//
//	YUGIOH_PATH=... go test -run NameShapedLikeAFilterStillLinks
func TestNameShapedLikeAFilterStillLinks(t *testing.T) {
	saved := mtgmatcher.GlobalDatastore()
	t.Cleanup(func() { mtgmatcher.SetGlobalDatastore(saved) })

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
		backend, err := mtgmatcher.Open(game, f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", game, err)
			continue
		}
		mtgmatcher.SetGlobalDatastore(backend)

		for _, uuid := range mtgmatcher.GetUUIDs() {
			co, err := mtgmatcher.GetUUID(uuid)
			if err != nil || co.Sealed || co.Number == "" || nameReadsAsAName(co.Name) {
				continue
			}
			if _, err := mtgmatcher.GetSet(co.SetCode); err != nil {
				continue
			}
			checked++

			link := "/card/" + url.PathEscape(co.SetCode) + "/" + url.PathEscape(co.Number)
			rec := httptest.NewRecorder()
			CardRedirect(rec, httptest.NewRequest(http.MethodGet, link, nil))
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := loc.Query().Get("q")
			if strings.HasPrefix(query, co.Name) {
				t.Errorf("%s asks %q, want the name left off", link, query)
				continue
			}

			keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, key := range keys {
				if key == uuid {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s asks %q and does not find %s %s #%s (%d results)",
					link, query, co.Name, co.SetCode, co.Number, len(keys))
			}
		}
	}

	if checked == 0 {
		t.Skip("no datastore on hand names a card the filter syntax can read")
	}
	t.Logf("%d printings named like a filter, every link back to its own", checked)
}
