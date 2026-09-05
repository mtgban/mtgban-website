package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A number can carry a slash - Flesh and Blood numbers a double-faced card
// WTR040//WTR039 - and it travels escaped. The path is split as written rather
// than as it decodes, so the slash stays inside the part it belongs to.
func TestCardRedirectReadsAnEscapedSlash(t *testing.T) {
	rec := httptest.NewRecorder()
	CardRedirect(rec, httptest.NewRequest(http.MethodGet,
		"/card/WTR/"+url.PathEscape("WTR040//WTR039")+"/1steditionnormal", nil))

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("q"); got != "s:WTR cns:WTR040//WTR039" {
		t.Errorf("asked %q, want the number whole", got)
	}
}

// The same against the datastore that numbers this way, where one is at hand.
// Loading a second datastore replaces the one TestMain loaded, so this runs
// only when asked for by name and puts the first one back after:
//
//	FLESHANDBLOOD_PATH=... go test -run SplitNumbersAgainstTheGameThatHasThem
func TestSplitNumbersAgainstTheGameThatHasThem(t *testing.T) {
	path := os.Getenv("FLESHANDBLOOD_PATH")
	if path == "" {
		t.Skip("set FLESHANDBLOOD_PATH to check this against the game that numbers this way")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Skip("opening the datastore:", err)
	}
	defer f.Close()
	if err := mtgmatcher.LoadDatastore(f); err != nil {
		t.Skip("loading the datastore:", err)
	}
	t.Cleanup(func() {
		restore, err := os.Open(Config.DatastorePath)
		if err != nil {
			return
		}
		defer restore.Close()
		mtgmatcher.LoadDatastore(restore)
	})

	var split int
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed || !strings.Contains(co.Number, "/") {
			continue
		}
		split++

		link := cardPath(co)
		if !strings.Contains(link, "%2F") {
			t.Fatalf("%s links as %q, want the slash escaped", co.Number, link)
		}

		rec := httptest.NewRecorder()
		CardRedirect(rec, httptest.NewRequest(http.MethodGet, link, nil))
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		query := loc.Query().Get("q")
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
			t.Errorf("%s asks %q and does not find %s #%s (%d results)",
				link, query, co.SetCode, co.Number, len(keys))
		}
	}

	if split == 0 {
		t.Skip("this datastore numbers nothing with a slash")
	}
	t.Logf("%d printings numbered with a slash, all found", split)
}
