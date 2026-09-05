package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A scryfall link reaches the same card here: swap the host, keep the path.
func TestCardRedirectFollowsScryfallsShape(t *testing.T) {
	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{"set and number", "/card/lea/1", "s:lea cns:1"},
		{"the name scryfall appends", "/card/otj/1/another-round", "s:otj cns:1"},
		{"anything else past it", "/card/10e/1%E2%98%85/ancestors-chosen/en", "s:10e cns:1★"},
		{"a trailing slash", "/card/sld/1/", "s:sld cns:1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			CardRedirect(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusFound {
				t.Fatalf("%s answered %d, want a redirect", tt.path, rec.Code)
			}
			got, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got.Path != "/search" {
				t.Errorf("landed on %q, want the search", got.Path)
			}
			if q := got.Query().Get("q"); q != tt.want {
				t.Errorf("asked %q, want %q", q, tt.want)
			}
		})
	}
}

// Every part is optional from the right, and a path that names less asks for
// more rather than for nothing.
func TestCardRedirectWidensAShortPath(t *testing.T) {
	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{"a set alone is the set", "/card/lea", "s:lea"},
		{"with a trailing slash", "/card/lea/", "s:lea"},
		{"nothing at all is the search", "/card/", ""},
		{"and so is a number with no set", "/card//1", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			CardRedirect(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusFound {
				t.Fatalf("%s answered %d, want a redirect", tt.path, rec.Code)
			}
			got, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got.Path != "/search" {
				t.Errorf("landed on %q, want the search", got.Path)
			}
			if q := got.Query().Get("q"); q != tt.want {
				t.Errorf("asked %q, want %q", q, tt.want)
			}
			// Nothing to ask for is no question at all, not an empty one.
			if tt.want == "" && got.RawQuery != "" {
				t.Errorf("landed on %q, want the bare search", got.RawQuery)
			}
		})
	}
}

// And a set alone reaches the set.
func TestCardRedirectSetAloneFindsTheSet(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	set, err := mtgmatcher.GetSet("LEA")
	if err != nil {
		t.Skip("this datastore has no LEA")
	}

	rec := httptest.NewRecorder()
	CardRedirect(rec, httptest.NewRequest(http.MethodGet, "/card/lea", nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := searchAndFilter(parseSearchOptionsNG(loc.Query().Get("q"), nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < len(set.Cards) {
		t.Errorf("the set came to %d results, want at least its %d cards", len(keys), len(set.Cards))
	}
	for _, key := range keys {
		co, err := mtgmatcher.GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if co.SetCode != "LEA" {
			t.Errorf("landed on a %s card, want only LEA", co.SetCode)
			break
		}
	}
}

// And the query it hands over is one the search resolves to that printing -
// every finish of it, which is the reason it is a search and not a lookup.
func TestCardRedirectLandsOnThePrinting(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	set, err := mtgmatcher.GetSet("LEA")
	if err != nil || len(set.Cards) == 0 {
		t.Skip("this datastore has no LEA")
	}
	card := set.Cards[0]

	rec := httptest.NewRecorder()
	CardRedirect(rec, httptest.NewRequest(http.MethodGet, "/card/lea/"+card.Number, nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	keys, err := searchAndFilter(parseSearchOptionsNG(loc.Query().Get("q"), nil, nil, nil))
	if err != nil {
		t.Fatalf("the query the redirect hands over does not run: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("%q found nothing, want %s", loc.Query().Get("q"), card.Name)
	}
	for _, key := range keys {
		co, err := mtgmatcher.GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if co.Name != card.Name {
			t.Errorf("landed on %s, want %s", co.Name, card.Name)
		}
	}
}

// The third part is a finish, and scryfall fills the same position with the
// card's name, so it counts only when it names one.
func TestCardRedirectTakesAFinishOrTheName(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	if _, err := mtgmatcher.GetSet("OTJ"); err != nil {
		t.Skip("this datastore has no OTJ")
	}

	for _, tt := range []struct{ path, want string }{
		{"/card/otj/1/foil", "s:otj cns:1 f:foil"},
		{"/card/otj/1/nonfoil", "s:otj cns:1 f:nonfoil"},
		// Scryfall's own link, whose third part is the card
		{"/card/otj/1/another-round", "s:otj cns:1"},
		// A finish this printing is not sold in is not one of its finishes
		{"/card/otj/1/etched", "s:otj cns:1"},
	} {
		rec := httptest.NewRecorder()
		CardRedirect(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		got, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if q := got.Query().Get("q"); q != tt.want {
			t.Errorf("%s asked %q, want %q", tt.path, q, tt.want)
		}
	}
}

// And the finish narrows the search to that one printing rather than to
// nothing, which is the only reason to pass it on.
func TestCardRedirectFinishNarrowsTheResults(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	if _, err := mtgmatcher.GetSet("OTJ"); err != nil {
		t.Skip("this datastore has no OTJ")
	}

	run := func(path string) []string {
		rec := httptest.NewRecorder()
		CardRedirect(rec, httptest.NewRequest(http.MethodGet, path, nil))
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		keys, err := searchAndFilter(parseSearchOptionsNG(loc.Query().Get("q"), nil, nil, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return keys
	}

	family := run("/card/otj/1")
	if len(family) < 2 {
		t.Fatalf("the whole printing came to %d results, want its finishes", len(family))
	}
	foil := run("/card/otj/1/foil")
	if len(foil) != 1 {
		t.Fatalf("asking for the foil came to %d results, want 1", len(foil))
	}
	co, err := mtgmatcher.GetUUID(foil[0])
	if err != nil {
		t.Fatal(err)
	}
	if !co.Foil {
		t.Errorf("asking for the foil landed on the %s printing", co.Finish)
	}
}

// The number is matched as printed: a star or a dagger is what tells two
// printings of one number apart, and cn: answered both.
func TestCardRedirectKeepsTheNumberAsPrinted(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	if _, err := mtgmatcher.GetSet("4ED"); err != nil {
		t.Skip("this datastore has no 4ED")
	}

	rec := httptest.NewRecorder()
	CardRedirect(rec, httptest.NewRequest(http.MethodGet, "/card/4ed/107†", nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := searchAndFilter(parseSearchOptionsNG(loc.Query().Get("q"), nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("the daggered number found nothing")
	}
	for _, key := range keys {
		co, err := mtgmatcher.GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if co.Number != "107†" {
			t.Errorf("landed on #%s (%s), want the daggered printing", co.Number, co.Name)
		}
	}
}

// A card whose name is a finish. The word is read as the finish either way,
// so scryfall's link for Foil, /card/uma/55/foil, lands on the foil printing
// of it: the position means one thing wherever it is read, and the card entire
// is the same link without the word.
func TestCardRedirectReadsAFinishOverAName(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	ids, err := mtgmatcher.SearchEquals("Foil")
	if err != nil || len(ids) == 0 {
		t.Skip("this datastore has no card named Foil")
	}
	co, err := mtgmatcher.GetUUID(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if !mtgmatcher.HasFoilPrinting(co.Name, co.SetCode) {
		t.Skip("the card named Foil has no foil printing here, so nothing collides")
	}

	ask := func(path string) (string, []string) {
		t.Helper()
		rec := httptest.NewRecorder()
		CardRedirect(rec, httptest.NewRequest(http.MethodGet, path, nil))
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		query := loc.Query().Get("q")
		keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		return query, keys
	}

	base := "/card/" + co.SetCode + "/" + co.Number
	query, keys := ask(base + "/foil")
	if !strings.Contains(query, "f:foil") {
		t.Errorf("asked %q, want the finish", query)
	}
	if len(keys) != 1 {
		t.Fatalf("%q came to %d results, want the one foil printing", query, len(keys))
	}
	card, err := mtgmatcher.GetUUID(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if card.Name != co.Name || !card.Foil {
		t.Errorf("landed on %s (foil=%v), want the foil of %s", card.Name, card.Foil, co.Name)
	}

	// The card entire is the same link without the word.
	query, keys = ask(base)
	if strings.Contains(query, "f:") {
		t.Errorf("asked %q, want no finish at all", query)
	}
	if len(keys) < 2 {
		t.Errorf("%q came to %d results, want every finish of the card", query, len(keys))
	}
}
