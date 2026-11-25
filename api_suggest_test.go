package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

// End to end through the handler against the real datastore, the way the
// browser's search bar asks (opensearch.xml points q= here).
func TestSuggestAPIFoldsTheQuery(t *testing.T) {
	skipWithoutDatastore(t)

	w := httptest.NewRecorder()
	testSite.SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?q=fire+ice", nil))
	if w.Code != 200 {
		t.Fatalf("code = %d, want 200", w.Code)
	}

	var out []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("response carries no suggestions: %s", w.Body.String())
	}
	var suggestions []string
	if err := json.Unmarshal(out[1], &suggestions); err != nil {
		t.Fatalf("suggestions are not a list: %v", err)
	}
	found := false
	for _, name := range suggestions {
		if name == "Fire // Ice" {
			found = true
		}
	}
	if !found {
		t.Errorf("%q not among the suggestions for 'fire ice': %v", "Fire // Ice", suggestions)
	}
}

// A query that folds to nothing must not match every name as an empty
// prefix.
func TestSuggestAPIRefusesAnEmptyFold(t *testing.T) {
	skipWithoutDatastore(t)

	w := httptest.NewRecorder()
	testSite.SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?q=----", nil))
	if w.Code != 204 {
		t.Errorf("code = %d, want 204", w.Code)
	}
}

// The OpenSearch descriptor names the host the browser fetched it from, so
// each game's search bar entry searches that game; a host that is not ours
// gets the public default rather than a made-up one.
func TestOpenSearchDescribesTheRequestsHost(t *testing.T) {
	for _, tc := range []struct {
		host, want string
	}{
		{"mtg.ban.cards", "https://mtg.ban.cards"},
		{"lorcana.ban.cards", "https://lorcana.ban.cards"},
		{"www.mtgban.com", "https://www.mtgban.com"},
		{"attacker.example", DefaultExternalURL},
	} {
		req := httptest.NewRequest("GET", "/api/opensearch.xml", nil)
		req.Host = tc.host
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		OpenSearchDesc(w, req)
		body := w.Body.String()
		for _, path := range []string{"/search?q={searchTerms}", "/api/opensearch.xml", "/api/suggest?q={searchTerms}", "/img/favicon/favicon.ico"} {
			if !strings.Contains(body, tc.want+path) {
				t.Errorf("%s: descriptor lacks %s%s:\n%s", tc.host, tc.want, path, body)
			}
		}
		if strings.Contains(body, "mtgban.com") && strings.HasSuffix(tc.host, ".ban.cards") {
			t.Errorf("%s: descriptor names mtgban.com", tc.host)
		}
	}

	// Another game's deployment, reached at a host that is not ours, names
	// its own search rather than Magic's
	withConfigCopy(t)
	Config().Game = "lorcana"
	req := httptest.NewRequest("GET", "/api/opensearch.xml", nil)
	req.Host = "attacker.example"
	w := httptest.NewRecorder()
	OpenSearchDesc(w, req)
	if body := w.Body.String(); !strings.Contains(body, "https://lorcana.mtgban.com/search?q={searchTerms}") || !strings.Contains(body, "Lorcana prices") {
		t.Errorf("a Lorcana deployment on an untrusted host describes:\n%s", body)
	}
}

// Every single name is served, the token pairs after the cards, and the rows
// the search box draws for "goblin" are cards.
func TestSuggestAPIListsTokenPairsLast(t *testing.T) {
	skipWithoutDatastore(t)
	w := httptest.NewRecorder()
	testSite.SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?all=true", nil))
	var names []string
	err := json.Unmarshal(w.Body.Bytes(), &names)
	if err != nil {
		t.Fatal(err)
	}
	cards, pairs := suggest.SplitPairs(backend())
	if len(pairs) == 0 || !slices.Equal(names, slices.Concat(cards, pairs)) {
		t.Errorf("served %d names, want %d cards and then %d pairs", len(names), len(cards), len(pairs))
	}
	all := backend().Names(matcher.NameFormCanonical, false)
	if len(names) != len(all) {
		t.Errorf("served %d names, want the datastore's %d", len(names), len(all))
	}
	for _, name := range testSite.datastore().names.Matches("goblin", false) {
		if slices.Contains(pairs, name) {
			t.Errorf("goblin offers %q before its cards run out", name)
		}
	}
}
