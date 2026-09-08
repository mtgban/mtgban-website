package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// The cases mirror tests/offline/autocomplete.test.js: the two matchers
// should fold a name the same way, or the search box and the browser's
// suggestion bar find different cards.
func TestFoldSuggestName(t *testing.T) {
	for _, tt := range []struct {
		name string
		want string
	}{
		{"Jace's Ire", "jaces ire"},
		{"Jötun Grunt", "jotun grunt"},
		{"Fire // Ice", "fire ice"},
		{"Ursula - Whisper of the Sea", "ursula whisper of the sea"},
		{"Lim-Dûl's Vault", "limduls vault"},
		{"Κλεοπάτρα", "κλεοπατρα"},
		{"_____", ""},
	} {
		got := foldSuggestName(tt.name)
		if got != tt.want {
			t.Errorf("fold(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSuggestPrefixMatchesFoldedNames(t *testing.T) {
	idx := &suggestIndex{singles: buildSuggestEntries([]string{
		"Ursula - Whisper of the Sea",
		"Jace's Ire",
		"Fire // Ice",
		"Lim-Dûl's Vault",
		"Lightning Bolt",
	})}

	for _, tt := range []struct {
		typed string
		want  string
	}{
		{"ursula whisper", "Ursula - Whisper of the Sea"},
		{"ursula - whisper", "Ursula - Whisper of the Sea"},
		{"jaces", "Jace's Ire"},
		{"fire ice", "Fire // Ice"},
		{"limduls", "Lim-Dûl's Vault"},
	} {
		matches := idx.prefixMatches(foldSuggestName(tt.typed), false)
		if len(matches) != 1 || matches[0].name != tt.want {
			t.Errorf("%q matched %v, want just %q", tt.typed, matches, tt.want)
		}
	}

	if matches := idx.prefixMatches(foldSuggestName("counterspell"), false); len(matches) != 0 {
		t.Errorf("counterspell matched %v, want nothing", matches)
	}
}

func TestSuggestPrefixMatchesCapsTheAnswer(t *testing.T) {
	names := make([]string, maxSuggestions+5)
	for i := range names {
		names[i] = fmt.Sprintf("Same Prefix %02d", i)
	}
	idx := &suggestIndex{singles: buildSuggestEntries(names)}
	matches := idx.prefixMatches(foldSuggestName("same prefix"), false)
	if len(matches) != maxSuggestions {
		t.Errorf("got %d matches, want the %d cap", len(matches), maxSuggestions)
	}
}

// End to end through the handler against the real datastore, the way the
// browser's search bar asks (opensearch.xml points q= here).
func TestSuggestAPIFoldsTheQuery(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}
	// The datastore load kicks the index build off as a goroutine; build it
	// here so the test doesn't race it.
	rebuildSuggestIndex()

	w := httptest.NewRecorder()
	SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?q=fire+ice", nil))
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
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}

	w := httptest.NewRecorder()
	SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?q=----", nil))
	if w.Code != 204 {
		t.Errorf("code = %d, want 204", w.Code)
	}
}
