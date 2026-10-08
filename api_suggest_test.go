package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
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

// sealed=all answers from both name lists: the full list carries a card
// and a product, and a typed prefix reaches a product.
func TestSuggestAPIAnswersFromBothLists(t *testing.T) {
	skipWithoutDatastore(t)

	w := httptest.NewRecorder()
	testSite.SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?all=true&sealed=all", nil))
	if w.Code != 200 {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var names []string
	if err := json.Unmarshal(w.Body.Bytes(), &names); err != nil {
		t.Fatalf("response is not a list: %v", err)
	}
	singleNames := backend().Names(mtgmatcher.NameFormCanonical, false)
	sealedNames := backend().Names(mtgmatcher.NameFormCanonical, true)
	shared := 0
	for _, name := range sealedNames {
		if slices.Contains(singleNames, name) {
			shared++
		}
	}
	singles, sealed := len(singleNames), len(sealedNames)
	if len(names) != singles+sealed-shared {
		t.Errorf("%d names, want %d cards + %d products - %d shared", len(names), singles, sealed, shared)
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Errorf("%q is listed twice", name)
			break
		}
		seen[name] = true
	}

	// Every sealed product's canonical name leads with its edition, so the
	// prefix has to name one; Revised is old enough to stay in the card
	// data for good.
	w = httptest.NewRecorder()
	testSite.SuggestAPI(w, httptest.NewRequest("GET", "/api/suggest?q=revised+edition&sealed=all", nil))
	if w.Code != 200 {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var out []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) < 2 {
		t.Fatalf("response carries no suggestions: %s", w.Body.String())
	}
	var suggestions []string
	if err := json.Unmarshal(out[1], &suggestions); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range suggestions {
		if co, err := backend().GetUUID(firstUUID(t, name)); err == nil && co.Sealed {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no product among the suggestions for 'revised edition': %v", suggestions)
	}
}

// firstUUID resolves a suggested name to one of its uuids, card or product.
func firstUUID(t *testing.T, name string) string {
	t.Helper()
	if uuids, err := backend().SearchSealedEquals(name); err == nil && len(uuids) > 0 {
		return uuids[0]
	}
	if uuids, err := backend().SearchEquals(name); err == nil && len(uuids) > 0 {
		return uuids[0]
	}
	return ""
}
