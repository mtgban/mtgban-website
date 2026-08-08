package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// suggestResponse invokes SuggestAPI for a query and decodes the OpenSearch
// response shape: [query, [names], [printings], [links]].
func suggestResponse(t *testing.T, query string, sealed bool) (int, []string) {
	t.Helper()
	url := "/api/suggest?q=" + query
	if sealed {
		url += "&sealed=true"
	}
	req := httptest.NewRequest("GET", url, nil)
	rec := httptest.NewRecorder()
	SuggestAPI(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var out []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("response too short: %s", rec.Body.String())
	}
	var names []string
	if err := json.Unmarshal(out[1], &names); err != nil {
		t.Fatalf("bad names: %v", err)
	}
	return rec.Code, names
}

func TestSuggestSingles(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}
	// loadDatastore builds the index in the background; build it here so the
	// test can't race that goroutine.
	rebuildSuggestIndex()

	// Every suggested name must actually start with the prefix (case
	// folded): a suggestion paired with the wrong display name betrays a
	// misaligned index.
	code, names := suggestResponse(t, "lightning+bo", false)
	if code != http.StatusOK || len(names) == 0 {
		t.Fatalf("no suggestions (code %d)", code)
	}
	var hasBolt bool
	for _, name := range names {
		if name == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(name), "lightning bo") {
			t.Errorf("suggestion %q does not match the typed prefix", name)
		}
		if name == "Lightning Bolt" {
			hasBolt = true
		}
	}
	if !hasBolt {
		t.Error("Lightning Bolt missing from lightning bo suggestions")
	}

	// Short prefixes don't suggest
	code, _ = suggestResponse(t, "li", false)
	if code != http.StatusNoContent {
		t.Errorf("short prefix code = %d, want 204", code)
	}
}

// The sealed autocomplete used to iterate the singles list while indexing
// the sealed one - wrong names at best, an index-out-of-range panic as soon
// as the singles list was longer.
func TestSuggestSealed(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}
	rebuildSuggestIndex()

	code, names := suggestResponse(t, "booster", true)
	if code != http.StatusOK {
		t.Fatalf("sealed suggestions code = %d", code)
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(name), "booster") {
			t.Errorf("sealed suggestion %q does not match the typed prefix", name)
		}
	}
}

func BenchmarkSuggestCommonPrefix(b *testing.B) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		b.Skip("mtgmatcher datastore not loaded")
	}
	rebuildSuggestIndex()
	req := httptest.NewRequest("GET", "/api/suggest?q=the", nil)
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		SuggestAPI(rec, req)
	}
}

func BenchmarkSuggestRarePrefix(b *testing.B) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		b.Skip("mtgmatcher datastore not loaded")
	}
	rebuildSuggestIndex()
	req := httptest.NewRequest("GET", "/api/suggest?q=zzyzx", nil)
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		SuggestAPI(rec, req)
	}
}
