package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func BenchmarkSuggestCommonPrefix(b *testing.B) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		b.Skip("mtgmatcher datastore not loaded")
	}
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
	req := httptest.NewRequest("GET", "/api/suggest?q=zzyzx", nil)
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		SuggestAPI(rec, req)
	}
}
