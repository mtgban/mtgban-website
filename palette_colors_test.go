package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/mtgban-website/internal/palette"
)

// TestColorsEndpoint checks the colour list served for the loaded game:
// every name a c: query carries, colorless and multicolor last.
func TestColorsEndpoint(t *testing.T) {
	if len(backend().AllSets) == 0 {
		t.Skip("no datastore loaded; skipping colour endpoint test")
	}

	rec := httptest.NewRecorder()
	testSite.palette.Colors(rec, httptest.NewRequest(http.MethodGet, "/api/palette/colors.json", nil))
	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Fatal("the list was never built, so the endpoint served an empty answer")
	}

	var colors []palette.Color
	err := json.Unmarshal(rec.Body.Bytes(), &colors)
	if err != nil {
		t.Fatal(err)
	}
	if len(colors) < 2 {
		t.Fatalf("served %d colours", len(colors))
	}
	last := colors[len(colors)-2:]
	if last[0].Value != "colorless" || last[1].Value != "multicolor" {
		t.Errorf("the list ends %v, want colorless then multicolor", last)
	}
}
