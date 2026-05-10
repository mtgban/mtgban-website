package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPaletteSealedNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/palette/sealed/Definitely%20Not%20A%20Real%20Product", nil)
	w := httptest.NewRecorder()
	PaletteSealed(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp PaletteSealedMetaResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp.Found {
		t.Fatalf("expected Found=false for nonexistent product")
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "max-age=300") {
		t.Errorf("missing 5-minute Cache-Control: %q", w.Header().Get("Cache-Control"))
	}
}
