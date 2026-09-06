package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// withSigMode runs one test under the given auth flags, restoring them after.
func withSigMode(t *testing.T, devMode, sigCheck bool) {
	t.Helper()
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = devMode, sigCheck
}

func TestRawCardAPIRefusesNonAdmins(t *testing.T) {
	withSigMode(t, false, true)

	w := httptest.NewRecorder()
	RawCardAPI(w, httptest.NewRequest("GET", "/api/mtgmatcher/raw/whatever", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRawCardAPIDumpsEveryField(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}
	withSigMode(t, true, false)

	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Fatal("datastore loaded but no uuids")
	}

	w := httptest.NewRecorder()
	RawCardAPI(w, httptest.NewRequest("GET", "/api/mtgmatcher/raw/"+uuids[0], nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	// The point of the endpoint: every field shows, the empty ones included
	// (watermark and faceName are empty on most printings), along with the
	// CardObject extras the plain card lacks.
	for _, key := range []string{"uuid", "name", "artist", "faceName", "watermark", "Edition", "Foil", "Etched", "Sealed"} {
		if _, found := decoded[key]; !found {
			t.Errorf("field %q missing from the dump", key)
		}
	}
}

func TestRawCardAPIUnknownId(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}
	withSigMode(t, true, false)

	w := httptest.NewRecorder()
	RawCardAPI(w, httptest.NewRequest("GET", "/api/mtgmatcher/raw/not-a-card-id", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want %d", w.Code, http.StatusNotFound)
	}
}
