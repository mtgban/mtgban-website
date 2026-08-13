package offlineapi

import (
	"compress/gzip"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/offline"
)

// TestServePricesCanonicalSetCode verifies that a lowercase set-code request
// is canonicalized via CanonicalSetCode before the manifest snapshot lookup
// and BuildSetPayload call, and that the served payload carries the manifest
// snapshot time rather than the current clock.
//
// GetSet requires the live mtgmatcher datastore which is unavailable in
// package tests, so canonicalization is injected via Deps.CanonicalSetCode.
func TestServePricesCanonicalSetCode(t *testing.T) {
	s, _ := newTestService(t)

	snapshotStr := "2024-01-15T10:00:00Z"
	snapshotTime, _ := time.Parse(time.RFC3339, snapshotStr)

	s.manifestStore.Set(manifestFile{
		Sets: map[string]setVersion{
			"NEO": {Fingerprint: "abc", Version: snapshotStr},
		},
	})
	t.Cleanup(func() { s.manifestStore.Set(manifestFile{}) })

	var gotCode string
	s.deps.CanonicalSetCode = func(code string) (string, error) {
		return "NEO", nil
	}
	s.deps.BuildSetPayload = func(setCode string, stores []string) (*offline.SetPayload, error) {
		gotCode = setCode
		return &offline.SetPayload{SetCode: setCode, Snapshot: time.Now()}, nil
	}
	s.deps.WatermarkSecret = func() []byte { return nil }
	s.deps.EnabledStores = func() []string { return nil }

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/offline/prices/neo.bin", nil)
	s.servePrices(w, r, "test@example.com", "neo.bin")

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotCode != "NEO" {
		t.Errorf("BuildSetPayload received setCode %q, want %q", gotCode, "NEO")
	}

	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := offline.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !payload.Snapshot.Equal(snapshotTime) {
		t.Errorf("Snapshot = %v, want %v", payload.Snapshot, snapshotTime)
	}
}
