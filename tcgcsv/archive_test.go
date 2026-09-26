package tcgcsv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The withdrawal notice tcgcsv serves for every date under /archive/, trimmed.
const withdrawalNotice = "The price archive has been temporarily removed due to rising server costs and its growing moderation burden."

// A 403 is tcgcsv refusing the whole archive, not a gap on one date, and the
// reason is in the body. Callers branch on the sentinel to stop asking for more
// dates, and an operator needs the notice itself to know what happened.
func TestFetchPriceArchiveWithdrawn(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(withdrawalNotice))
	}))
	defer srv.Close()

	_, found, err := testClient(srv.URL).FetchPriceArchive(context.Background(), ArchiveEpoch, nil)
	if !errors.Is(err, ErrArchiveUnavailable) {
		t.Fatalf("err = %v, want ErrArchiveUnavailable", err)
	}
	if found {
		t.Error("found = true for a withdrawn archive")
	}
	if !strings.Contains(err.Error(), "rising server costs") {
		t.Errorf("error should carry the upstream notice, got %q", err)
	}
	// A 403 is not transient: retrying it three more times is three more refusals.
	if calls != 1 {
		t.Errorf("server was hit %d times, want 1", calls)
	}
}

// A date tcgcsv simply has no archive for is a day to skip, not a failure.
func TestFetchPriceArchiveMissingDay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	byCat, found, err := testClient(srv.URL).FetchPriceArchive(context.Background(),
		time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("FetchPriceArchive: %v", err)
	}
	if found || byCat != nil {
		t.Errorf("found=%v byCategory=%v, want false/nil", found, byCat)
	}
}

func TestCategoryFromArchivePath(t *testing.T) {
	for _, tc := range []struct {
		path string
		cat  int
		ok   bool
	}{
		{"2024-02-08/71/17690/prices", 71, true},
		{"2024-02-08/71/17690/products", 0, false},
		{"2024-02-08/71/prices", 0, false},
		{"2024-02-08/lorcana/17690/prices", 0, false},
	} {
		cat, ok := categoryFromArchivePath(tc.path)
		if cat != tc.cat || ok != tc.ok {
			t.Errorf("categoryFromArchivePath(%q) = %d, %v; want %d, %v", tc.path, cat, ok, tc.cat, tc.ok)
		}
	}
}
