package tcgcsv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// forbiddenNotice is the body tcgcsv served on 2026-09-24, trimmed of nothing:
// the reason and, in its second half, what to call instead. The length is the
// point of the test below, so it is reproduced rather than summarized.
const forbiddenNotice = `The price archive has been temporarily removed due to rising server costs and its growing moderation burden. Prices are still being archived behind-the-scenes. My goal is to share the price archive once I can get further clarification from TCGplayer, and standup a reliable way to cover my operating costs.

If you were previously relying on the price archive to pull daily pricing, please instead process categories, groups, and prices by making multiple requests. This will primarily help by reducing overall bandwidth. Separately, avoid requesting the same price file more than once in a 24 hour period.

I am very sorry for the inconvenience. There are no workarounds or ways to appeal this decision at this time.
-Toaster-`

// A 403 is the endpoint refusing, not a day that has no archive, so it comes
// back as ErrArchiveForbidden for a caller to stop on.
func TestFetchPriceArchiveForbidden(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(forbiddenNotice))
	}))
	defer srv.Close()

	day := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	_, found, err := testClient(srv.URL).FetchPriceArchive(context.Background(), day, nil)
	if !errors.Is(err, ErrArchiveForbidden) {
		t.Fatalf("err = %v, want ErrArchiveForbidden", err)
	}
	if found {
		t.Error("found should be false when the archive is refused")
	}

	// A 403 is not a transient failure, so it must not burn the retry budget.
	if n := hits.Load(); n != 1 {
		t.Errorf("server saw %d requests, want 1 (403 must not be retried)", n)
	}

	// The operator's note is the only place the reason and the alternative are
	// written down, and the actionable half is at the end. A 200-character
	// snippet would cut it, so the whole thing has to survive.
	if !strings.Contains(err.Error(), "process categories, groups, and prices") {
		t.Errorf("the note's actionable half was truncated away: %v", err)
	}
	if !strings.Contains(err.Error(), "-Toaster-") {
		t.Errorf("the note was cut before its end: %v", err)
	}
}

// A day tcgcsv simply has no archive for stays a skip, not an error, so a
// backfill walks past it.
func TestFetchPriceArchiveNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	day := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, found, err := testClient(srv.URL).FetchPriceArchive(context.Background(), day, nil)
	if err != nil {
		t.Fatalf("a missing day should not be an error: %v", err)
	}
	if found {
		t.Error("found should be false for a day with no archive")
	}
}

// Any other refusal keeps the old shape: an error, but not the sentinel, so a
// backfill counts it and carries on rather than abandoning the range.
func TestFetchPriceArchiveOtherStatusIsNotSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		w.Write([]byte("gone"))
	}))
	defer srv.Close()

	day := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	_, _, err := testClient(srv.URL).FetchPriceArchive(context.Background(), day, nil)
	if err == nil {
		t.Fatal("want an error for an unexpected status")
	}
	if errors.Is(err, ErrArchiveForbidden) {
		t.Errorf("410 should not read as the archive being withdrawn: %v", err)
	}
}

func TestSnippetLenCutsAndMarks(t *testing.T) {
	if got := snippetLen([]byte("  short  "), 100); got != "short" {
		t.Errorf("snippetLen trimmed = %q, want %q", got, "short")
	}
	if got := snippetLen([]byte("abcdef"), 3); got != "abc..." {
		t.Errorf("snippetLen cut = %q, want %q", got, "abc...")
	}
	// The default snippet stays where it was, so other errors read unchanged.
	if got := snippet([]byte(strings.Repeat("x", 250))); len(got) != 203 {
		t.Errorf("snippet len = %d, want 203 (200 + ellipsis)", len(got))
	}
}
