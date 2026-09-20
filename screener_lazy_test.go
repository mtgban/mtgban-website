package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

// The screener's rows are an archive read plus a resolve pass over tens of
// thousands of them. A cold page now paints without them and asks for them
// itself; a warm one still answers in one go.
func TestScreenerDefersTheColdBuild(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	uuid := backend().GetUUIDs()[0]

	prevFetch := screenerFetch
	prevClassify := screenerClassify
	prevDB := PricesArchiveDB
	prevDev, prevSig := DevMode, SigCheck
	t.Cleanup(func() {
		screenerFetch = prevFetch
		screenerClassify = prevClassify
		PricesArchiveDB = prevDB
		DevMode, SigCheck = prevDev, prevSig
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	})

	DevMode, SigCheck = true, false
	PricesArchiveDB = &timeseries.Client{}
	screenerCacheMu.Lock()
	screenerCache = map[string]screenerCacheEntry{}
	screenerCacheMu.Unlock()

	var fetches int
	screenerFetch = func(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]timeseries.MoverRow, error) {
		fetches++
		return []timeseries.MoverRow{{MtgjsonUUID: uuid, Current: 10, Prior: 5}}, nil
	}
	screenerClassify = func(string) (screenerMeta, bool) {
		return screenerMeta{SetCode: "STX", Edition: "Strixhaven"}, true
	}

	get := func(t *testing.T, url string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		Screener(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d", url, rec.Code)
		}
		return rec.Body.String()
	}

	// Cold: the shell, with an in-flow spinner and nothing built.
	shell := get(t, "/screener")
	if fetches != 0 {
		t.Errorf("the cold page built %d times before painting", fetches)
	}
	if strings.Contains(shell, "screener-loading-overlay active") {
		t.Error("the cold page blocks the in-flow loading message with the overlay")
	}
	if !strings.Contains(shell, "screener-loading-state") || !strings.Contains(shell, "Loading results, please wait") {
		t.Error("the cold page paints without saying it is still working")
	}
	if strings.Contains(shell, `id="screenerTable"`) {
		t.Error("the cold page carries a table it has no rows for")
	}
	if !strings.Contains(shell, "'rows', '1'") {
		t.Error("the cold page never asks for its rows")
	}

	// What the page asks for next: the same request, answered in full.
	rows := get(t, "/screener?rows=1")
	if fetches != 1 {
		t.Errorf("the row request built %d times, want 1", fetches)
	}
	if !strings.Contains(rows, `id="screenerPage"`) {
		t.Fatal("the reply carries no region for the page to swap in")
	}
	if !strings.Contains(rows, `id="screenerTable"`) {
		t.Error("the row request came back without a table")
	}
	if strings.Contains(rows, "screener-loading-overlay active") {
		t.Error("the reply still says it is working")
	}
	if strings.Contains(rows, "screener-loading-state") || strings.Contains(rows, "Loading results, please wait") {
		t.Error("the row response still carries the deferred loading cue")
	}

	// Warm: answered in one go, with no second round trip to wait for.
	warm := get(t, "/screener")
	if fetches != 1 {
		t.Errorf("a warm page rebuilt the rows (%d fetches)", fetches)
	}
	if !strings.Contains(warm, `id="screenerTable"`) {
		t.Error("a warm page defers rows it already holds")
	}
	if strings.Contains(warm, "'rows', '1'") {
		t.Error("a warm page asks for rows it already has")
	}
}
