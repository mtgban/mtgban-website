package main

import (
	"context"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

func sampleMovers() []timeseries.MoverRow {
	return []timeseries.MoverRow{
		{MtgjsonUUID: "a", Current: 100, Prior: 50},  // +100%
		{MtgjsonUUID: "b", Current: 60, Prior: 50},   // +20%
		{MtgjsonUUID: "c", Current: 40, Prior: 80},   // -50%
		{MtgjsonUUID: "d", Current: 3, Prior: 1},      // +200% but below $5 floor
	}
}

func uuidSet(rows []ScreenerResult) map[string]bool {
	m := map[string]bool{}
	for _, r := range rows {
		m[r.UUID] = true
	}
	return m
}

func TestFilterScreenerRowsUp(t *testing.T) {
	got := filterScreenerRows(sampleMovers(), screenerFilter{Move: "up", MinPrice: 5, MinPct: 20})
	set := uuidSet(got)
	if !set["a"] || !set["b"] {
		t.Errorf("expected a and b, got %v", set)
	}
	if set["c"] {
		t.Errorf("c is a drop, should be excluded for up")
	}
	if set["d"] {
		t.Errorf("d is below the $5 floor, should be excluded")
	}
}

func TestFilterScreenerRowsDown(t *testing.T) {
	got := filterScreenerRows(sampleMovers(), screenerFilter{Move: "down", MinPrice: 5, MinPct: 20})
	set := uuidSet(got)
	if !set["c"] {
		t.Errorf("expected c (a -50%% drop), got %v", set)
	}
	if set["a"] || set["b"] {
		t.Errorf("gainers should be excluded for down, got %v", set)
	}
}

func TestFilterScreenerRowsEitherAndMaxPct(t *testing.T) {
	got := filterScreenerRows(sampleMovers(), screenerFilter{Move: "either", MinPrice: 5, MinPct: 20, MaxPct: 80})
	set := uuidSet(got)
	// a is +100% which exceeds the 80%% sanity cap.
	if set["a"] {
		t.Errorf("a (+100%%) should be capped out by MaxPct=80, got %v", set)
	}
	if !set["b"] || !set["c"] {
		t.Errorf("expected b (+20%%) and c (-50%%), got %v", set)
	}
}

func TestFilterScreenerRowsComputesChange(t *testing.T) {
	got := filterScreenerRows([]timeseries.MoverRow{{MtgjsonUUID: "a", Current: 60, Prior: 50}}, screenerFilter{Move: "up", MinPct: 0})
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].AbsChange != 10 {
		t.Errorf("AbsChange = %v, want 10", got[0].AbsChange)
	}
	if got[0].PctChange < 0.1999 || got[0].PctChange > 0.2001 {
		t.Errorf("PctChange = %v, want ~0.20", got[0].PctChange)
	}
}

func TestFilterScreenerRowsDedup(t *testing.T) {
	// Same (uuid, foil, etched) twice (e.g. is_alt variants): keep one.
	rows := []timeseries.MoverRow{
		{MtgjsonUUID: "a", Current: 100, Prior: 50},
		{MtgjsonUUID: "a", Current: 100, Prior: 50},
	}
	got := filterScreenerRows(rows, screenerFilter{Move: "up", MinPct: 0})
	if len(got) != 1 {
		t.Errorf("expected dedup to 1 row, got %d", len(got))
	}
}

func TestSortScreenerRows(t *testing.T) {
	rows := []ScreenerResult{
		{UUID: "a", PctChange: 1.0},
		{UUID: "b", PctChange: 0.2},
		{UUID: "c", PctChange: 0.5},
	}
	sortScreenerRows(rows, "pct", "desc")
	if rows[0].UUID != "a" || rows[2].UUID != "b" {
		t.Errorf("desc sort wrong: %v %v %v", rows[0].UUID, rows[1].UUID, rows[2].UUID)
	}
	sortScreenerRows(rows, "pct", "asc")
	if rows[0].UUID != "b" || rows[2].UUID != "a" {
		t.Errorf("asc sort wrong: %v %v %v", rows[0].UUID, rows[1].UUID, rows[2].UUID)
	}
}

func TestScreenerResultFieldValue(t *testing.T) {
	r := ScreenerResult{Current: 12.5, Prior: 10, PctChange: 0.25, AbsChange: 2.5}
	if r.FieldValue("current") != "12.5" {
		t.Errorf("current = %q", r.FieldValue("current"))
	}
	if r.FieldValue("pct") != "0.25" {
		t.Errorf("pct = %q", r.FieldValue("pct"))
	}
	if r.FieldValue("bogus") != "" {
		t.Errorf("unknown field should be empty, got %q", r.FieldValue("bogus"))
	}
}

func TestValidMetricAndWindow(t *testing.T) {
	if !validMetric(2) {
		t.Error("metric 2 (TCG Low) should be valid")
	}
	if validMetric(99) {
		t.Error("metric 99 should be invalid")
	}
	if !validWindow(30) {
		t.Error("window 30 should be valid")
	}
	if validWindow(31) {
		t.Error("window 31 is not a preset, should be invalid")
	}
}

func TestBuildScreenerDisplaySkipsUnresolved(t *testing.T) {
	results := []ScreenerResult{
		{UUID: "good1"}, {UUID: "bad"}, {UUID: "good2"},
	}
	resolve := func(uuid string) GenericCard {
		if uuid == "bad" {
			return GenericCard{} // unresolved
		}
		return GenericCard{UUID: uuid, Name: "Card " + uuid}
	}
	got := buildScreenerDisplay(results, resolve)
	if len(got) != 2 {
		t.Fatalf("expected 2 displayable, got %d", len(got))
	}
	if got[0].Row.UUID != "good1" || got[1].Row.UUID != "good2" {
		t.Errorf("wrong rows kept: %v, %v", got[0].Row.UUID, got[1].Row.UUID)
	}
	if got[0].Card.Name != "Card good1" {
		t.Errorf("card not paired: %q", got[0].Card.Name)
	}
}

func TestCachedMoversCachesAndEvicts(t *testing.T) {
	calls := map[string]int{}
	prev := screenerFetch
	t.Cleanup(func() {
		screenerFetch = prev
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	})
	screenerCacheMu.Lock()
	screenerCache = map[string]screenerCacheEntry{}
	screenerCacheMu.Unlock()

	screenerFetch = func(ctx context.Context, metric, window int) ([]timeseries.MoverRow, error) {
		calls[screenerCacheKey(metric, window)]++
		return []timeseries.MoverRow{{MtgjsonUUID: "x"}}, nil
	}

	// First call fetches, second is served from cache.
	if _, err := cachedMovers(context.Background(), 2, 30); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedMovers(context.Background(), 2, 30); err != nil {
		t.Fatal(err)
	}
	if calls[screenerCacheKey(2, 30)] != 1 {
		t.Errorf("expected 1 fetch for (2,30), got %d", calls[screenerCacheKey(2, 30)])
	}

	// Fill past the cap with distinct keys; the map must stay bounded.
	for w := 0; w < screenerCacheMax+5; w++ {
		if _, err := cachedMovers(context.Background(), 99, w); err != nil {
			t.Fatal(err)
		}
	}
	screenerCacheMu.Lock()
	n := len(screenerCache)
	screenerCacheMu.Unlock()
	if n > screenerCacheMax {
		t.Errorf("cache size %d exceeds cap %d", n, screenerCacheMax)
	}
}
