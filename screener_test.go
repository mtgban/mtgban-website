package main

import (
	"context"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

func sampleMovers() []screenerRow {
	return []screenerRow{
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "a", Current: 100, Prior: 50}}, // +100%
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "b", Current: 60, Prior: 50}},  // +20%
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "c", Current: 40, Prior: 80}},  // -50%
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "d", Current: 3, Prior: 1}},    // +200% but below $5 floor
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
	got := filterScreenerRows([]screenerRow{{MoverRow: timeseries.MoverRow{MtgjsonUUID: "a", Current: 60, Prior: 50}}}, screenerFilter{Move: "up", MinPct: 0})
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
	rows := []screenerRow{
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "a", Current: 100, Prior: 50}},
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "a", Current: 100, Prior: 50}},
	}
	got := filterScreenerRows(rows, screenerFilter{Move: "up", MinPct: 0})
	if len(got) != 1 {
		t.Errorf("expected dedup to 1 row, got %d", len(got))
	}
}

func TestFilterScreenerRowsKind(t *testing.T) {
	rows := []screenerRow{
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "single", Current: 100, Prior: 50}, Sealed: false},
		{MoverRow: timeseries.MoverRow{MtgjsonUUID: "box", Current: 100, Prior: 50}, Sealed: true},
	}
	singles := uuidSet(filterScreenerRows(rows, screenerFilter{Kind: "singles", Move: "up", MinPct: 0}))
	if !singles["single"] || singles["box"] {
		t.Errorf("singles should keep only the single, got %v", singles)
	}
	sealed := uuidSet(filterScreenerRows(rows, screenerFilter{Kind: "sealed", Move: "up", MinPct: 0}))
	if !sealed["box"] || sealed["single"] {
		t.Errorf("sealed should keep only the box, got %v", sealed)
	}
	both := uuidSet(filterScreenerRows(rows, screenerFilter{Kind: "both", Move: "up", MinPct: 0}))
	if !both["single"] || !both["box"] {
		t.Errorf("both should keep all, got %v", both)
	}
}

func TestScreenerEditionsAndFilter(t *testing.T) {
	results := []ScreenerResult{
		{UUID: "a", SetCode: "STX", Edition: "Strixhaven"},
		{UUID: "b", SetCode: "STX", Edition: "Strixhaven"},
		{UUID: "c", SetCode: "NEO", Edition: "Kamigawa"},
		{UUID: "d", SetCode: "", Edition: ""},
	}
	facets := screenerEditions(results)
	if len(facets) != 2 {
		t.Fatalf("expected 2 editions (blank skipped), got %d", len(facets))
	}
	if facets[0].Code != "STX" || facets[0].Count != 2 {
		t.Errorf("expected STX count 2 first, got %+v", facets[0])
	}
	if facets[1].Code != "NEO" || facets[1].Count != 1 {
		t.Errorf("expected NEO count 1 second, got %+v", facets[1])
	}

	if got := filterByEditions(results, nil); len(got) != 4 {
		t.Errorf("nil selection should keep all, got %d", len(got))
	}
	got := filterByEditions(results, map[string]bool{"NEO": true})
	if len(got) != 1 || got[0].SetCode != "NEO" {
		t.Errorf("expected only NEO row, got %v", got)
	}
}

func TestFilterScreenerRowsPriorFloor(t *testing.T) {
	// sampleMovers priors: a=50, b=50, c=80, d=1.
	got := uuidSet(filterScreenerRows(sampleMovers(), screenerFilter{Move: "either", MinPct: 0, MinPriorPrice: 70}))
	if !got["c"] {
		t.Errorf("c (was 80) should pass a was>=70 floor, got %v", got)
	}
	if got["a"] || got["b"] || got["d"] {
		t.Errorf("only c was >= 70, got %v", got)
	}

	// Floors combine with AND: no row has both now>=50 and was>=70.
	both := uuidSet(filterScreenerRows(sampleMovers(), screenerFilter{Move: "either", MinPct: 0, MinPrice: 50, MinPriorPrice: 70}))
	if len(both) != 0 {
		// a,b have prior 50 (<70); c has current 40 (<50). No row satisfies both.
		t.Errorf("no row satisfies now>=50 AND was>=70, got %v", both)
	}
}

func TestValidPageSize(t *testing.T) {
	for _, n := range []int{25, 50, 100} {
		if validPageSize(n) != n {
			t.Errorf("validPageSize(%d) should be %d", n, n)
		}
	}
	if validPageSize(0) != 25 || validPageSize(37) != 25 || validPageSize(1000) != 25 {
		t.Error("invalid sizes should fall back to 25")
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

func TestCachedMoversFiltersUnresolvable(t *testing.T) {
	prevFetch := screenerFetch
	prevClassify := screenerClassify
	t.Cleanup(func() {
		screenerFetch = prevFetch
		screenerClassify = prevClassify
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	})
	screenerCacheMu.Lock()
	screenerCache = map[string]screenerCacheEntry{}
	screenerCacheMu.Unlock()

	screenerFetch = func(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]timeseries.MoverRow, error) {
		return []timeseries.MoverRow{
			{MtgjsonUUID: "good1"}, {MtgjsonUUID: "bad"}, {MtgjsonUUID: "box"},
		}, nil
	}
	screenerClassify = func(uuid string) (screenerMeta, bool) {
		switch uuid {
		case "bad":
			return screenerMeta{}, false
		case "box":
			return screenerMeta{Sealed: true, SetCode: "BOX", Edition: "Box Set"}, true
		default:
			return screenerMeta{SetCode: "STX", Edition: "Strixhaven"}, true
		}
	}

	rows, err := cachedMovers(context.Background(), 2, 30, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 resolvable rows, got %d", len(rows))
	}
	for _, r := range rows {
		if r.MtgjsonUUID == "bad" {
			t.Errorf("unresolvable UUID not filtered: %s", r.MtgjsonUUID)
		}
		if r.MtgjsonUUID == "box" && !r.Sealed {
			t.Errorf("box should be flagged sealed")
		}
	}
}

func TestCachedMoversCachesAndEvicts(t *testing.T) {
	calls := map[string]int{}
	prevFetch := screenerFetch
	prevClassify := screenerClassify
	t.Cleanup(func() {
		screenerFetch = prevFetch
		screenerClassify = prevClassify
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	})
	screenerCacheMu.Lock()
	screenerCache = map[string]screenerCacheEntry{}
	screenerCacheMu.Unlock()

	screenerClassify = func(uuid string) (screenerMeta, bool) { return screenerMeta{}, true }
	screenerFetch = func(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]timeseries.MoverRow, error) {
		calls[screenerCacheKey(metric, window, minPrice, minPriorPrice)]++
		return []timeseries.MoverRow{{MtgjsonUUID: "x"}}, nil
	}

	// First call fetches, second is served from cache.
	if _, err := cachedMovers(context.Background(), 2, 30, 5, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedMovers(context.Background(), 2, 30, 5, 0); err != nil {
		t.Fatal(err)
	}
	if calls[screenerCacheKey(2, 30, 5, 0)] != 1 {
		t.Errorf("expected 1 fetch for (2,30,5,0), got %d", calls[screenerCacheKey(2, 30, 5, 0)])
	}

	// A different current floor is a distinct cache key.
	if _, err := cachedMovers(context.Background(), 2, 30, 10, 0); err != nil {
		t.Fatal(err)
	}
	if calls[screenerCacheKey(2, 30, 10, 0)] != 1 {
		t.Errorf("expected 1 fetch for (2,30,10,0), got %d", calls[screenerCacheKey(2, 30, 10, 0)])
	}

	// A different prior floor is also a distinct cache key.
	if _, err := cachedMovers(context.Background(), 2, 30, 5, 100); err != nil {
		t.Fatal(err)
	}
	if calls[screenerCacheKey(2, 30, 5, 100)] != 1 {
		t.Errorf("expected 1 fetch for (2,30,5,100), got %d", calls[screenerCacheKey(2, 30, 5, 100)])
	}

	// Fill past the cap with distinct keys; the map must stay bounded.
	for w := 0; w < screenerCacheMax+5; w++ {
		if _, err := cachedMovers(context.Background(), 99, w, 5, 0); err != nil {
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
