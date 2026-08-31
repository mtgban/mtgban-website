package main

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
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
	prev := Config.TimeseriesConfig
	t.Cleanup(func() { Config.TimeseriesConfig = prev })
	Config.TimeseriesConfig = TimeseriesConfig{Datasets: []DatasetConfig{
		{Index: 2, PublicName: "TCGplayer Low"},
		{Index: 3, PublicName: "TCGplayer Market"},
	}}

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

// Non-Magic mover rows arrive keyed by TCGplayer product; they resolve to the
// serving game's uuid, with the sub-type naming which finish of that card the
// row is about.
func TestMoverCardIdResolvesTCGRows(t *testing.T) {
	// Magic rows pass through untouched
	uuid, isFoil, ok := moverCardID(timeseries.MoverRow{MtgjsonUUID: "abc", IsFoil: true}, nil)
	if !ok || uuid != "abc" || !isFoil {
		t.Errorf("magic row = %q/%v/%v, want abc/true/true", uuid, isFoil, ok)
	}

	// A row with no identity at all resolves to nothing
	if _, _, ok := moverCardID(timeseries.MoverRow{}, nil); ok {
		t.Error("identity-less row should not resolve")
	}

	// TCG-keyed rows resolve through the id map (needs the datastore)
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("datastore not loaded")
	}
	// A card that is sold in both finishes, so the two sub-types have two
	// printings to land on. One with no foil at all would prove nothing.
	var pid int
	var want, wantFoil string
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
		if err != nil || co.Foil || co.Etched || co.Sealed {
			continue
		}
		foil, hasFoil := co.FoilUUIDs[mtgmatcher.FinishFoil]
		if !hasFoil || foil == co.UUID {
			continue
		}
		pidStr, found := co.Identifiers["tcgplayerProductId"]
		if !found {
			continue
		}
		if n, err := strconv.Atoi(pidStr); err == nil {
			pid, want, wantFoil = n, co.UUID, foil
			break
		}
	}
	if pid == 0 {
		t.Skip("no card sold in both finishes with a tcgplayer product id")
	}

	uuid, isFoil, ok = moverCardID(timeseries.MoverRow{TCGProductID: pid, TCGSubType: "Normal"}, nil)
	if !ok || isFoil {
		t.Fatalf("tcg row did not resolve: %q/%v/%v", uuid, isFoil, ok)
	}
	if uuid != want {
		t.Errorf("resolved %q, want %q", uuid, want)
	}

	// A foil sub-type reaches a foil printing, and the finish comes from the
	// printing that was resolved rather than from the sub-type's name.
	foilUUID, isFoil, ok := moverCardID(timeseries.MoverRow{TCGProductID: pid, TCGSubType: "Foil"}, nil)
	if !ok {
		t.Fatal("foil sub-type did not resolve")
	}
	if !isFoil {
		t.Errorf("foil sub-type resolved %q as unfoiled", foilUUID)
	}
	if foilUUID != wantFoil {
		t.Errorf("foil sub-type resolved %q, want the foil printing %q", foilUUID, wantFoil)
	}
}

// Two foil sub-types on one product are two printings, not one. Reading the
// finish as "anything but Normal" collapsed them onto a single card, so a
// Lorcana screener showed one row where the archive holds two.
func TestMoverCardIdSeparatesFoilSubTypes(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("datastore not loaded")
	}

	// A card whose product is priced under more than one foil sub-type: its
	// extra finishes each need an id of their own.
	co := &mtgmatcher.CardObject{}
	subTypes := map[string]int64{"Normal": 1, "Cold Foil": 2, "Holofoil": 3}

	seen := map[string]string{}
	for _, subType := range []string{"Normal", "Cold Foil", "Holofoil"} {
		id := tcgFinishIDForSubType(co, subTypes, subType)
		if prev, dup := seen[id]; dup && id != "" {
			t.Errorf("sub-types %q and %q both resolve to %q", prev, subType, id)
		}
		seen[id] = subType
	}
}

// The archive is scoped per game via TCGplayer category, read from the
// catalog dump the game loads at startup. Only the default game may fall back
// to a category without one; every other game refuses to guess.
func TestGameTCGCategory(t *testing.T) {
	prevGame := Config.Game
	prevCatalog := tcgCatalogPtr.Load()
	t.Cleanup(func() {
		Config.Game = prevGame
		tcgCatalogPtr.Store(prevCatalog)
	})

	// A loaded catalog names the category, whatever the game is called.
	tcgCatalogPtr.Store(&tcgCatalogSnapshot{CategoryID: 71, CategoryName: "Lorcana TCG"})
	Config.Game = "lorcana"
	if got := gameTCGCategory(); got != 71 {
		t.Errorf("lorcana category = %d, want 71 (from the catalog)", got)
	}

	// Without one, only the default game has an answer.
	tcgCatalogPtr.Store(nil)
	Config.Game = DefaultGame
	if got := gameTCGCategory(); got != timeseries.CategoryMagic {
		t.Errorf("default game category = %d, want %d", got, timeseries.CategoryMagic)
	}

	Config.Game = "unknowngame"
	if got := gameTCGCategory(); got != -1 {
		t.Errorf("catalog-less non-default game = %d, want -1", got)
	}
}

// A cache miss costs an archive read plus a resolve pass over every row it
// returns, and the entry only lands at the end of it. Every request that
// arrives in that window used to start its own copy of the same work.
func TestCachedMoversCollapsesConcurrentBuilds(t *testing.T) {
	prevFetch, prevClassify := screenerFetch, screenerClassify
	t.Cleanup(func() {
		screenerFetch, screenerClassify = prevFetch, prevClassify
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	})
	screenerCacheMu.Lock()
	screenerCache = map[string]screenerCacheEntry{}
	screenerCacheMu.Unlock()

	var calls atomic.Int32
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	screenerFetch = func(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]timeseries.MoverRow, error) {
		calls.Add(1)
		select {
		case arrived <- struct{}{}:
		default:
		}
		// Hold the build open so the other callers are all asking at once,
		// which is the state this collapses.
		<-release
		return []timeseries.MoverRow{{MtgjsonUUID: "good", Current: 100, Prior: 50}}, nil
	}
	screenerClassify = func(uuid string) (screenerMeta, bool) {
		return screenerMeta{SetCode: "STX", Edition: "Strixhaven"}, true
	}

	const callers = 8
	var wg sync.WaitGroup
	rows := make([][]screenerRow, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rows[i], errs[i] = cachedMovers(context.Background(), 2, 30, 5, 0)
		}(i)
	}

	<-arrived
	// The first caller is inside the read; give the rest a moment to queue up
	// behind it. Arriving late is harmless - they find the filled cache - so a
	// slow scheduler costs the test its point, never a false failure.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("the archive was read %d times for one key, want 1", got)
	}
	for i := range callers {
		if errs[i] != nil {
			t.Errorf("caller %d: %v", i, errs[i])
			continue
		}
		if len(rows[i]) != 1 || rows[i][0].MtgjsonUUID != "good" {
			t.Errorf("caller %d got %+v, want the one built row", i, rows[i])
		}
	}
}
