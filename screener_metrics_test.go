package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/timeseries"
)

func TestScreenerFacts(t *testing.T) {
	base := screenerFilter{Metric: int(timeseries.ProviderTCGLow), Window: 30, Kind: "singles", Move: "up", MinPrice: 5, MinPct: 20}
	wantFacts(t, screenerFacts(screenerRun{filter: base, landing: true, size: 25}), []fact{
		newFact("", "screener.provider", "TCGLow"), newFact("", "screener.window", "30"), newFact("", "screener.kind", "singles"),
		newFact("", "screener.move", "up"), newFact("", "screener.size", "25"), newFact("desc", "screener.sort", "pct"),
		newFact("", "screener.page", "1"),
	})

	// The landing's 5 and 20 ride every later form and link, so only another value is a choice.
	resent := base
	resent.MaxPct = -3
	wantFacts(t, screenerFacts(screenerRun{filter: resent, size: 50, index: 2, sorting: "current"}), []fact{
		newFact("", "screener.provider", "TCGLow"), newFact("", "screener.window", "30"), newFact("", "screener.kind", "singles"),
		newFact("", "screener.move", "up"), newFact("", "screener.size", "50"), newFact("desc", "screener.sort", "current"),
		newFact("", "screener.page", "2"),
	})

	set := base
	set.MinPrice, set.MinPriorPrice, set.MinPct, set.MaxPct, set.Metric = 2, 1, -10, 300, 9999
	wantFacts(t, screenerFacts(screenerRun{filter: set, editions: 2, size: 100, index: 7, sorting: "abs", dir: "asc"}), []fact{
		newFact("", "screener.window", "30"), newFact("", "screener.kind", "singles"), newFact("", "screener.move", "up"),
		newFact("", "screener.filter", "min_price"), newFact("", "screener.filter", "min_was"), newFact("", "screener.filter", "min_pct"),
		newFact("", "screener.filter", "max_pct"), newFact("", "screener.filter", "edition"),
		newFact("", "screener.size", "100"), newFact("asc", "screener.sort", "abs"),
		newFact("", "screener.page", "6+"),
	})

	// A landing URL counts no filter, and a sort the code lacks is not a value.
	odd := screenerFacts(screenerRun{filter: set, landing: true, editions: 1, size: 25, sorting: "name"})
	for _, f := range odd {
		if f.name == "screener.filter" || f.name == "screener.sort" {
			t.Errorf("unexpected fact %v", f)
		}
	}
}

func TestScreenerProviderName(t *testing.T) {
	if got := screenerProviderName(int(timeseries.ProviderTCGLow)); got != "TCGLow" {
		t.Errorf("TCGLow = %q", got)
	}
	if got := screenerProviderName(9999); got != "" {
		t.Errorf("an unseeded id = %q, want empty", got)
	}
}

// Every seeded provider, window and page size is a registry value.
func TestScreenerEnumsMatchTheCode(t *testing.T) {
	providers, _ := observability.Lookup("screener.provider")
	for _, p := range timeseries.Providers() {
		if !slices.Contains(providers.Enum, p.Shorthand) {
			t.Errorf("screener.provider lacks %q", p.Shorthand)
		}
	}
	windows, _ := observability.Lookup("screener.window")
	for _, w := range screenerWindows {
		if !slices.Contains(windows.Enum, strconv.Itoa(w.Days)) {
			t.Errorf("screener.window lacks %d", w.Days)
		}
	}
	sizes, _ := observability.Lookup("screener.size")
	for _, n := range screenerPageSizes {
		if !slices.Contains(sizes.Enum, strconv.Itoa(n)) {
			t.Errorf("screener.size lacks %d", n)
		}
	}
}

// With no archive the page refuses and counts nothing.
func TestScreenerRefusalIsNotCounted(t *testing.T) {
	if PricesArchiveDB != nil {
		t.Skip("an archive is configured")
	}
	withSigMode(t, true, false)
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodGet, "/screener?provider=1&min_price=2", nil)
	req.Header.Set("Sec-Fetch-Dest", "document")
	testSite.Screener(httptest.NewRecorder(), req)
	got := rows.rows()
	for _, row := range got {
		if strings.HasPrefix(row.Name, "screener.") {
			t.Errorf("unexpected row %+v", row)
		}
	}
}

// Facts count once where rows are served: not at a cold shell, not on a failed archive read.
func TestScreenerViewsAreCounted(t *testing.T) {
	prevFetch, prevClassify, prevDB := screenerFetch, screenerClassify, PricesArchiveDB
	clearCache := func() {
		screenerCacheMu.Lock()
		screenerCache = map[string]screenerCacheEntry{}
		screenerCacheMu.Unlock()
	}
	t.Cleanup(func() {
		screenerFetch, screenerClassify, PricesArchiveDB = prevFetch, prevClassify, prevDB
		clearCache()
	})
	withSigMode(t, true, false)
	PricesArchiveDB = &timeseries.Client{}
	clearCache()
	var fail bool
	screenerFetch = func(context.Context, int, int, float64, float64) ([]timeseries.MoverRow, error) {
		if fail {
			return nil, errors.New("archive down")
		}
		return []timeseries.MoverRow{{MtgjsonUUID: "fixture-uuid", Current: 10, Prior: 5}}, nil
	}
	screenerClassify = func(*matcher.Backend, string) (screenerMeta, bool) {
		return screenerMeta{SetCode: "STX", Edition: "Strixhaven"}, true
	}
	serve := func(t *testing.T, target, dest string) []observability.Row {
		rows := withFeatureCounter(t)
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Sec-Fetch-Dest", dest)
		testSite.Screener(httptest.NewRecorder(), req)
		return rows.rows()
	}

	noScreenerRows := func(t *testing.T, got []observability.Row) {
		t.Helper()
		for _, row := range got {
			if strings.HasPrefix(row.Name, "screener.") {
				t.Errorf("unexpected row %+v", row)
			}
		}
	}

	t.Run("failed read", func(t *testing.T) {
		fail = true
		defer func() { fail = false }()
		noScreenerRows(t, serve(t, "/screener?rows=1", "document"))
		noScreenerRows(t, serve(t, "/screener?rows=1", "empty"))
	})
	t.Run("shell", func(t *testing.T) {
		noScreenerRows(t, serve(t, "/screener", "document"))
	})
	t.Run("rows fetch", func(t *testing.T) {
		got := serve(t, "/screener?rows=1&index=3", "empty")
		wantRow(t, got, "", "screener.window", "30", 1)
		wantRow(t, got, "desc", "screener.sort", "pct", 1)
		wantRow(t, got, "", "screener.page", "1", 1)
		wantNoRow(t, got, "screener.filter")
	})
	t.Run("warm", func(t *testing.T) {
		// Fill the cache first, so the page serves rows whatever ran before.
		const query = "provider=1&min_price=5&min_pct=20&max_pct=50"
		prime := httptest.NewRequest(http.MethodGet, "/screener?rows=1&"+query, nil)
		testSite.Screener(httptest.NewRecorder(), prime)
		got := serve(t, "/screener?"+query+"&index=999", "document")
		wantRow(t, got, "", "screener.window", "30", 1)
		wantRow(t, got, "", "screener.page", "1", 1)
		wantRow(t, got, "", "screener.filter", "max_pct", 1)
		if n := len(find(got, "screener.filter")); n != 1 {
			t.Errorf("%d screener.filter rows, want 1", n)
		}
	})
}
