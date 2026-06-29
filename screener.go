package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// ScreenerMetric is a selectable price metric (dataset index plus label).
type ScreenerMetric struct {
	Index int
	Name  string
}

// screenerMetrics mirrors config.json timeseries_config.datasets. TCG Low first
// so it is the default landing metric.
var screenerMetrics = []ScreenerMetric{
	{2, "TCGplayer Low"},
	{3, "TCGplayer Market"},
	{0, "Card Kingdom Retail"},
	{1, "Card Kingdom Buylist"},
	{4, "Cardmarket Low"},
	{5, "Cardmarket Trend"},
	{6, "Star City Games Buylist"},
	{7, "ABU Games Buylist"},
	{9, "Cool Stuff Inc Buylist"},
	{8, "Sealed EV (TCG Low)"},
}

// ScreenerWindow is a selectable lookback in days.
type ScreenerWindow struct {
	Days  int
	Label string
}

var screenerWindows = []ScreenerWindow{
	{1, "1 day"},
	{7, "7 days"},
	{14, "14 days"},
	{30, "30 days"},
	{90, "90 days"},
}

func validMetric(index int) bool {
	for _, m := range screenerMetrics {
		if m.Index == index {
			return true
		}
	}
	return false
}

func validWindow(days int) bool {
	for _, w := range screenerWindows {
		if w.Days == days {
			return true
		}
	}
	return false
}

// ScreenerResult is one display row.
type ScreenerResult struct {
	UUID      string
	IsFoil    bool
	IsEtched  bool
	Current   float64
	Prior     float64
	PctChange float64 // fraction: 0.20 == +20%
	AbsChange float64
}

// FieldValue returns a field as a string for sorting and template rendering.
func (r ScreenerResult) FieldValue(name string) string {
	switch name {
	case "current":
		return strconv.FormatFloat(r.Current, 'f', -1, 64)
	case "prior":
		return strconv.FormatFloat(r.Prior, 'f', -1, 64)
	case "pct":
		return strconv.FormatFloat(r.PctChange, 'f', -1, 64)
	case "abs":
		return strconv.FormatFloat(r.AbsChange, 'f', -1, 64)
	default:
		return ""
	}
}

// screenerFilter holds the user-editable thresholds.
type screenerFilter struct {
	Metric   int
	Window   int
	Move     string  // up | down | either
	MinPrice float64 // dollar floor on current price
	MinPct   float64 // whole percent, e.g. 20
	MaxPct   float64 // optional sanity cap in whole percent, 0 == off
}

// filterScreenerRows computes change, applies the thresholds, and dedups by
// (uuid, foil, etched). Rows with a non-positive prior price are skipped.
func filterScreenerRows(rows []timeseries.MoverRow, f screenerFilter) []ScreenerResult {
	type key struct {
		uuid   string
		foil   bool
		etched bool
	}
	seen := map[key]bool{}
	var out []ScreenerResult
	for _, row := range rows {
		if row.Prior <= 0 || row.Current <= 0 {
			continue
		}
		if row.Current < f.MinPrice {
			continue
		}
		pct := (row.Current - row.Prior) / row.Prior
		pctWhole := pct * 100
		switch f.Move {
		case "down":
			if pctWhole > -f.MinPct {
				continue
			}
		case "either":
			if abs(pctWhole) < f.MinPct {
				continue
			}
		default: // up
			if pctWhole < f.MinPct {
				continue
			}
		}
		if f.MaxPct > 0 && abs(pctWhole) > f.MaxPct {
			continue
		}
		k := key{row.MtgjsonUUID, row.IsFoil, row.IsEtched}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ScreenerResult{
			UUID:      row.MtgjsonUUID,
			IsFoil:    row.IsFoil,
			IsEtched:  row.IsEtched,
			Current:   row.Current,
			Prior:     row.Prior,
			PctChange: pct,
			AbsChange: row.Current - row.Prior,
		})
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// sortScreenerRows sorts in place by a ScreenerResult field name and direction.
func sortScreenerRows(rows []ScreenerResult, field, dir string) {
	if field == "" {
		field = "pct"
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := strconv.ParseFloat(rows[i].FieldValue(field), 64)
		b, _ := strconv.ParseFloat(rows[j].FieldValue(field), 64)
		if dir == "asc" {
			return a < b
		}
		return a > b
	})
}

type screenerCacheEntry struct {
	rows    []timeseries.MoverRow
	fetched time.Time
}

const (
	screenerCacheTTL = 3 * time.Hour
	screenerCacheMax = 16
)

var (
	screenerCacheMu sync.Mutex
	screenerCache   = map[string]screenerCacheEntry{}
)

func screenerCacheKey(metric, window int) string {
	return fmt.Sprintf("%d:%d", metric, window)
}

// screenerFetch is the source of raw movers; overridable in tests.
var screenerFetch = func(ctx context.Context, metric, window int) ([]timeseries.MoverRow, error) {
	return PricesArchiveDB.GetMovers(ctx, metric, window)
}

// cachedMovers returns the raw change-list for a metric and window, fetching on
// a cache miss or stale entry and evicting the oldest entry past the cap.
func cachedMovers(ctx context.Context, metric, window int) ([]timeseries.MoverRow, error) {
	key := screenerCacheKey(metric, window)

	screenerCacheMu.Lock()
	e, ok := screenerCache[key]
	screenerCacheMu.Unlock()
	if ok && time.Since(e.fetched) < screenerCacheTTL {
		return e.rows, nil
	}

	rows, err := screenerFetch(ctx, metric, window)
	if err != nil {
		return nil, err
	}

	screenerCacheMu.Lock()
	if _, exists := screenerCache[key]; !exists && len(screenerCache) >= screenerCacheMax {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, v := range screenerCache {
			if first || v.fetched.Before(oldest) {
				oldestKey, oldest, first = k, v.fetched, false
			}
		}
		delete(screenerCache, oldestKey)
	}
	screenerCache[key] = screenerCacheEntry{rows: rows, fetched: time.Now()}
	screenerCacheMu.Unlock()

	return rows, nil
}

// ScreenerVars is the screener-specific template payload, hung off PageVars.
type ScreenerVars struct {
	Metrics   []ScreenerMetric
	Windows   []ScreenerWindow
	SelMetric int
	SelWindow int
	Move      string
	MinPrice  float64
	MinPct    float64
	MaxPct    float64
	Rows      []ScreenerResult
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// screenerDisplay pairs a result with its resolved card.
type screenerDisplay struct {
	Row  ScreenerResult
	Card GenericCard
}

// buildScreenerDisplay resolves each result to a card and drops rows that do
// not resolve, so blank rows never reach the page or pagination counts.
func buildScreenerDisplay(results []ScreenerResult, resolve func(uuid string) GenericCard) []screenerDisplay {
	var out []screenerDisplay
	for _, res := range results {
		c := resolve(res.UUID)
		if c.Name == "" {
			continue
		}
		out = append(out, screenerDisplay{Row: res, Card: c})
	}
	return out
}

// Screener serves the price-movers screener page.
func Screener(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Screener", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	pageVars.Title = "Price Movers Screener"

	if PricesArchiveDB == nil {
		pageVars.Title = "This feature is not enabled"
		pageVars.ErrorMessage = ErrMsgDenied
		render(w, "screener.html", pageVars)
		return
	}

	// Reuse the Newspaper access tier.
	enabled := GetParamFromSig(sig, "NewsEnabled")
	if !(enabled == "1day" || enabled == "3day" || enabled == "0day" || (DevMode && !SigCheck)) {
		pageVars.Title = "This feature is BANned"
		pageVars.ErrorMessage = ErrMsgDenied
		render(w, "screener.html", pageVars)
		return
	}

	r.ParseForm()
	metric := atoiDefault(r.FormValue("metric"), 2)
	window := atoiDefault(r.FormValue("window"), 30)
	if !validMetric(metric) {
		metric = 2
	}
	if !validWindow(window) {
		window = 30
	}
	move := r.FormValue("move")
	if move != "up" && move != "down" && move != "either" {
		move = "up"
	}
	minPrice, _ := strconv.ParseFloat(r.FormValue("min_price"), 64)
	minPct, _ := strconv.ParseFloat(r.FormValue("min_pct"), 64)
	maxPct, _ := strconv.ParseFloat(r.FormValue("max_pct"), 64)
	sorting := r.FormValue("sort")
	dir := r.FormValue("dir")
	pageIndex, _ := strconv.Atoi(r.FormValue("index"))

	// Fresh load with no filter params: apply the landing defaults.
	if r.FormValue("metric") == "" && r.FormValue("min_price") == "" && r.FormValue("min_pct") == "" {
		minPrice = 5
		minPct = 20
	}

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")

	sv := &ScreenerVars{
		Metrics:   screenerMetrics,
		Windows:   screenerWindows,
		SelMetric: metric,
		SelWindow: window,
		Move:      move,
		MinPrice:  minPrice,
		MinPct:    minPct,
		MaxPct:    maxPct,
	}
	pageVars.Screener = sv

	rows, err := cachedMovers(r.Context(), metric, window)
	if err != nil {
		pageVars.InfoMessage = "Screener data is temporarily unavailable, please try again shortly"
		render(w, "screener.html", pageVars)
		return
	}

	results := filterScreenerRows(rows, screenerFilter{
		Metric: metric, Window: window, Move: move,
		MinPrice: minPrice, MinPct: minPct, MaxPct: maxPct,
	})

	if sorting == "" {
		sorting = "pct"
		if dir == "" {
			dir = "desc"
		}
	}
	sortScreenerRows(results, sorting, dir)
	pageVars.SortOption = sorting
	pageVars.SortDir = dir

	display := buildScreenerDisplay(results, func(uuid string) GenericCard {
		return uuid2card(uuid, true, false, preferFlavor)
	})

	var paged []screenerDisplay
	paged, pageVars.Pagination = Paginate(display, pageIndex, DefaultPageSize, len(display))

	for _, d := range paged {
		sv.Rows = append(sv.Rows, d.Row)
		pageVars.Cards = append(pageVars.Cards, d.Card)
		pageVars.CardHashes = append(pageVars.CardHashes, d.Row.UUID)
	}

	if len(paged) == 0 {
		pageVars.InfoMessage = "No cards match the current filters"
	}

	render(w, "screener.html", pageVars)
}
