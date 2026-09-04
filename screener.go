package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
	"golang.org/x/sync/singleflight"
)

type ScreenerMetric struct {
	Index int
	Name  string
}

func screenerMetricList() []ScreenerMetric {
	out := make([]ScreenerMetric, 0, len(Config.TimeseriesConfig.Datasets))
	for _, d := range Config.TimeseriesConfig.Datasets {
		out = append(out, ScreenerMetric{Index: d.Index, Name: d.PublicName})
	}
	return out
}

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
	for _, d := range Config.TimeseriesConfig.Datasets {
		if d.Index == index {
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

type ScreenerResult struct {
	UUID      string
	IsFoil    bool
	IsEtched  bool
	SetCode   string
	Edition   string
	Current   float64
	Prior     float64
	PctChange float64 // fraction: 0.20 == +20%
	AbsChange float64
}

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

type screenerFilter struct {
	Metric        int
	Window        int
	Kind          string  // singles | sealed | both
	Move          string  // up | down | either
	MinPrice      float64 // floor on current price
	MinPriorPrice float64 // floor on the prior ("was") price
	MinPct        float64 // whole percent, e.g. 20
	MaxPct        float64 // whole percent, 0 == off
}

func filterScreenerRows(rows []screenerRow, f screenerFilter) []ScreenerResult {
	type key struct {
		uuid   string
		foil   bool
		etched bool
	}
	seen := map[key]bool{}
	var out []ScreenerResult
	for _, row := range rows {
		switch f.Kind {
		case "sealed":
			if !row.Sealed {
				continue
			}
		case "singles":
			if row.Sealed {
				continue
			}
		}
		if row.Prior <= 0 || row.Current <= 0 {
			continue
		}
		if row.Current < f.MinPrice {
			continue
		}
		if row.Prior < f.MinPriorPrice {
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
			SetCode:   row.SetCode,
			Edition:   row.Edition,
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

type EditionFacet struct {
	Code  string
	Name  string
	Count int
}

func screenerEditions(results []ScreenerResult) []EditionFacet {
	counts := map[string]int{}
	names := map[string]string{}
	var order []string
	for _, r := range results {
		if r.SetCode == "" {
			continue
		}
		if _, ok := counts[r.SetCode]; !ok {
			order = append(order, r.SetCode)
			names[r.SetCode] = r.Edition
		}
		counts[r.SetCode]++
	}
	facets := make([]EditionFacet, 0, len(order))
	for _, code := range order {
		facets = append(facets, EditionFacet{Code: code, Name: names[code], Count: counts[code]})
	}
	sort.SliceStable(facets, func(i, j int) bool {
		if facets[i].Count != facets[j].Count {
			return facets[i].Count > facets[j].Count
		}
		return facets[i].Name < facets[j].Name
	})
	return facets
}

func filterByEditions(results []ScreenerResult, selected map[string]bool) []ScreenerResult {
	if len(selected) == 0 {
		return results
	}
	var out []ScreenerResult
	for _, r := range results {
		if selected[r.SetCode] {
			out = append(out, r)
		}
	}
	return out
}

var screenerPageSizes = []int{25, 50, 100}

func validPageSize(n int) int {
	for _, s := range screenerPageSizes {
		if s == n {
			return n
		}
	}
	return 25
}

type screenerRow struct {
	timeseries.MoverRow
	Sealed  bool
	SetCode string
	Edition string
}

type screenerCacheEntry struct {
	rows    []screenerRow
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

func screenerCacheKey(metric, window int, minPrice, minPriorPrice float64) string {
	return fmt.Sprintf("%d:%d:%.2f:%.2f", metric, window, minPrice, minPriorPrice)
}

// gameTCGCategory returns the TCGplayer category of the serving game, used to
// scope shared-archive reads to this site's rows. It comes from the catalog
// dump the game already loads at startup, which names its own category, so a
// new game site needs no case here - only its dump.
//
// The default game falls back to Magic when no catalog is loaded, since it
// predates the dumps and screens fine without one. Any other game without a
// catalog returns -1: its rows are indistinguishable from every other game's
// in the shared archive, and callers refuse to guess.
func gameTCGCategory() int {
	if id := GetTCGCategoryID(); id > 0 {
		return id
	}
	if Config.Game == DefaultGame {
		return timeseries.CategoryMagic
	}
	return -1
}

// overridable in tests
var screenerFetch = func(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]timeseries.MoverRow, error) {
	if Config.TimeseriesConfig.LongFormReads {
		provider, ok := providerForDatasetIndex(metric)
		if !ok {
			return nil, fmt.Errorf("screener: no provider configured for metric %d", metric)
		}
		category := gameTCGCategory()
		if category < 0 {
			return nil, fmt.Errorf("screener: no TCGplayer category known for game %q", Config.Game)
		}
		return PricesArchiveDB.GetMoversLong(ctx, provider, window, minPrice, minPriorPrice, category)
	}
	return PricesArchiveDB.GetMovers(ctx, metric, window, minPrice, minPriorPrice)
}

// moverCardID resolves a mover row to this game's uuid: Magic rows carry the
// mtgjson uuid already, non-Magic rows carry their TCGplayer product, resolved
// through the external id map with the sub-type picking the finish. subTypes is
// the row's product's sub-type map, gathered for the whole result set by
// moverSubTypes; nil resolves on the card object alone. Overridable in tests.
var moverCardID = func(row timeseries.MoverRow, subTypes map[string]int64) (string, bool, bool) {
	if row.MtgjsonUUID != "" {
		return row.MtgjsonUUID, row.IsFoil, true
	}
	if row.TCGProductID == 0 {
		return "", false, false
	}

	// One product covers every finish of a card, so the sub-type is where the
	// finish lives - and which sub-type names which finish varies by game.
	// Reading it as "anything but Normal is the foil" collapses a game with
	// more than one onto a single printing: Lorcana prices Cold Foil and
	// Holofoil, and both would land on the same card. tcgFinishIDForSubType
	// pairs them off the sub-types the product is actually priced under, the
	// same way the chart read path does.
	base, err := mtgmatcher.MatchID(strconv.Itoa(row.TCGProductID))
	if err != nil {
		return "", false, false
	}
	co, err := mtgmatcher.GetUUID(base)
	if err != nil {
		return "", false, false
	}

	uuid := tcgFinishIDForSubType(co, subTypes, row.TCGSubType)
	if uuid == "" {
		return "", false, false
	}

	// The finish belongs to the printing that was resolved, not to the name of
	// the sub-type that led there.
	isFoil := false
	if finished, ferr := mtgmatcher.GetUUID(uuid); ferr == nil {
		isFoil = finished.Foil || finished.Etched
	}
	return uuid, isFoil, true
}

type screenerMeta struct {
	Sealed  bool
	SetCode string
	Edition string
}

// Classification is static, so resolve once at cache build, not per request; overridable in tests.
var screenerClassify = func(uuid string) (screenerMeta, bool) {
	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		return screenerMeta{}, false
	}
	return screenerMeta{Sealed: co.Sealed, SetCode: co.SetCode, Edition: co.Edition}, true
}

// moverSubTypes gathers the sub-type maps the TCG-keyed rows in raw need, warm
// cache first and one batched query for the rest. Resolving row by row asked
// the table per miss, which is a round-trip each across a result set that runs
// to tens of thousands - fine for the single-card paths the lookup was written
// for, not for a whole screener page rebuilt on a cold cache.
func moverSubTypes(ctx context.Context, raw []timeseries.MoverRow) map[int]map[string]int64 {
	if PricesArchiveDB == nil {
		return nil
	}
	out := map[int]map[string]int64{}
	var missing []int
	for _, row := range raw {
		if row.MtgjsonUUID != "" || row.TCGProductID == 0 {
			continue
		}
		// A nil entry still counts as seen, so a product asked for once is not
		// asked for again.
		if _, seen := out[row.TCGProductID]; seen {
			continue
		}
		m, cached := PricesArchiveDB.CachedTCGSubTypeBanIDs(row.TCGProductID)
		out[row.TCGProductID] = m
		if !cached {
			missing = append(missing, row.TCGProductID)
		}
	}
	if len(missing) == 0 {
		return out
	}
	found, err := PricesArchiveDB.LookupTCGSubTypeBanIDsBatch(ctx, missing)
	if err != nil {
		log.Println("screener: batched sub-type lookup failed:", err)
		return out
	}
	for productID, m := range found {
		out[productID] = m
	}
	return out
}

// screenerFlight collapses concurrent builds of the same key. The window
// between a cache entry expiring and the next one landing is a whole archive
// read plus a resolve pass over tens of thousands of rows, and every request
// that arrived during it used to run its own copy.
var screenerFlight singleflight.Group

// cachedScreenerRows returns a live cache entry, if there is one.
func cachedScreenerRows(key string) ([]screenerRow, bool) {
	screenerCacheMu.Lock()
	defer screenerCacheMu.Unlock()
	e, ok := screenerCache[key]
	return e.rows, ok && time.Since(e.fetched) < screenerCacheTTL
}

func cachedMovers(ctx context.Context, metric, window int, minPrice, minPriorPrice float64) ([]screenerRow, error) {
	key := screenerCacheKey(metric, window, minPrice, minPriorPrice)

	if rows, live := cachedScreenerRows(key); live {
		return rows, nil
	}

	// The flight's own context is the one that started it, so a caller that
	// goes away takes the build with it only if it was the one doing it -
	// the others get its error and can ask again.
	built, err, _ := screenerFlight.Do(key, func() (any, error) {
		// A build that just finished while this one queued is a hit now.
		if rows, live := cachedScreenerRows(key); live {
			return rows, nil
		}
		return buildMovers(ctx, key, metric, window, minPrice, minPriorPrice)
	})
	if err != nil {
		return nil, err
	}
	rows, ok := built.([]screenerRow)
	if !ok {
		return nil, fmt.Errorf("screener flight built %T, not rows", built)
	}
	return rows, nil
}

// buildMovers reads a page of movers, resolves every row to this game's uuid,
// and caches the result under key.
func buildMovers(ctx context.Context, key string, metric, window int, minPrice, minPriorPrice float64) ([]screenerRow, error) {
	raw, err := screenerFetch(ctx, metric, window, minPrice, minPriorPrice)
	if err != nil {
		return nil, err
	}
	subTypes := moverSubTypes(ctx, raw)
	rows := make([]screenerRow, 0, len(raw))
	for _, row := range raw {
		// Resolve non-Magic rows to this game's uuid so the rest of the
		// pipeline (classification, dedup keys, links) is id-uniform
		uuid, isFoil, ok := moverCardID(row, subTypes[row.TCGProductID])
		if !ok {
			continue
		}
		row.MtgjsonUUID = uuid
		row.IsFoil = isFoil
		if meta, ok := screenerClassify(row.MtgjsonUUID); ok {
			rows = append(rows, screenerRow{MoverRow: row, Sealed: meta.Sealed, SetCode: meta.SetCode, Edition: meta.Edition})
		}
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

type ScreenerVars struct {
	Metrics       []ScreenerMetric
	Windows       []ScreenerWindow
	SelMetric     int
	SelWindow     int
	SelKind       string
	Move          string
	MinPrice      float64
	MinPriorPrice float64
	MinPct        float64
	MaxPct        float64
	Editions      []EditionFacet
	SelEditions   []string
	SelEditionSet map[string]bool
	PageSizes     []int
	SelSize       int
	Rows          []ScreenerResult

	// Deferred marks the shell rendered before the rows exist: the filters
	// paint, and the page asks for the rows itself.
	Deferred bool
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

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
	kind := r.FormValue("kind")
	if kind != "sealed" && kind != "both" {
		kind = "singles"
	}
	minPrice, _ := strconv.ParseFloat(r.FormValue("min_price"), 64)
	minWas, _ := strconv.ParseFloat(r.FormValue("min_was"), 64)
	minPct, _ := strconv.ParseFloat(r.FormValue("min_pct"), 64)
	maxPct, _ := strconv.ParseFloat(r.FormValue("max_pct"), 64)
	size := validPageSize(atoiDefault(r.FormValue("size"), 25))
	selEditions := r.Form["edition"]
	editionSet := map[string]bool{}
	for _, code := range selEditions {
		editionSet[code] = true
	}
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
		Metrics:       screenerMetricList(),
		Windows:       screenerWindows,
		SelMetric:     metric,
		SelWindow:     window,
		SelKind:       kind,
		Move:          move,
		MinPrice:      minPrice,
		MinPriorPrice: minWas,
		MinPct:        minPct,
		MaxPct:        maxPct,
		SelEditions:   selEditions,
		SelEditionSet: editionSet,
		PageSizes:     screenerPageSizes,
		SelSize:       size,
	}
	pageVars.Screener = sv

	// Building the rows is an archive read plus a resolve pass over tens of
	// thousands of them, and the page used to spend that wait as a blank tab.
	// Paint what the wait does not depend on, and let the page ask for the
	// rest itself - the request it makes carries rows=1 and is answered in
	// full. A warm cache renders here as it always did, since a round trip to
	// ask for what is already in hand is a round trip wasted.
	if r.FormValue("rows") != "1" {
		_, warm := cachedScreenerRows(screenerCacheKey(metric, window, minPrice, minWas))
		if !warm {
			sv.Deferred = true
			render(w, "screener.html", pageVars)
			return
		}
	}

	rows, err := cachedMovers(r.Context(), metric, window, minPrice, minWas)
	if err != nil {
		pageVars.InfoMessage = "Screener data is temporarily unavailable, please try again shortly"
		render(w, "screener.html", pageVars)
		return
	}

	results := filterScreenerRows(rows, screenerFilter{
		Metric: metric, Window: window, Kind: kind, Move: move,
		MinPrice: minPrice, MinPriorPrice: minWas, MinPct: minPct, MaxPct: maxPct,
	})

	// Facet the edition list before narrowing, then apply the edition filter.
	sv.Editions = screenerEditions(results)
	results = filterByEditions(results, editionSet)

	if sorting == "" {
		sorting = "pct"
		if dir == "" {
			dir = "desc"
		}
	}
	sortScreenerRows(results, sorting, dir)
	pageVars.SortOption = sorting
	pageVars.SortDir = dir

	// Cached rows are already resolvable, so resolve only the visible page.
	var paged []ScreenerResult
	paged, pageVars.Pagination = Paginate(results, pageIndex, size, len(results))
	sv.Rows = paged

	for _, res := range paged {
		// DB uuid is finish-agnostic; resolve the priced foil/etched variant.
		cardID, err := mtgmatcher.MatchID(res.UUID, res.IsFoil, res.IsEtched)
		if err != nil {
			cardID = res.UUID
		}
		c := uuid2card(cardID, true, false, preferFlavor)
		pageVars.Cards = append(pageVars.Cards, c)
		pageVars.CardHashes = append(pageVars.CardHashes, cardID)
	}

	if len(paged) == 0 {
		pageVars.InfoMessage = "No cards match the current filters"
	}

	render(w, "screener.html", pageVars)
}
