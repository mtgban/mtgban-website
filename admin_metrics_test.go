package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/metricsreport"
	"github.com/mtgban/mtgban-website/observability"
)

var (
	loaderTestNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	loaderTestDay = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
)

// fakeMetricsStore records each call and returns its fields, or err.
type fakeMetricsStore struct {
	mu sync.Mutex

	totals       []observability.DayTotal               // every other DayTotals query
	totalsTo     map[time.Time][]observability.DayTotal // unsplit Step 30 queries ending on that day, before totals
	byTier       []observability.DayTotal               // ByTier queries
	byDevice     []observability.DayTotal               // ByDevice queries
	named        []observability.DayTotal               // Step 1 queries naming their names
	client       []observability.DayTotal               // one-period queries naming their names
	hours        []observability.HourTotal
	week         []observability.DayTotal // Step 7 queries
	stock        []observability.DayTotal // queries under SharedInstance
	stockLast    []observability.DayTotal // the stale stored-state look-back under SharedInstance
	visits       []observability.PageVisit
	instances    []string
	reviews      []observability.Review
	health       []observability.InstanceHealth
	jobs         []observability.JobRun
	through      time.Time
	folded       bool
	err          error // every method
	totalsErr    error // DayTotals only
	reviewErr    error // Reviews only
	throughErr   error // FoldedThrough only
	healthErr    error // CounterHealth only
	hoursErr     error // HourTotals only
	visitsErr    error // PageVisits only
	tiersErr     error // ByTier DayTotals only
	stockLastErr error // the stale stored-state look-back only

	queries      []observability.DayQuery
	visitCalls   [][2]time.Time
	hourCalls    []hourCall
	reviewCalls  int
	healthCalls  int
	throughCalls int
	saved        []observability.Review
	deleted      []string
}

func newFakeMetrics() *fakeMetricsStore {
	return &fakeMetricsStore{through: loaderTestDay, folded: true, instances: []string{"lorcana", "magic"}}
}

func (f *fakeMetricsStore) DayTotals(_ context.Context, q observability.DayQuery) ([]observability.DayTotal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return nil, f.err
	}
	if f.totalsErr != nil {
		return nil, f.totalsErr
	}
	switch {
	case q.Instance == observability.SharedInstance && q.Step == 0 && q.Days == metricsStockLookBack:
		return f.stockLast, f.stockLastErr
	case q.Instance == observability.SharedInstance:
		return f.stock, nil
	case q.ByTier && f.tiersErr != nil:
		return nil, f.tiersErr
	case q.ByTier:
		return f.byTier, nil
	case q.ByDevice:
		return f.byDevice, nil
	case q.Step == 7:
		return f.week, nil
	case q.Names != nil && q.Step == 1:
		return f.named, nil
	case q.Names != nil:
		return f.client, nil
	}
	if rows, ok := f.totalsTo[q.To]; ok && q.Step == 30 {
		return rows, nil
	}
	return f.totals, nil
}

// hourCall is one HourTotals call.
type hourCall struct {
	q     observability.DayQuery
	since time.Time
}

func (f *fakeMetricsStore) HourTotals(_ context.Context, q observability.DayQuery, since time.Time) ([]observability.HourTotal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hourCalls = append(f.hourCalls, hourCall{q, since})
	if f.hoursErr != nil {
		return nil, f.hoursErr
	}
	return f.hours, f.err
}

func (f *fakeMetricsStore) PageVisits(_ context.Context, _ string, from, until time.Time) ([]observability.PageVisit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visitCalls = append(f.visitCalls, [2]time.Time{from, until})
	if f.visitsErr != nil {
		return nil, f.visitsErr
	}
	return f.visits, f.err
}

func (f *fakeMetricsStore) Instances(context.Context, time.Time) ([]string, error) {
	return f.instances, f.err
}

func (f *fakeMetricsStore) FoldStamp(context.Context) (string, error) {
	return "stamp", f.err
}

func (f *fakeMetricsStore) FoldedThrough(context.Context, time.Time) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.throughCalls++
	if f.throughErr != nil {
		return time.Time{}, false, f.throughErr
	}
	return f.through, f.folded, f.err
}

func (f *fakeMetricsStore) CounterHealth(context.Context, time.Time) ([]observability.InstanceHealth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthCalls++
	if f.healthErr != nil {
		return nil, f.healthErr
	}
	return f.health, f.err
}

func (f *fakeMetricsStore) JobRuns(context.Context) ([]observability.JobRun, error) {
	return f.jobs, f.err
}

func (f *fakeMetricsStore) Reviews(context.Context, string) ([]observability.Review, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reviewCalls++
	if f.reviewErr != nil {
		return nil, f.reviewErr
	}
	return f.reviews, f.err
}

func (f *fakeMetricsStore) SetReview(ctx context.Context, r observability.Review) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, r)
	return f.err
}

func (f *fakeMetricsStore) DeleteReview(ctx context.Context, instance, name, scope, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, strings.Join([]string{instance, name, scope, value}, "|"))
	return f.err
}

// dayTotalCount is how many DayTotals calls the fake has seen.
func (f *fakeMetricsStore) dayTotalCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

// testClock is a clock a test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func withMetricsInstance(t *testing.T, inst string) {
	t.Helper()
	saved := observabilityInstance
	observabilityInstance = inst
	t.Cleanup(func() { observabilityInstance = saved })
}

// resetMetricsCache gives the test an empty process cache and restores the old one after.
func resetMetricsCache(t *testing.T) {
	t.Helper()
	metricsReportCache.mu.Lock()
	savedStore, savedCache := metricsReportCache.store, metricsReportCache.cache
	metricsReportCache.store, metricsReportCache.cache = nil, nil
	metricsReportCache.mu.Unlock()
	t.Cleanup(func() {
		metricsReportCache.mu.Lock()
		metricsReportCache.store, metricsReportCache.cache = savedStore, savedCache
		metricsReportCache.mu.Unlock()
	})
}

var metricsTestLists = metricsreport.Lists{Pages: []string{"alerts", "search", "sets"}}

// metricsTestRegistry is a small registry for the builders.
func metricsTestRegistry() []observability.Name {
	return []observability.Name{
		{Name: "metrics.flush", Report: observability.ReportInternal},
		{Name: "page.view", Values: observability.ValuePage, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "page", Area: "site", Help: "Page views, by page."},
		{Name: "search.sort", Area: "search", Values: observability.ValueEnum, Enum: []string{"alpha", "price"}, Report: observability.ReportCandidate, Kind: "option", Page: "*", Help: "Order the results were sorted in."},
		{Name: "search.filter", Area: "search", Values: observability.ValueEnum, Enum: []string{"t"}, Report: observability.ReportCandidate, Kind: "operator", Page: "*", Help: "An operator the reader typed."},
		{Name: "arbit.toggle", Area: "arbit", Values: observability.ValueEnum, Enum: []string{"legit"}, Report: observability.ReportCandidate, Kind: "setting", Page: "*", Help: "Counted when turned away from its default."},
		{Name: "auth.refuse", Area: "account", Values: observability.ValueEnum, Enum: []string{"no_access"}, Scope: observability.ScopeRoute, Report: observability.ReportSignal, Help: "Requests refused at the door."},
		{Name: "job.run", Values: observability.ValueEnum, Enum: []string{"ok", "fail"}, Scope: observability.ScopeEnum, Scopes: []string{"fold", "stock", "events_rollup"}, Report: observability.ReportInternal},
		{Name: "stock.rows", Family: observability.FamilyStock, Scope: observability.ScopeEnum, Scopes: []string{"magic", "lorcana"}, Report: observability.ReportContext, Help: "Rows stored, by game."},
	}
}

// fullRows is one row of name and value in each of periods Step-30 periods, each fully counted.
func fullRows(name, scope, value string, n int64, periods int) []observability.DayTotal {
	var out []observability.DayTotal
	for p := range periods {
		last := loaderTestDay.AddDate(0, 0, -30*p)
		out = append(out, observability.DayTotal{Period: p, Name: name, Scope: scope, Value: value, N: n, Days: 30, First: last.AddDate(0, 0, -29), Last: last})
	}
	return out
}

func loadTestView(t *testing.T, store metricsStore, cache *metricsreport.Cache, names []observability.Name, p metricsParams) *MetricsView {
	t.Helper()
	return loadMetricsViewFor(context.Background(), store, cache, names, metricsTestLists, p, loaderTestNow)
}

func testCache(store metricsStore) *metricsreport.Cache {
	return metricsreport.NewCache(store.FoldStamp, func() time.Time { return loaderTestNow })
}

func TestReadMetricsParams(t *testing.T) {
	withMetricsInstance(t, "magic")
	instances := []string{"magic", "lorcana"}

	get := func(v url.Values) func(string) string { return v.Get }
	def := readMetricsParams(get(url.Values{}), instances)
	if def.View != "overview" || def.Instance != "magic" || def.Days != 90 || def.Anon || def.Bots || def.Hourly || def.Name != "" || def.Area != "" {
		t.Errorf("defaults = %+v", def)
	}
	if w := def.window(); !w.Signed || !w.Humans || w.Days != 90 {
		t.Errorf("default window = %+v", w)
	}
	good := readMetricsParams(get(url.Values{"view": {"invest"}, "instance": {"lorcana"}, "days": {"180"}, "anon": {"1"}, "bots": {"1"}, "hourly": {"1"}, "name": {"http.status"}, "area": {"search"}}), instances)
	if good.View != "invest" || good.Instance != "lorcana" || good.Days != 180 || !good.Anon || !good.Bots || !good.Hourly || good.Name != "http.status" || good.Area != "search" {
		t.Errorf("good = %+v", good)
	}
	if w := good.window(); w.Signed || w.Humans || w.Days != 180 {
		t.Errorf("toggled window = %+v", w)
	}
	bad := readMetricsParams(get(url.Values{"view": {"../x"}, "instance": {"shared"}, "days": {"45"}, "anon": {"yes"}, "name": {"x'; DROP"}, "area": {"nope"}}), instances)
	if bad.View != "overview" || bad.Instance != "magic" || bad.Days != 90 || bad.Anon || bad.Name != "" || bad.Area != "" {
		t.Errorf("bad input got through: %+v", bad)
	}
	if other := readMetricsParams(get(url.Values{"instance": {"pokemon"}}), instances); other.Instance != "magic" {
		t.Errorf("an instance with no rows was accepted: %q", other.Instance)
	}
}

// Nothing a request crafts reaches the params unlisted.
func TestReadMetricsParamsRefusesCraftedValues(t *testing.T) {
	withMetricsInstance(t, "magic")
	instances := []string{"magic", "lorcana", "shared", ""}
	long := strings.Repeat("a", 10000)
	for _, c := range []struct {
		name string
		v    url.Values
	}{
		{"long", url.Values{"view": {long}, "instance": {long}, "days": {long}, "name": {long}, "area": {long}}},
		{"sql", url.Values{"view": {"overview' OR 1=1 --"}, "instance": {"magic'; DROP TABLE feature_days; --"}, "days": {"90; DELETE"}, "name": {"page.view' --"}, "area": {"site' --"}}},
		{"shared offered by the list", url.Values{"instance": {"shared"}}},
		{"blank instance", url.Values{"instance": {""}}},
		{"another real site", url.Values{"instance": {"pokemon"}}},
		{"a view that does not exist", url.Values{"view": {"trends"}}},
		{"a negative window", url.Values{"days": {"-90"}}},
		{"a window not offered", url.Values{"days": {"400"}}},
		{"a toggle spelled out", url.Values{"anon": {"true"}, "bots": {"on"}, "hourly": {"yes"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := readMetricsParams(c.v.Get, instances)
			if p.View != "overview" || p.Instance != "magic" || p.Days != 90 || p.Anon || p.Bots || p.Hourly || p.Name != "" || p.Area != "" {
				t.Errorf("got %+v", p)
			}
		})
	}
	// A repeated parameter is read once, its first value.
	repeated := readMetricsParams(url.Values{"view": {"remove", "invest"}, "instance": {"pokemon", "lorcana"}}.Get, instances)
	if repeated.View != "remove" || repeated.Instance != "magic" {
		t.Errorf("repeated = %+v", repeated)
	}
}

func TestMetricsLinkKeepsOnlyWhatDiffers(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "remove", Instance: "magic", Days: 90}
	if got := p.link("invest"); got != "?page=metrics&view=invest" {
		t.Errorf("got %q", got)
	}
	p = metricsParams{Instance: "lorcana", Days: 30, Bots: true}
	if got := p.link("feature", "name", "search.sort"); got != "?page=metrics&view=feature&bots=1&days=30&instance=lorcana&name=search.sort" {
		t.Errorf("got %q", got)
	}
	p = metricsParams{Instance: "magic", Days: 90, Anon: true}
	if got := p.link("overview", "area", "a&b"); got != "?page=metrics&view=overview&anon=1&area=a%26b" {
		t.Errorf("got %q", got)
	}
}

// M6: the page candidates leave out what is not a page to remove.
func TestMetricsPagesLeaveOutWhatIsNotAPage(t *testing.T) {
	none := metricsPagesWith(func(*NavElem) bool { return false })
	if len(none) == 0 || !slices.IsSorted(none) {
		t.Fatalf("pages = %v, want a sorted, non-empty list", none)
	}
	for _, label := range none {
		if strings.HasSuffix(label, "/other") || label == "other" {
			t.Errorf("a catch-all %q is a page candidate", label)
		}
	}
	for _, label := range metricsNotPages {
		if slices.Contains(none, label) {
			t.Errorf("%q only redirects or is opened from mail, yet is a page candidate", label)
		}
	}
	for _, want := range []string{"search", "sets", "home", "newspaper/index", "newspaper/syp", "screener"} {
		if !slices.Contains(none, want) {
			t.Errorf("%q is missing from %v", want, none)
		}
	}
	// A hidden section takes its sub-pages and subviews; a hidden sub-page goes alone.
	hidden := metricsPagesWith(func(nav *NavElem) bool { return nav.Name == "Newspaper" || nav.Name == "Sealed" })
	for _, gone := range []string{"newspaper/index", "newspaper/syp", "newspaper/spike_score", "sealed"} {
		if slices.Contains(hidden, gone) {
			t.Errorf("%q is hidden on this site, yet is a page candidate", gone)
		}
	}
	if !slices.Contains(hidden, "search") || !slices.Contains(hidden, "sets") {
		t.Error("hiding Sealed took its siblings with it")
	}
	syp := metricsPagesWith(func(nav *NavElem) bool { return nav.Name == "TCG Syp List" })
	if slices.Contains(syp, "newspaper/syp") || !slices.Contains(syp, "newspaper/index") {
		t.Errorf("hiding the SYP sub-page: %v", syp)
	}
	// The real site's list is a subset of the labels the registry accepts.
	for _, label := range metricsPages(testSite) {
		if !pageLabelSet()[label] {
			t.Errorf("%q is not a page label", label)
		}
	}
}

func TestMetricsListsStoresAndRoutes(t *testing.T) {
	if got := metricsStores(nil); got != nil {
		t.Errorf("stores with no snapshot = %v", got)
	}
	p := &prices{index: storeIndex{
		seller: map[string]mtgban.Seller{"TCGPlayer": nil, "CK": nil},
		vendor: map[string]mtgban.Vendor{"CK": nil, "SCG": nil},
	}}
	if got := metricsStores(p); !slices.Equal(got, []string{"CK", "SCG", "TCGPlayer"}) {
		t.Errorf("stores = %v", got)
	}
	routes := metricsRoutes()
	if !slices.IsSorted(routes) || !slices.Contains(routes, "home") || !slices.Contains(routes, "search") || slices.Contains(routes, "other") {
		t.Errorf("routes = %v", routes)
	}
}

func TestPageHasMobile(t *testing.T) {
	for label, want := range map[string]bool{"search": true, "sets": true, "newspaper/syp": true, "home": true, "admin": true,
		"arbit": false, "reverse": false, "global": false, "upload": false, "screener": false, "privacy": true,
		"upload/handoff": true, "alerts/confirm": true, "api-plans": true, "user": true} {
		if got := pageHasMobile(label); got != want {
			t.Errorf("pageHasMobile(%s) = %v, want %v", label, got, want)
		}
	}
}

func TestFamilyLabel(t *testing.T) {
	for f, want := range map[observability.Family]string{
		observability.FamilyServer: "Server", observability.FamilyUI: "Controls",
		observability.FamilyState: "Settings", observability.FamilyStock: "Stored state",
	} {
		if got := familyLabel(f); got != want {
			t.Errorf("familyLabel(%d) = %q, want %q", f, got, want)
		}
	}
}

func TestDefaultMetricsStoreIsNilWithoutTheTables(t *testing.T) {
	saved := ObservabilityDB
	t.Cleanup(func() { ObservabilityDB = saved })
	ObservabilityDB = nil
	if store := defaultMetricsStore(); store != nil {
		t.Errorf("no database: store = %v", store)
	}
	ObservabilityDB = &observability.Client{} // feature tables not ready
	if store := defaultMetricsStore(); store != nil {
		t.Errorf("tables missing: store = %v", store)
	}
}

func TestMetricsCacheIsKeptPerStore(t *testing.T) {
	resetMetricsCache(t)
	a, b := newFakeMetrics(), newFakeMetrics()
	ca := metricsCache(a)
	if metricsCache(a) != ca {
		t.Error("the same store got another cache")
	}
	if metricsCache(b) == ca {
		t.Error("another store was served the first store's cache")
	}
}

// L20: an ok run drops this process's report cache; a failed one keeps it.
func TestAnOkMetricsJobDropsTheReportCache(t *testing.T) {
	resetMetricsCache(t)
	setTestJobs(t)
	cache := metricsCache(newFakeMetrics())
	loads := 0
	load := func(context.Context) (int, error) { loads++; return loads, nil }
	key := metricsreport.Key{Report: "bundle", Instance: "magic"}
	mustLoad := func() {
		t.Helper()
		if _, err := metricsreport.Load(context.Background(), cache, key, load); err != nil {
			t.Fatal(err)
		}
	}
	free := func(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
		return true, fn(ctx)
	}

	mustLoad()
	runMetricsJob(free, jobMetricsFold, "fold", func(context.Context) (string, error) { return "", errors.New("boom") })
	mustLoad()
	if loads != 1 {
		t.Fatalf("a failed run dropped the cache: %d loads", loads)
	}
	runMetricsJob(free, jobMetricsFold, "fold", func(context.Context) (string, error) { return "done", nil })
	mustLoad()
	if loads != 2 {
		t.Errorf("an ok run kept the cache: %d loads", loads)
	}
}

func TestLoadMetricsViewAsksForTheRightDays(t *testing.T) {
	withMetricsInstance(t, "magic")
	find := func(qs []observability.DayQuery, match func(observability.DayQuery) bool) (observability.DayQuery, bool) {
		i := slices.IndexFunc(qs, match)
		if i < 0 {
			return observability.DayQuery{}, false
		}
		return qs[i], true
	}
	store := newFakeMetrics()
	loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	unsplit, ok := find(store.queries, func(q observability.DayQuery) bool { return !q.ByTier })
	if !ok || !unsplit.To.Equal(loaderTestDay) || unsplit.Days != 180 || unsplit.Step != 30 || !unsplit.Signed || !unsplit.Humans || unsplit.Instance != "magic" {
		t.Errorf("unsplit = %+v", unsplit)
	}
	tier, ok := find(store.queries, func(q observability.DayQuery) bool { return q.ByTier })
	if !ok || !tier.To.Equal(loaderTestDay) || tier.Days != 90 || tier.Step != 0 || !tier.Signed || !tier.Humans {
		t.Errorf("by tier = %+v", tier)
	}

	store = newFakeMetrics()
	loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "remove", Instance: "lorcana", Days: 30, Anon: true, Bots: true})
	for _, q := range store.queries {
		if q.Signed || q.Humans || q.Instance != "lorcana" {
			t.Errorf("anon and bots: %+v", q)
		}
	}

	store = newFakeMetrics()
	loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if _, ok := find(store.queries, func(q observability.DayQuery) bool { return q.To.Equal(loaderTestDay.AddDate(0, 0, -7)) }); !ok {
		t.Errorf("the overview asked for no window ending 2026-11-03: %+v", store.queries)
	}
}

// M8: the digest reads its fixed windows whatever the picker says.
func TestDigestReadsItsFixedWindows(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "overview", Instance: "lorcana", Days: 180, Anon: true, Bots: true})
	has := func(want observability.DayQuery) bool {
		return slices.ContainsFunc(store.queries, func(q observability.DayQuery) bool {
			return q.Instance == want.Instance && q.To.Equal(want.To) && q.Days == want.Days && q.Step == want.Step &&
				q.Signed == want.Signed && q.Humans == want.Humans && !q.ByTier && q.Names == nil
		})
	}
	before := loaderTestDay.AddDate(0, 0, -7)
	for _, want := range []observability.DayQuery{
		{Instance: "lorcana", To: loaderTestDay, Days: 14, Step: 7, Signed: true, Humans: true},  // signals, both weeks
		{Instance: "lorcana", To: loaderTestDay, Days: 60, Step: 30, Signed: true, Humans: true}, // candidates now
		{Instance: "lorcana", To: before, Days: 60, Step: 30, Signed: true, Humans: true},        // candidates a week before
		{Instance: "lorcana", To: loaderTestDay, Days: 30, Step: 30},                             // Silent, every reader
		{Instance: "lorcana", To: loaderTestDay, Days: 360, Step: 30},                            // the picker's own window
	} {
		if !has(want) {
			t.Errorf("no query %+v in %+v", want, store.queries)
		}
	}
	// the phone rows of each week come from page.view by device, never from page hits
	if !slices.ContainsFunc(store.queries, func(q observability.DayQuery) bool {
		return q.ByDevice && q.Days == 14 && q.Step == 7 && q.Signed && q.Humans && slices.Equal(q.Names, []string{"page.view"}) && q.To.Equal(loaderTestDay)
	}) {
		t.Errorf("no weekly page.view by device in %+v", store.queries)
	}
	// D3: a cold Overview reads page hits once, the last 30 complete days whatever the picker says
	want := [][2]time.Time{{loaderTestDay.AddDate(0, 0, -29), loaderTestDay.AddDate(0, 0, 1)}}
	if !slices.Equal(store.visitCalls, want) {
		t.Errorf("page visits %v, want one call %v", store.visitCalls, want)
	}
}

// D3: a failed page hits read is remembered a minute, so reloads do not ask again; then it is asked again.
func TestAFailedPageHitsReadIsRememberedAMinute(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.visitsErr = errors.New("slow")
	clk := &testClock{t: loaderTestNow}
	cache := metricsreport.NewCache(store.FoldStamp, clk.now)
	p := metricsParams{View: "invest", Instance: "magic", Days: 90}
	for range 3 {
		if v := loadTestView(t, store, cache, metricsTestRegistry(), p); !v.Invest.VisitsRead.Failed || !v.Failed {
			t.Fatalf("visits read %+v, failed %v", v.Invest.VisitsRead, v.Failed)
		}
	}
	if len(store.visitCalls) != 1 {
		t.Errorf("%d page hits reads within a minute, want 1", len(store.visitCalls))
	}
	clk.add(metricsVisitsFailFor)
	store.mu.Lock()
	store.visitsErr = nil
	store.mu.Unlock()
	if v := loadTestView(t, store, cache, metricsTestRegistry(), p); v.Invest.VisitsRead.Failed || len(store.visitCalls) != 2 {
		t.Errorf("after a minute: %+v, %d reads", v.Invest.VisitsRead, len(store.visitCalls))
	}
}

func TestLoadMetricsViewBuildsOnlyItsView(t *testing.T) {
	withMetricsInstance(t, "magic")
	for _, c := range []struct{ asked, built string }{
		{"overview", "overview"}, {"remove", "remove"}, {"invest", "invest"}, {"feature", "feature"},
		{"health", "health"}, {"explore", "explore"}, {"trends", "overview"}, {"", "overview"},
	} {
		store := newFakeMetrics()
		p := readMetricsParams(url.Values{"view": {c.asked}}.Get, nil)
		v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p)
		got := map[string]bool{"overview": v.Overview != nil, "remove": v.Remove != nil, "invest": v.Invest != nil,
			"feature": v.Feature != nil, "health": v.Health != nil, "explore": v.Explore != nil}
		for view, built := range got {
			if built != (view == c.built) {
				t.Errorf("view %q: %s built %v", c.asked, view, built)
			}
		}
		if v.View != c.built || len(v.Charts) != 0 {
			t.Errorf("view %q: View %q, charts %d", c.asked, v.View, len(v.Charts))
		}
		var active []string
		for _, l := range v.Views {
			if l.Active {
				active = append(active, l.Label)
			}
		}
		if len(v.Views) != len(metricsViewList) || len(active) != 1 || !strings.EqualFold(active[0], c.built) {
			t.Errorf("view %q: tabs %+v", c.asked, v.Views)
		}
	}
}

func TestMetricsViewPickers(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.instances = []string{"lorcana"} // this site has no rows yet
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "lorcana", Days: 30})
	if len(v.Instances) != 2 || v.Instances[0].Label != "magic" || v.Instances[0].URL != "?page=metrics&view=remove&days=30" || !v.Instances[1].Active {
		t.Errorf("instances = %+v", v.Instances)
	}
	if len(v.Windows) != 3 || !v.Windows[0].Active || v.Windows[1].URL != "?page=metrics&view=remove&instance=lorcana" {
		t.Errorf("windows = %+v", v.Windows)
	}
	if v.AnonLink.Active || v.AnonLink.URL != "?page=metrics&view=remove&anon=1&days=30&instance=lorcana" {
		t.Errorf("anon = %+v", v.AnonLink)
	}
	if v.BotsLink.URL != "?page=metrics&view=remove&bots=1&days=30&instance=lorcana" {
		t.Errorf("bots = %+v", v.BotsLink)
	}
	if !v.Folded || !v.Through.Equal(loaderTestDay) {
		t.Errorf("through = %v, folded %v", v.Through, v.Folded)
	}
}

// removeFixture is a full 90-day window: page views of search only, and the counter every day.
func removeFixture() []observability.DayTotal {
	rows := fullRows("metrics.flush", "", "", 1440, 6)
	return append(rows, fullRows("page.view", "", "search", 100, 6)...)
}

func TestRemoveViewGroupsAndDecorates(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "remove", Instance: "magic", Days: 90}
	names := metricsTestRegistry()
	byTier := []observability.DayTotal{{Name: "page.view", Value: "sets", Tier: "Legacy", N: 2}}
	view := buildMetricsRemove(names, metricsTestLists, removeFixture(), byTier, true, nil, 60, p)
	var areas []string
	for _, a := range view.Areas {
		areas = append(areas, a.Area)
	}
	if !slices.Equal(areas, []string{"site", "search", "arbit"}) {
		t.Fatalf("areas = %v, want the registry's order", areas)
	}
	var kinds []string
	for _, k := range view.Areas[1].Kinds {
		kinds = append(kinds, k.Kind)
	}
	if !slices.Equal(kinds, []string{"option", "operator"}) {
		t.Errorf("search kinds = %v", kinds)
	}
	for _, a := range view.Areas {
		for _, k := range a.Kinds {
			for _, r := range k.Rows {
				if !strings.HasPrefix(r.URL, "?page=metrics&view=feature&name=") || r.Help == "" || r.Key != r.Name+"|"+r.Scope+"|"+r.Value {
					t.Errorf("row %+v", r)
				}
			}
		}
	}
	sets := view.Areas[0].Kinds[0].Rows
	if len(sets) != 2 || sets[0].Value != "alerts" || sets[1].Value != "sets" || sets[1].Tiers != "Legacy 2" || sets[0].Class != metricsreport.ClassUnused {
		t.Errorf("page rows = %+v", sets)
	}
	// M3: a row carries its registry Help, which says what the count means.
	arbit := view.Areas[2].Kinds[0].Rows[0]
	if arbit.Help != "Counted when turned away from its default." {
		t.Errorf("arbit row help = %q", arbit.Help)
	}

	reviews := []observability.Review{{Instance: "magic", Name: "arbit.toggle", Value: "legit", Verdict: "keep", Note: "default on"}}
	view = buildMetricsRemove(names, metricsTestLists, removeFixture(), nil, true, reviews, 60, p)
	if len(view.Areas) != 2 || len(view.Reviewed) != 1 || view.Reviewed[0].Verdict != "keep" || view.Reviewed[0].Note != "default on" {
		t.Errorf("reviewed: areas %d, reviewed %+v", len(view.Areas), view.Reviewed)
	}

	// With no rows at all every candidate is not measured, never unused.
	empty := buildMetricsRemove(names, metricsTestLists, nil, nil, true, nil, 60, p)
	if len(empty.Areas) != 0 || len(empty.NotMeasured) == 0 {
		t.Errorf("no rows: areas %v, not measured %d", empty.Areas, len(empty.NotMeasured))
	}
}

func TestRemoveViewWithTheRealRegistry(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "remove", Instance: "magic", Days: 90}
	view := buildMetricsRemove(observability.All(), metricsLists(testSite, nil), removeFixture(), nil, true, nil, 60, p)
	if len(view.Areas) == 0 {
		t.Fatal("no removal rows from a full window of the real registry")
	}
	for _, a := range view.Areas {
		for _, k := range a.Kinds {
			for _, r := range k.Rows {
				if !strings.HasPrefix(r.URL, "?page=metrics&view=feature&name=") {
					t.Errorf("row URL %q", r.URL)
				}
			}
		}
	}
}

func TestInvestViewAlwaysHasItsSixSections(t *testing.T) {
	withMetricsInstance(t, "magic")
	view := buildMetricsInvest(observability.All(), nil, nil, true, nil, true, metricsParams{Instance: "magic", Days: 90})
	var titles []string
	for _, s := range view.Sections {
		titles = append(titles, s.Title)
		for _, r := range s.Rows {
			if (s.Key == metricsreport.SectionWalls || s.Key == metricsreport.SectionFailures) && !r.NotMeasured {
				t.Errorf("%s holds a measured row with no data: %+v", s.Title, r)
			}
		}
		if (s.Key == metricsreport.SectionMobile || s.Key == metricsreport.SectionDepth) != (s.Note == metricsPageHitsNote) {
			t.Errorf("%s note %q", s.Title, s.Note)
		}
	}
	if !slices.Equal(titles, []string{"Walls", "Failures", "Phones on desktop pages", "Growing", "New", "Depth, pages only"}) {
		t.Errorf("titles = %v", titles)
	}
	empty := &MetricsInvest{Sections: metricsSections(nil)}
	if len(empty.Sections) != 6 {
		t.Errorf("an empty view has %d sections", len(empty.Sections))
	}
}

func TestInvestViewMarksScriptErrorsNotMeasured(t *testing.T) {
	withMetricsInstance(t, "magic")
	view := buildMetricsInvest(observability.All(), nil, nil, true, nil, true, metricsParams{Instance: "magic", Days: 90})
	rows := view.Sections[1].Rows
	if len(rows) == 0 || rows[len(rows)-1].Label != "Script errors" || !rows[len(rows)-1].NotMeasured || rows[len(rows)-1].RateText != "" {
		t.Errorf("failures = %+v", rows)
	}
}

func TestInvestWallsTrendAndTiers(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{Instance: "magic", Days: 30}
	walls := []observability.DayTotal{
		{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 30, Days: 10},
		{Period: 1, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 10, Days: 5},
	}
	byTier := []observability.DayTotal{
		{Name: "auth.refuse", Scope: "search", Value: "no_access", Tier: "Any", N: 25},
		{Name: "auth.refuse", Scope: "search", Value: "no_access", Tier: "Pioneer", N: 5},
	}
	unmeasuredBefore := buildMetricsInvest(metricsTestRegistry(), append(fullRows("metrics.flush", "", "", 1, 1), walls...), byTier, true, nil, true, p)
	row := unmeasuredBefore.Sections[0].Rows[0]
	if row.Label != "Page refused for the tier: search" || row.Trend != "" || row.Tiers != "Any 25, Pioneer 5" || row.URL != "?page=metrics&view=feature&days=30&name=auth.refuse" ||
		row.PrevText != "the earlier period was not counted, so no trend" {
		t.Errorf("no earlier window: %+v", row)
	}
	// a full window against a 13-day one: no trend, and the cell says why
	partial := append(fullRows("metrics.flush", "", "", 1, 1), observability.DayTotal{Period: 1, Name: "metrics.flush", N: 1, Days: 13})
	row = buildMetricsInvest(metricsTestRegistry(), append(partial, walls...), byTier, true, nil, true, p).Sections[0].Rows[0]
	if row.Trend != "" || row.PrevText != "10 in 13 counted days; the earlier period was not fully counted, so no trend" {
		t.Errorf("a 13-day earlier window: trend %q, %q", row.Trend, row.PrevText)
	}
	measured := buildMetricsInvest(metricsTestRegistry(), append(fullRows("metrics.flush", "", "", 1, 2), walls...), byTier, true, nil, true, p)
	if got := measured.Sections[0].Rows[0]; got.Trend != "up" || got.PrevText != "10 in 30 counted days, up" {
		t.Errorf("trend = %q, %q, want up", got.Trend, got.PrevText)
	}
}

func TestMobileRowsUsePageHasMobile(t *testing.T) {
	withMetricsInstance(t, "magic")
	visits := []observability.PageVisit{
		{Path: "arbit", Views: 200, MobileViews: 50, Visitors: 10},
		{Path: "search", Views: 9000, MobileViews: 4000, Visitors: 100},
		{Path: "other", Views: 500, MobileViews: 500, Visitors: 5},
	}
	view := buildMetricsInvest(metricsTestRegistry(), nil, nil, true, metricsreport.PageDepths(visits, []string{"arbit", "search", "sets"}, pageHasMobile), true, metricsParams{Instance: "magic", Days: 90})
	mobile := view.Sections[2]
	if mobile.Key != metricsreport.SectionMobile || len(mobile.Rows) != 1 || mobile.Rows[0].Label != "arbit" || mobile.Rows[0].RateText != "25.0%" {
		t.Errorf("mobile = %+v", mobile.Rows)
	}
	for _, r := range view.Sections[5].Rows {
		if r.Label == "other" {
			t.Error("the catch-all reads as a page in depth")
		}
	}
}

func TestOverviewTakesTenAndCountsTheRest(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := []observability.Name{
		{Name: "metrics.flush", Report: observability.ReportInternal},
		{Name: "page.view", Values: observability.ValuePage, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "page", Area: "site", Help: "Page views, by page."},
	}
	var pages []string
	for i := range 16 {
		pages = append(pages, "p"+string(rune('a'+i)))
	}
	store := newFakeMetrics()
	store.totals = append(fullRows("metrics.flush", "", "", 1440, 6), fullRows("page.view", "", "pa", 100, 6)...)
	store.reviews = []observability.Review{{Instance: "magic", Name: "page.view", Value: "pb", Verdict: "keep"}}
	v := loadMetricsViewFor(context.Background(), store, testCache(store), names, metricsreport.Lists{Pages: pages}, metricsParams{View: "overview", Instance: "magic", Days: 90}, loaderTestNow)
	ov := v.Overview
	if len(ov.Remove) != 10 {
		t.Fatalf("Remove has %d rows, want 10", len(ov.Remove))
	}
	if len(ov.MoreRows) != 1 || ov.MoreRows[0].Area != "site" || ov.MoreRows[0].Rows != 4 {
		t.Errorf("MoreRows = %+v, want 4 in site", ov.MoreRows)
	}
	for _, r := range ov.Remove {
		if r.Value == "pb" || r.Value == "pa" || r.Help != "Page views, by page." {
			t.Errorf("row %+v", r)
		}
	}
	if !ov.DigestReady || ov.NothingChanged != metricsreport.NothingChanged || ov.DaysData != 90 {
		t.Errorf("digest ready %v, nothing changed %q, days %d", ov.DigestReady, ov.NothingChanged, ov.DaysData)
	}
	if v.Failed {
		t.Error("a load failed")
	}
}

func TestOverviewLiveAndDigestHealth(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.health = []observability.InstanceHealth{{Instance: "magic", LastFlush: loaderTestNow.Add(-5 * time.Minute)}}
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if !v.Overview.Live {
		t.Error("a flush five minutes ago is not live")
	}
	// No job ran, so the digest's Health section names each registered job.
	var health []string
	for _, s := range v.Overview.Changes.Sections {
		if s.Title == "Health" {
			health = s.Lines
		}
	}
	for _, job := range []string{"fold", "stock", "events_rollup"} {
		if !slices.Contains(health, "Job "+job+": no run in 14 days") {
			t.Errorf("health %v does not name %s", health, job)
		}
	}

	store = newFakeMetrics()
	store.health = []observability.InstanceHealth{{Instance: "magic", LastFlush: loaderTestNow.Add(-11 * time.Minute)}}
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90}); v.Overview.Live {
		t.Error("a flush eleven minutes ago is live")
	}
}

func TestStockNamesAreReadUnderShared(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	older := loaderTestDay.AddDate(0, 0, -1)
	store.stock = []observability.DayTotal{
		{Name: "stock.rows", Scope: "magic", N: 300, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Name: "stock.rows", Scope: "lorcana", N: 100, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Period: 1, Name: "stock.rows", Scope: "pokemon", N: 999, Days: 1, First: older, Last: older},
	}
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "lorcana", Days: 90})
	i := slices.IndexFunc(store.queries, func(q observability.DayQuery) bool { return q.Instance == observability.SharedInstance })
	if i < 0 {
		t.Fatalf("no query under %q: %+v", observability.SharedInstance, store.queries)
	}
	q := store.queries[i]
	if q.Signed || q.Humans || q.Step != 1 || !slices.Equal(q.Names, []string{"stock.rows"}) {
		t.Errorf("stock query = %+v", q)
	}
	ov := v.Overview
	if !ov.StockDay.Equal(loaderTestDay) || len(ov.Stock) != 1 {
		t.Fatalf("stock day %v, groups %+v", ov.StockDay, ov.Stock)
	}
	g := ov.Stock[0]
	if g.Name != "stock.rows" || g.Help != "Rows stored, by game." || g.Total != 400 || len(g.Rows) != 2 ||
		g.Rows[0].Label != "magic" || g.Rows[0].Share != 0.75 || g.Rows[1].Share != 0.25 {
		t.Errorf("group = %+v", g)
	}

	// A registry with no stored-state name asks nothing under shared.
	store = newFakeMetrics()
	loadTestView(t, store, testCache(store), metricsTestRegistry()[:6], metricsParams{View: "overview", Instance: "magic", Days: 90})
	if slices.ContainsFunc(store.queries, func(q observability.DayQuery) bool { return q.Instance == observability.SharedInstance }) {
		t.Error("a stock query with no stock names")
	}
}

// M9: a view only notes the families whose rows it loaded.
func TestCoverageNotesOnlyForLoadedData(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = removeFixture()
	remove := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	if !slices.Equal(remove.Notes, []string{"Controls: not measured yet.", "Settings: not measured yet."}) {
		t.Errorf("remove notes = %v", remove.Notes)
	}
	overview := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if !slices.Contains(overview.Notes, "Stored state: "+metricsStockStale(time.Time{})+".") {
		t.Errorf("overview notes = %v, the stock load was empty", overview.Notes)
	}
	store.stock = []observability.DayTotal{{Name: "stock.rows", N: 1, Days: 1, First: loaderTestDay, Last: loaderTestDay}}
	overview = loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if slices.Contains(overview.Notes, "Stored state: not measured yet.") || slices.Contains(overview.Notes, "Server facts: not measured yet.") {
		t.Errorf("overview notes = %v", overview.Notes)
	}
}

// L9: before the first fold every view renders and says so, asking nothing of feature_days but stock.
func TestNothingFoldedYet(t *testing.T) {
	withMetricsInstance(t, "magic")
	for _, view := range []string{"overview", "remove", "invest"} {
		store := newFakeMetrics()
		store.folded, store.through = false, time.Time{}
		v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: view, Instance: "magic", Days: 90})
		if v.Folded || !v.Through.IsZero() || v.Failed || len(v.Notes) != 0 || len(v.Coverage) != 0 {
			t.Errorf("%s: folded %v, through %v, failed %v, notes %v", view, v.Folded, v.Through, v.Failed, v.Notes)
		}
		for _, q := range store.queries {
			if q.Instance != observability.SharedInstance {
				t.Errorf("%s: asked %+v before a fold", view, q)
			}
		}
		switch view {
		case "remove":
			if v.Remove == nil || len(v.Remove.Areas)+len(v.Remove.NotMeasured) != 0 {
				t.Errorf("remove = %+v", v.Remove)
			}
		case "invest":
			if v.Invest == nil || len(v.Invest.Sections) != 6 {
				t.Errorf("invest = %+v", v.Invest)
			}
		default:
			if v.Overview == nil || v.Overview.DigestReady || len(v.Overview.Remove) != 0 {
				t.Errorf("overview = %+v", v.Overview)
			}
		}
	}
}

func TestMetricsSnapshotCarriesErrors(t *testing.T) {
	names := metricsTestRegistry()
	week := append(fullRows("metrics.flush", "", "", 1, 1), observability.DayTotal{Period: 1, Name: "metrics.flush", N: 1, Days: 4})
	week[0].Days = 6
	s, prev := metricsreport.DigestSnapshots(metricsreport.DigestInput{Names: names, Lists: metricsTestLists, Week: week, Now: removeFixture(),
		Problems: []string{"p"}, NowErrors: []string{"navbar.js:42 TypeError"}})
	if !slices.Equal(s.Problems, []string{"p"}) || !slices.Equal(s.Errors, []string{"navbar.js:42 TypeError"}) || s.CounterDays != 6 {
		t.Errorf("snapshot problems %v, errors %v, counter days %d", s.Problems, s.Errors, s.CounterDays)
	}
	if prev.Problems != nil || prev.Errors != nil || prev.CounterDays != 4 {
		t.Errorf("prev problems %v, errors %v, counter days %d", prev.Problems, prev.Errors, prev.CounterDays)
	}
}

func TestAFailedQueryIsShownNotCached(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	cache := testCache(store)
	store.totalsErr = errors.New("database down")
	p := metricsParams{View: "remove", Instance: "magic", Days: 90}
	v := loadTestView(t, store, cache, metricsTestRegistry(), p)
	if !v.Failed || v.Remove == nil || len(v.Remove.Areas) != 0 {
		t.Errorf("failed %v, remove %+v", v.Failed, v.Remove)
	}
	before := store.dayTotalCount()
	store.totalsErr = nil
	store.totals = removeFixture()
	v = loadTestView(t, store, cache, metricsTestRegistry(), p)
	if v.Failed || store.dayTotalCount() == before || len(v.Remove.Areas) == 0 {
		t.Errorf("after the error cleared: failed %v, queries %d then %d", v.Failed, before, store.dayTotalCount())
	}

	// Every method failing still builds each view.
	for _, view := range []string{"overview", "remove", "invest"} {
		store := newFakeMetrics()
		store.err = errors.New("database down")
		v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: view, Instance: "magic", Days: 90})
		if !v.Failed || (v.Overview == nil && v.Remove == nil && v.Invest == nil) {
			t.Errorf("%s: failed %v", view, v.Failed)
		}
		if len(v.Instances) != 1 || v.Instances[0].Label != "magic" {
			t.Errorf("%s: instances %+v", view, v.Instances)
		}
	}
}

func TestSecondLoadIsServedFromTheCache(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	cache := testCache(store)
	p := metricsParams{View: "overview", Instance: "magic", Days: 90}
	loadTestView(t, store, cache, metricsTestRegistry(), p)
	queries, visits := store.dayTotalCount(), len(store.visitCalls)
	loadTestView(t, store, cache, metricsTestRegistry(), p)
	if store.dayTotalCount() != queries || len(store.visitCalls) != visits {
		t.Errorf("DayTotals %d then %d, PageVisits %d then %d", queries, store.dayTotalCount(), visits, len(store.visitCalls))
	}
	if store.reviewCalls != 2 {
		t.Errorf("Reviews read %d times, want every request", store.reviewCalls)
	}
}

// S1: minute rows are at most a minute old, page hits ten minutes; day rows wait for the stamp.
func TestMinuteLoadsExpire(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	clock := &testClock{t: loaderTestNow}
	cache := metricsreport.NewCache(store.FoldStamp, clock.now)
	p := metricsParams{View: "overview", Instance: "magic", Days: 90}
	load := func() {
		t.Helper()
		loadMetricsViewFor(context.Background(), store, cache, metricsTestRegistry(), metricsTestLists, p, clock.now())
	}
	load()
	queries, visits := store.dayTotalCount(), len(store.visitCalls)
	clock.add(59 * time.Second)
	load()
	if store.healthCalls != 1 || store.throughCalls != 1 {
		t.Errorf("at 59 s: health read %d times, folded through %d", store.healthCalls, store.throughCalls)
	}
	clock.add(2 * time.Second)
	load()
	if store.healthCalls != 2 || store.throughCalls != 2 || len(store.visitCalls) != visits {
		t.Errorf("at 61 s: health read %d times, folded through %d, visits %d", store.healthCalls, store.throughCalls, len(store.visitCalls))
	}
	clock.add(10 * time.Minute)
	load()
	if len(store.visitCalls) <= visits {
		t.Error("page visits were served past ten minutes")
	}
	if store.dayTotalCount() != queries {
		t.Errorf("day rows were read again with the stamp unchanged: %d then %d", queries, store.dayTotalCount())
	}
}

func TestMetricsOffWithoutTheStore(t *testing.T) {
	saved := metricsStoreFn
	metricsStoreFn = func() metricsStore { return nil }
	t.Cleanup(func() { metricsStoreFn = saved })
	withSigMode(t, true, false)
	rec := httptest.NewRecorder()
	testSite.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin?page=metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTheAdminPageLoadsTheMetricsSection(t *testing.T) {
	resetMetricsCache(t)
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	saved := metricsStoreFn
	metricsStoreFn = func() metricsStore { return store }
	t.Cleanup(func() { metricsStoreFn = saved })
	withSigMode(t, true, false)

	rec := httptest.NewRecorder()
	testSite.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin?page=usage", nil))
	if rec.Code != http.StatusOK || store.dayTotalCount() != 0 {
		t.Fatalf("another tab: status %d, %d queries", rec.Code, store.dayTotalCount())
	}
	rec = httptest.NewRecorder()
	testSite.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin?page=metrics&view=remove&instance=x'--&days=7", nil))
	if rec.Code != http.StatusOK || store.dayTotalCount() == 0 {
		t.Fatalf("metrics: status %d, %d queries", rec.Code, store.dayTotalCount())
	}
	for _, q := range store.queries {
		if q.Instance != "magic" || (q.Days != 180 && q.Days != 90) {
			t.Errorf("query %+v", q)
		}
	}
}

// digestSection is the lines of the digest section titled title.
func digestSection(d metricsreport.Digest, title string) []string {
	for _, sec := range d.Sections {
		if sec.Title == title {
			return sec.Lines
		}
	}
	return nil
}

// usedThenUnused is pa used in both windows and pb used only in the window ending a week before the folded day.
func usedThenUnused() map[time.Time][]observability.DayTotal {
	now := append(fullRows("metrics.flush", "", "", 1440, 2), fullRows("page.view", "", "pa", 100, 2)...)
	before := append(append(fullRows("metrics.flush", "", "", 1440, 2), fullRows("page.view", "", "pa", 100, 2)...), fullRows("page.view", "", "pb", 100, 2)...)
	return map[time.Time][]observability.DayTotal{loaderTestDay: now, loaderTestDay.AddDate(0, 0, -7): before}
}

// Finding 1: another site's pages are not filtered by this site's hiding, and its unviewed pages are not judged.
func TestAnotherSitesUnviewedPagesAreNotJudged(t *testing.T) {
	withMetricsInstance(t, "magic")
	if got, want := metricsListsFor(testSite, nil, "magic").Pages, metricsPages(testSite); !slices.Equal(got, want) {
		t.Errorf("own pages = %v, want this site's filtered list", got)
	}
	if got, want := metricsListsFor(testSite, nil, "lorcana").Pages, metricsPagesWith(func(*NavElem) bool { return false }); !slices.Equal(got, want) {
		t.Errorf("another site's pages = %v, want the unfiltered list", got)
	}

	names := metricsTestRegistry()
	totals := append(removeFixture(), fullRows("page.view", "", "sets", 50, 6)...)
	pageRows := func(v *MetricsRemove) []string {
		var out []string
		for _, a := range v.Areas {
			for _, k := range a.Kinds {
				for _, r := range k.Rows {
					if r.Name == "page.view" {
						out = append(out, r.Value+":"+r.Class)
					}
				}
			}
		}
		return out
	}
	// Own: sealed is hidden here, so it is not in the list; alerts is shown and unused.
	own := buildMetricsRemove(names, metricsreport.Lists{Pages: []string{"alerts", "search", "sets"}}, totals, nil, true, nil, 60, metricsParams{View: "remove", Instance: "magic", Days: 90})
	if got := pageRows(own); !slices.Equal(got, []string{"alerts:unused"}) {
		t.Errorf("own page rows = %v", got)
	}
	// Another: every page is listed, the unviewed ones are left out, a viewed one is classed as usual.
	reviews := []observability.Review{{Instance: "lorcana", Name: "page.view", Value: "sets", Verdict: "keep"}}
	foreignLists := metricsreport.Lists{Pages: []string{"alerts", "sealed", "search", "sets"}}
	other := buildMetricsRemove(names, foreignLists, totals, nil, true, reviews, 60, metricsParams{View: "remove", Instance: "lorcana", Days: 90})
	if got := pageRows(other); len(got) != 0 {
		t.Errorf("another site's unviewed pages were judged: %v", got)
	}
	if len(other.Reviewed) != 1 || other.Reviewed[0].Value != "sets" {
		t.Errorf("a viewed page lost its class: %+v", other.Reviewed)
	}
	for _, r := range other.NotMeasured {
		if r.Name == "page.view" {
			t.Errorf("an unviewed page reads not measured: %+v", r)
		}
	}
	if len(other.Areas) == 0 {
		t.Error("options on every page were dropped with the pages")
	}

	// The loader: the note on another site's Overview and Remove only; its Overview rows skip the pages too.
	for _, c := range []struct {
		inst, view string
		note       bool
	}{{"magic", "remove", false}, {"magic", "overview", false}, {"lorcana", "remove", true}, {"lorcana", "overview", true}, {"lorcana", "invest", false}} {
		store := newFakeMetrics()
		store.totals = totals
		v := loadMetricsViewFor(context.Background(), store, testCache(store), names, foreignLists, metricsParams{View: c.view, Instance: c.inst, Days: 90}, loaderTestNow)
		if (v.PagesNote == metricsForeignPagesNote) != c.note || (!c.note && v.PagesNote != "") {
			t.Errorf("%s %s: note %q", c.inst, c.view, v.PagesNote)
		}
		if c.view == "overview" {
			listed := slices.ContainsFunc(v.Overview.Remove, func(r MetricsCandidateRow) bool { return r.Name == "page.view" })
			if listed == c.note {
				t.Errorf("%s overview: page rows listed %v", c.inst, listed)
			}
		}
	}
}

// Finding 1, digest: another site's unviewed pages never become new to consider removing.
func TestDigestSkipsAnotherSitesUnviewedPages(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := metricsTestRegistry()[:2]
	lists := metricsreport.Lists{Pages: []string{"pa", "pb"}}
	for _, c := range []struct {
		inst string
		want []string
	}{{"magic", []string{"site: 1"}}, {"lorcana", nil}} {
		store := newFakeMetrics()
		store.totalsTo = usedThenUnused()
		v := loadMetricsViewFor(context.Background(), store, testCache(store), names, lists, metricsParams{View: "overview", Instance: c.inst, Days: 30}, loaderTestNow)
		if got := digestSection(v.Overview.Changes, "New to consider removing"); !slices.Equal(got, c.want) {
			t.Errorf("%s: removals %v, want %v", c.inst, got, c.want)
		}
	}
}

// Finding 4: the digest's two weeks and two candidate windows are each read at their own end.
func TestDigestComparesTwoDifferentWeeks(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := metricsTestRegistry()
	store := newFakeMetrics()
	store.week = []observability.DayTotal{
		{Period: 0, Name: "metrics.flush", N: 1, Days: 7},
		{Period: 1, Name: "metrics.flush", N: 1, Days: 7},
		{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 200, Days: 7},
		{Period: 1, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 50, Days: 7},
	}
	v := loadTestView(t, store, testCache(store), names, metricsParams{View: "overview", Instance: "magic", Days: 90})
	if got := digestSection(v.Overview.Changes, "Moved most"); !slices.Equal(got, []string{"Page refused for the tier: search: 50 to 200"}) {
		t.Errorf("moved most = %v", got)
	}

	store = newFakeMetrics()
	store.totalsTo = usedThenUnused()
	v = loadMetricsViewFor(context.Background(), store, testCache(store), names[:2], metricsreport.Lists{Pages: []string{"pa", "pb"}}, metricsParams{View: "overview", Instance: "magic", Days: 90}, loaderTestNow)
	if got := digestSection(v.Overview.Changes, "New to consider removing"); !slices.Equal(got, []string{"site: 1"}) {
		t.Errorf("removals = %v, want pb new since a week ago", got)
	}
}

// Finding 2: a failed read is told apart from a fact.
func TestTheViewSaysWhatIsKnown(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "overview", Instance: "magic", Days: 90}
	store := newFakeMetrics()
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p)
	if !v.FoldedKnown || !v.Folded || !v.Overview.LiveKnown {
		t.Errorf("all answered: folded known %v, folded %v, live known %v", v.FoldedKnown, v.Folded, v.Overview.LiveKnown)
	}
	store = newFakeMetrics()
	store.folded = false
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p); !v.FoldedKnown || v.Folded || v.Failed {
		t.Errorf("nothing folded: known %v, folded %v, failed %v", v.FoldedKnown, v.Folded, v.Failed)
	}
	store = newFakeMetrics()
	store.throughErr = errors.New("down")
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p); v.FoldedKnown || v.Folded || !v.Failed {
		t.Errorf("read failed: known %v, folded %v, failed %v", v.FoldedKnown, v.Folded, v.Failed)
	}
	store = newFakeMetrics()
	store.healthErr = errors.New("down")
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p); v.Overview.LiveKnown || v.Overview.Live || !v.Failed || v.Overview.DigestReady {
		t.Errorf("health failed: live known %v, live %v, failed %v, digest %v", v.Overview.LiveKnown, v.Overview.Live, v.Failed, v.Overview.DigestReady)
	}
}

// Finding 3: a failed reviews read is said, and no digest is built without the reviews.
func TestAFailedReviewsReadIsSaid(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = removeFixture()
	store.reviewErr = errors.New("down")
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	if !v.Failed || !v.Remove.ReviewsFailed || len(v.Remove.Areas) == 0 {
		t.Errorf("remove: failed %v, reviews failed %v, areas %d", v.Failed, v.Remove.ReviewsFailed, len(v.Remove.Areas))
	}
	v = loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if !v.Failed || !v.Overview.ReviewsFailed || v.Overview.DigestReady {
		t.Errorf("overview: failed %v, reviews failed %v, digest ready %v", v.Failed, v.Overview.ReviewsFailed, v.Overview.DigestReady)
	}
	store.reviewErr = nil
	v = loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	if v.Remove.ReviewsFailed || v.Failed {
		t.Errorf("reviews read: reviews failed %v, failed %v", v.Remove.ReviewsFailed, v.Failed)
	}
}

// featureTestRegistry is metricsTestRegistry with stock.rows given an area, a denominator for
// search.sort and two of Silent's every-view counts.
func featureTestRegistry() []observability.Name {
	names := metricsTestRegistry()
	for i := range names {
		switch names[i].Name {
		case "stock.rows":
			names[i].Area = "account"
		case "search.sort":
			names[i].Denom = "search.result"
		}
	}
	return append(names,
		observability.Name{Name: "search.result", Area: "search", Values: observability.ValueEnum, Enum: []string{"found", "empty"}, Report: observability.ReportSignal, Help: "Outcome of a results page view."},
		observability.Name{Name: "arbit.view", Area: "arbit", Report: observability.ReportSignal, Page: "arbit,reverse,global", Help: "An arbit page view."},
		observability.Name{Name: "news.report", Area: "news", Report: observability.ReportSignal, Page: "newspaper/index", Help: "A newspaper report view."},
	)
}

// queriedNames are the names every DayTotals call asked for, nil ones left out.
func queriedNames(f *fakeMetricsStore) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, q := range f.queries {
		out = append(out, q.Names...)
	}
	for _, c := range f.hourCalls {
		out = append(out, c.q.Names...)
	}
	return out
}

// chartByID is the chart with id, and whether there is one.
func chartByID(v *MetricsView, id string) (MetricsChart, bool) {
	i := slices.IndexFunc(v.Charts, func(c MetricsChart) bool { return c.ID == id })
	if i < 0 {
		return MetricsChart{}, false
	}
	return v.Charts[i], true
}

func TestFeatureNameViewFillsEveryDay(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.named = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Scope: "search", Value: "alpha", N: 30, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Period: 3, Name: "search.sort", Scope: "sets", Value: "alpha", N: 10, Days: 1},
	}
	store.byTier = []observability.DayTotal{{Name: "search.sort", Value: "alpha", Tier: "Any", N: 30}, {Name: "search.sort", Value: "alpha", Tier: "Legacy", N: 10}}
	store.byDevice = []observability.DayTotal{{Name: "search.sort", Value: "alpha", Device: "desktop", N: 40}}
	p := metricsParams{View: "feature", Instance: "magic", Days: 30, Name: "search.sort"}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), p)
	f := v.Feature
	if f == nil || f.Name == nil || f.Name.Name != "search.sort" || f.Name.Help != "Order the results were sorted in." || f.Family != "Server" || f.NoSuchName {
		t.Fatalf("feature = %+v", f)
	}
	if f.Total != 40 || !f.HasRows || f.Standing || f.Read.Failed || v.Failed {
		t.Errorf("total %d, has rows %v, standing %v, read %+v", f.Total, f.HasRows, f.Standing, f.Read)
	}
	// alpha has every use; price is in the registry with none
	if len(f.Values) != 2 || f.Values[0].Label != "alpha" || f.Values[0].Share != 1 || f.Values[1].Label != "price" || f.Values[1].N != 0 {
		t.Errorf("values = %+v", f.Values)
	}
	var sum float64
	for _, s := range f.Values {
		sum += s.Share
	}
	if sum != 1 {
		t.Errorf("value shares sum to %v", sum)
	}
	if len(f.Scopes) != 2 || f.Scopes[0].Label != "search" || f.Scopes[0].Share != 0.75 {
		t.Errorf("scopes = %+v", f.Scopes)
	}
	if len(f.Tiers) != 2 || f.Tiers[0].Label != "Any" || f.Tiers[0].Share != 0.75 || len(f.Devices) != 1 || f.Devices[0].Share != 1 {
		t.Errorf("tiers %+v, devices %+v", f.Tiers, f.Devices)
	}
	if f.AreaURL != "?page=metrics&view=feature&area=search&days=30" || f.ExploreURL != "?page=metrics&view=explore&days=30&name=search.sort" {
		t.Errorf("links %q %q", f.AreaURL, f.ExploreURL)
	}
	c, ok := chartByID(v, "metrics-days")
	if !ok || f.DaysID != "metrics-days" || c.Kind != "line" || len(v.Charts) != 1 {
		t.Fatalf("charts = %+v", v.Charts)
	}
	if len(c.Labels) != 30 || c.Labels[0] != "2026-10-12" || c.Labels[29] != "2026-11-10" || len(c.Series) != 1 {
		t.Fatalf("labels %v", c.Labels)
	}
	d := c.Series[0].Data
	if len(d) != 30 || d[29] != 30 || d[26] != 10 || d[27] != 0 || d[0] != 0 {
		t.Errorf("data = %v", d)
	}
	for _, q := range store.queries {
		if q.Names == nil {
			continue
		}
		if !slices.Equal(q.Names, []string{"search.sort"}) || q.Instance != "magic" || !q.To.Equal(loaderTestDay) || q.Days != 30 || !q.Signed || !q.Humans {
			t.Errorf("query %+v", q)
		}
	}
	// A name with only "" values and scopes has no breakdowns.
	store = newFakeMetrics()
	store.named = []observability.DayTotal{{Period: 0, Name: "arbit.view", N: 5, Days: 1}}
	v = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 30, Name: "arbit.view"})
	if v.Feature.Total != 5 || v.Feature.Values != nil || v.Feature.Scopes != nil {
		t.Errorf("blank breakdowns: %+v", v.Feature)
	}
}

func TestFeatureAreaViewListsItsNames(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Value: "alpha", N: 5, Days: 20},
		{Period: 0, Name: "search.result", Value: "found", N: 1000, Days: 30},
	}
	store.named = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Value: "alpha", N: 3, Days: 1},
		{Period: 2, Name: "search.sort", Value: "alpha", N: 2, Days: 1},
	}
	p := metricsParams{View: "feature", Instance: "magic", Days: 30, Area: "search"}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), p)
	f := v.Feature
	var got []string
	for _, r := range f.Names {
		got = append(got, r.Name)
	}
	if f.Area != "search" || !slices.Equal(got, []string{"search.sort", "search.filter", "search.result"}) {
		t.Fatalf("area %q names %v", f.Area, got)
	}
	sort := f.Names[0]
	if !sort.Counted || sort.Count != 5 || sort.Denom != 1000 || sort.RateText != "0.50% of results page views" || sort.Help == "" ||
		sort.SparkID != "metrics-spark-0" || sort.URL != "?page=metrics&view=feature&days=30&name=search.sort" {
		t.Errorf("search.sort row = %+v", sort)
	}
	spark, ok := chartByID(v, "metrics-spark-0")
	if !ok || spark.Kind != "spark" || len(spark.Labels) != 30 || spark.Series[0].Data[29] != 3 || spark.Series[0].Data[27] != 2 {
		t.Errorf("spark = %+v", spark)
	}
	if len(v.Charts) != 3 {
		t.Errorf("%d charts, want one a name", len(v.Charts))
	}
	i := slices.IndexFunc(store.queries, func(q observability.DayQuery) bool { return q.Names != nil })
	if i < 0 || !slices.Equal(store.queries[i].Names, []string{"search.sort", "search.filter", "search.result"}) || store.queries[i].Step != 1 {
		t.Errorf("area query = %+v", store.queries)
	}
	if !slices.Contains(v.Notes, "Controls: not measured yet.") {
		t.Errorf("notes %v, the area page loaded the bundle", v.Notes)
	}

	// Before a fold the rows are listed, not counted.
	store = newFakeMetrics()
	store.folded, store.through = false, time.Time{}
	v = loadTestView(t, store, testCache(store), featureTestRegistry(), p)
	if len(v.Feature.Names) != 3 || v.Feature.Names[0].Counted || store.dayTotalCount() != 0 || len(v.Notes) != 0 {
		t.Errorf("before a fold: %+v, %d queries", v.Feature.Names, store.dayTotalCount())
	}
}

func TestFeatureIndexListsEveryArea(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{{Period: 0, Name: "search.sort", Value: "alpha", N: 7, Days: 3}}
	p := metricsParams{View: "feature", Instance: "magic", Days: 90}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), p)
	f := v.Feature
	if !f.Counted || len(f.Areas) == 0 || f.Areas[0].Area != "search" || f.Areas[0].Events != 7 || f.Areas[0].URL != "?page=metrics&view=feature&area=search" {
		t.Errorf("areas = %+v", f.Areas)
	}
	all := map[string]bool{}
	for _, a := range append(slices.Clone(f.Areas), f.OtherAreas...) {
		if all[a.Area] {
			t.Errorf("%q listed twice", a.Area)
		}
		all[a.Area] = true
	}
	for _, n := range featureTestRegistry() {
		if n.Area != "" && !all[n.Area] {
			t.Errorf("area %q is not reachable from the index", n.Area)
		}
	}
	store = newFakeMetrics()
	store.folded = false
	v = loadTestView(t, store, testCache(store), featureTestRegistry(), p)
	if v.Feature.Counted || len(v.Feature.Areas) == 0 || v.Feature.Areas[0].Events != 0 || store.dayTotalCount() != 0 {
		t.Errorf("before a fold: %+v", v.Feature)
	}
}

// Crafted names and areas are validated before a query or a cache key.
func TestUnknownNamesNeverReachTheStore(t *testing.T) {
	withMetricsInstance(t, "magic")
	registered := map[string]bool{}
	names := featureTestRegistry()
	for _, n := range names {
		registered[n.Name] = true
	}
	for _, c := range []struct {
		label string
		v     url.Values
		stray bool // names a real registry name this registry lacks
	}{
		{"sql", url.Values{"name": {"search.sort'; DROP TABLE feature_days; --"}}, false},
		{"long", url.Values{"name": {strings.Repeat("x", 5000)}}, false},
		{"a name of another registry", url.Values{"name": {"http.status"}}, true},
		{"a crafted area", url.Values{"area": {"search' OR 1=1"}}, false},
	} {
		for _, view := range []string{"feature", "explore"} {
			t.Run(c.label+"/"+view, func(t *testing.T) {
				c.v.Set("view", view)
				c.v.Set("hourly", "1")
				p := readMetricsParams(c.v.Get, []string{"magic"})
				store := newFakeMetrics()
				cache := testCache(store)
				v := loadTestView(t, store, cache, names, p)
				for _, n := range queriedNames(store) {
					if !registered[n] {
						t.Errorf("%q reached the store", n)
					}
				}
				if len(store.hourCalls) != 0 {
					t.Errorf("hour calls %+v", store.hourCalls)
				}
				asked := c.v.Get("name") != ""
				noSuch := (v.Feature != nil && v.Feature.NoSuchName) || (v.Explore != nil && v.Explore.NoSuchName)
				if noSuch != asked || (asked && !c.stray && !p.UnknownName) {
					t.Errorf("no such name %v, unknown %v", noSuch, p.UnknownName)
				}
				if p.Area != "" {
					t.Errorf("area %q accepted", p.Area)
				}
			})
		}
	}
}

// stockFixture is stock.rows on the newest day (period 1 from today) and an older day.
func stockFixture() []observability.DayTotal {
	older := loaderTestDay.AddDate(0, 0, -1)
	return []observability.DayTotal{
		{Period: 1, Name: "stock.rows", Scope: "magic", N: 300, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Period: 1, Name: "stock.rows", Scope: "lorcana", N: 100, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Period: 2, Name: "stock.rows", Scope: "magic", N: 250, Days: 1, First: older, Last: older},
		{Period: 2, Name: "stock.rows", Scope: "pokemon", N: 999, Days: 1, First: older, Last: older},
	}
}

// M2: a stored-state name is its newest day under shared on Feature, an area page and Explore.
func TestStockNameIsTheNewestDayOnEveryView(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := featureTestRegistry()
	sharedOnly := func(t *testing.T, store *fakeMetricsStore) {
		t.Helper()
		for _, q := range store.queries {
			if slices.Contains(q.Names, "stock.rows") && (q.Instance != observability.SharedInstance || q.Signed || q.Humans || !q.To.Equal(utcDay(loaderTestNow)) || q.Step != 1) {
				t.Errorf("stock query %+v", q)
			}
		}
	}
	// Feature by name, for another instance: still read under shared.
	store := newFakeMetrics()
	store.stock = stockFixture()
	v := loadTestView(t, store, testCache(store), names, metricsParams{View: "feature", Instance: "lorcana", Days: 30, Name: "stock.rows"})
	f := v.Feature
	if !f.Standing || f.Total != 400 || !f.StockDay.Equal(loaderTestDay) || len(f.Scopes) != 2 || f.Scopes[0].Label != "magic" || f.Scopes[0].Share != 0.75 || f.Tiers != nil || f.Devices != nil {
		t.Errorf("feature = %+v", f)
	}
	if c, ok := chartByID(v, "metrics-days"); !ok || c.Labels[len(c.Labels)-1] != "2026-11-10" || c.Series[0].Data[len(c.Labels)-1] != 400 || c.Series[0].Data[len(c.Labels)-2] != 1249 {
		t.Errorf("stock line = %+v", c)
	}
	sharedOnly(t, store)
	if slices.ContainsFunc(store.queries, func(q observability.DayQuery) bool { return q.ByTier || q.ByDevice }) {
		t.Error("a stored-state name was split by tier or device")
	}

	// The area page: the stock row is its newest day, not a sum and not 0.
	store = newFakeMetrics()
	store.stock = stockFixture()
	v = loadTestView(t, store, testCache(store), names, metricsParams{View: "feature", Instance: "magic", Days: 30, Area: "account"})
	i := slices.IndexFunc(v.Feature.Names, func(r MetricsNameRow) bool { return r.Name == "stock.rows" })
	if i < 0 {
		t.Fatalf("names = %+v", v.Feature.Names)
	}
	row := v.Feature.Names[i]
	if !row.Standing || !row.Counted || row.Count != 400 || !row.Day.Equal(loaderTestDay) || row.RateText != "" || row.SparkID == "" {
		t.Errorf("stock row = %+v", row)
	}
	sharedOnly(t, store)

	// Explore, asked by hour: by day, newest day only, no minute rows read.
	store = newFakeMetrics()
	store.stock = stockFixture()
	v = loadTestView(t, store, testCache(store), names, metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "stock.rows", Hourly: true})
	e := v.Explore
	if e.Hourly || e.HourlyLink != (MetricsLink{}) || len(store.hourCalls) != 0 || e.Total != 400 || len(e.Rows) != 2 ||
		e.Rows[0] != (MetricsExploreRow{Scope: "magic", N: 300, Share: 0.75}) || !e.StockDay.Equal(loaderTestDay) {
		t.Errorf("explore = %+v", e)
	}
	sharedOnly(t, store)

	// With no stock rows: nothing, and no chart.
	store = newFakeMetrics()
	v = loadTestView(t, store, testCache(store), names, metricsParams{View: "feature", Instance: "magic", Days: 30, Name: "stock.rows"})
	if v.Feature.HasRows || v.Feature.Total != 0 || len(v.Charts) != 0 || v.Feature.Values != nil {
		t.Errorf("no stock rows: %+v, charts %d", v.Feature, len(v.Charts))
	}
}

func TestExploreNamesComeFromTheRegistry(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	v := loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "explore", Instance: "magic", Days: 90})
	seen := map[string]int{}
	for _, g := range v.Explore.Groups {
		if g.Label == "" || !strings.Contains(g.Label, ": ") {
			t.Errorf("group label %q", g.Label)
		}
		for _, n := range g.Names {
			seen[n.Label]++
			if n.URL != "?page=metrics&view=explore&name="+url.QueryEscape(n.Label) {
				t.Errorf("link %q", n.URL)
			}
		}
	}
	for _, n := range observability.All() {
		if seen[n.Name] != 1 {
			t.Errorf("%s listed %d times", n.Name, seen[n.Name])
		}
	}
	if len(seen) != len(observability.All()) {
		t.Errorf("%d names listed, %d registered", len(seen), len(observability.All()))
	}
	if store.dayTotalCount() != 0 || len(store.hourCalls) != 0 || v.Explore.Rows != nil {
		t.Errorf("no name, yet %d queries", store.dayTotalCount())
	}
	if g := v.Explore.Groups[0]; g.Label != "Server: no area" {
		t.Errorf("first group %q", g.Label)
	}
	want := []MetricsField{{"page", "metrics"}, {"view", "explore"}}
	if !slices.Equal(v.Explore.Hidden, want) {
		t.Errorf("hidden = %+v", v.Explore.Hidden)
	}
	p := metricsParams{View: "explore", Instance: "lorcana", Days: 30, Bots: true, Hourly: true}
	if got := metricsHidden(p); !slices.Equal(got, append(want, MetricsField{"bots", "1"}, MetricsField{"days", "30"}, MetricsField{"hourly", "1"}, MetricsField{"instance", "lorcana"})) {
		t.Errorf("hidden = %+v", got)
	}
}

func TestExploreRowsByDay(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.named = []observability.DayTotal{
		{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 10, Days: 1},
		{Period: 5, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 20, Days: 1},
		{Period: 1, Name: "auth.refuse", Scope: "arbit", Value: "no_access", N: 10, Days: 1},
	}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "auth.refuse"})
	e := v.Explore
	if e.Total != 40 || len(e.Rows) != 2 || e.Rows[0] != (MetricsExploreRow{Scope: "search", Value: "no_access", N: 30, Share: 0.75}) || e.Help != "Requests refused at the door." {
		t.Errorf("explore = %+v", e)
	}
	c, ok := chartByID(v, "metrics-explore")
	if !ok || e.LineID != "metrics-explore" || len(c.Labels) != 90 || c.Series[0].Data[89] != 10 || c.Series[0].Data[84] != 20 {
		t.Errorf("chart = %+v", c)
	}
	if e.HourlyLink.Active || e.HourlyLink.URL != "?page=metrics&view=explore&hourly=1&name=auth.refuse" || e.FeatureURL != "?page=metrics&view=feature&name=auth.refuse" {
		t.Errorf("links %+v %q", e.HourlyLink, e.FeatureURL)
	}
	// The picker keeps the name; a tab does not.
	if v.Windows[0].URL != "?page=metrics&view=explore&days=30&name=auth.refuse" || v.Views[0].URL != "?page=metrics&view=overview" {
		t.Errorf("windows %+v", v.Windows)
	}
}

// S1 and the hourly bounds: minute rows of one name, 14 days of hours, at most a minute old.
func TestExploreHourlyBounds(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	since := time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC)
	store.hours = []observability.HourTotal{
		{Hour: since.Add(-time.Hour), Scope: "search", Value: "no_access", N: 1000}, // before the window
		{Hour: since, Scope: "search", Value: "no_access", N: 3},
		{Hour: since.Add(10 * time.Hour), Scope: "arbit", Value: "other", N: 1},
		{Hour: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), Scope: "search", Value: "no_access", N: 5},
		{Hour: time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC), Scope: "search", Value: "no_access", N: 1000}, // after now's hour
	}
	clock := &testClock{t: loaderTestNow}
	cache := metricsreport.NewCache(store.FoldStamp, clock.now)
	p := metricsParams{View: "explore", Instance: "lorcana", Days: 180, Anon: true, Name: "auth.refuse", Hourly: true}
	load := func() *MetricsView {
		t.Helper()
		return loadMetricsViewFor(context.Background(), store, cache, featureTestRegistry(), metricsTestLists, p, clock.now())
	}
	v := load()
	if len(store.hourCalls) != 1 {
		t.Fatalf("hour calls %+v", store.hourCalls)
	}
	call := store.hourCalls[0]
	if !call.since.Equal(since) || call.q.Instance != "lorcana" || !slices.Equal(call.q.Names, []string{"auth.refuse"}) || call.q.Signed || !call.q.Humans {
		t.Errorf("hour call %+v", call)
	}
	if store.dayTotalCount() != 0 {
		t.Errorf("the hourly view read %d day queries", store.dayTotalCount())
	}
	e := v.Explore
	c, ok := chartByID(v, "metrics-explore")
	if !e.Hourly || !e.HoursFrom.Equal(since) || !ok || len(c.Labels) != 14*24 || c.Labels[0] != "2026-10-28 13:00" || c.Labels[len(c.Labels)-1] != "2026-11-11 12:00" {
		t.Fatalf("hourly %v from %v, labels %d", e.Hourly, e.HoursFrom, len(c.Labels))
	}
	d := c.Series[0].Data
	if d[0] != 3 || d[10] != 1 || d[len(d)-1] != 5 || e.Total != 9 || len(e.Rows) != 2 || e.Rows[0].N != 8 {
		t.Errorf("data %v..%v, total %d, rows %+v", d[:11], d[len(d)-1], e.Total, e.Rows)
	}
	if !e.HourlyLink.Active || e.HourlyLink.URL != "?page=metrics&view=explore&anon=1&days=180&instance=lorcana&name=auth.refuse" {
		t.Errorf("hourly link %+v", e.HourlyLink)
	}
	clock.add(59 * time.Second)
	load()
	if len(store.hourCalls) != 1 {
		t.Errorf("at 59 s: %d hour calls", len(store.hourCalls))
	}
	clock.add(2 * time.Second)
	load()
	if len(store.hourCalls) != 2 {
		t.Errorf("at 61 s: %d hour calls", len(store.hourCalls))
	}
	// Before any fold the minute rows still read.
	store = newFakeMetrics()
	store.folded = false
	if v := loadTestView(t, store, testCache(store), featureTestRegistry(), p); len(store.hourCalls) != 1 || v.Explore.LineID == "" {
		t.Errorf("before a fold: %d hour calls", len(store.hourCalls))
	}
}

func TestHealthListsEveryRegisteredJob(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	early, late := loaderTestNow.Add(-3*time.Hour), loaderTestNow.Add(-2*time.Hour)
	store.jobs = []observability.JobRun{
		{Instance: "magic", Job: "fold", Result: "ok", At: early},
		{Instance: "lorcana", Job: "fold", Result: "ok", At: late},
	}
	v := loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "health", Instance: "magic", Days: 90})
	h := v.Health
	jr, ok := observability.Lookup("job.run")
	if !ok {
		t.Fatal("job.run is not registered")
	}
	var jobs []string
	for _, j := range h.Jobs {
		jobs = append(jobs, j.Job)
	}
	if !slices.Equal(jobs, jr.Scopes) {
		t.Fatalf("jobs %v, want %v", jobs, jr.Scopes)
	}
	fold := h.Jobs[0]
	if fold.Instance != "lorcana" || fold.Result != "ok" || !fold.At.Equal(late) || !fold.LastOK.Equal(late) || !slices.Equal(fold.Runners, []string{"lorcana", "magic"}) {
		t.Errorf("fold = %+v", fold)
	}
	for _, j := range h.Jobs[1:] {
		if !j.At.IsZero() || j.Result != "" || j.Instance != "" || !slices.Contains(h.Problems, "Job "+j.Job+": no run in 14 days") {
			t.Errorf("%s = %+v, problems %v", j.Job, j, h.Problems)
		}
	}
	// L10: the stock job says it is scheduled only with the user-state database.
	if i := slices.IndexFunc(h.Jobs, func(j MetricsJobRow) bool { return j.Job == "stock" }); i < 0 || h.Jobs[i].Note != metricsreport.JobNote("stock") || h.Jobs[i].Note == "" {
		t.Errorf("stock note: %+v", h.Jobs)
	}
	if slices.ContainsFunc(h.Problems, func(s string) bool { return strings.HasPrefix(s, "Job fold") }) {
		t.Errorf("an ok fold two hours ago is a problem: %v", h.Problems)
	}
	// A failed newest run is the row; with no job.run name there are no job rows or job lines.
	store.jobs = append(store.jobs, observability.JobRun{Instance: "lorcana", Job: "fold", Result: "fail", At: loaderTestNow.Add(-time.Hour)})
	h = loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	if h.Jobs[0].Result != "fail" || !h.Jobs[0].LastOK.Equal(late) {
		t.Errorf("failed fold = %+v", h.Jobs[0])
	}
	var noJobs []observability.Name
	for _, n := range featureTestRegistry() {
		if n.Name != "job.run" {
			noJobs = append(noJobs, n)
		}
	}
	h = loadTestView(t, store, testCache(store), noJobs, metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	if len(h.Jobs) != 0 || slices.ContainsFunc(h.Problems, func(s string) bool { return strings.HasPrefix(s, "Job ") }) {
		t.Errorf("no job.run: jobs %+v, problems %v", h.Jobs, h.Problems)
	}
}

func TestHealthShowsEveryInstanceCounter(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.health = []observability.InstanceHealth{
		{Instance: ""}, {Instance: "lorcana", LastFlush: loaderTestNow.Add(-time.Minute), Rejected: 9},
		{Instance: "magic", LastFlush: loaderTestNow.Add(-time.Hour), Dropped: 2, Rejected: 4}, {Instance: observability.SharedInstance},
	}
	h := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "lorcana", Days: 90}).Health
	if len(h.Counters) != 2 || h.Counters[0].Instance != "lorcana" || !h.Counters[0].Current || !h.Counters[0].Live || h.Counters[1].Current || h.Counters[1].Live || h.Counters[1].Dropped != 2 {
		t.Errorf("counters = %+v", h.Counters)
	}
	if h.Rejected != 9 || h.CountersRead.Failed {
		t.Errorf("rejected %d, read %+v", h.Rejected, h.CountersRead)
	}
	// Problems are the instance's own counter lines.
	if slices.ContainsFunc(h.Problems, func(s string) bool { return strings.HasPrefix(s, "Counters") }) {
		t.Errorf("lorcana flushed a minute ago: %v", h.Problems)
	}
}

// Health reads neither the toggles nor the window.
func TestHealthIsTheSameWhateverTheToggles(t *testing.T) {
	withMetricsInstance(t, "magic")
	var first string
	var firstQueries []observability.DayQuery
	for _, p := range []metricsParams{
		{View: "health", Instance: "magic", Days: 90},
		{View: "health", Instance: "magic", Days: 30, Anon: true, Bots: true},
		{View: "health", Instance: "magic", Days: 180, Anon: true},
	} {
		store := newFakeMetrics()
		store.totals = []observability.DayTotal{{Period: 0, Name: "page.view", Value: "arbit", N: 5, Days: 3}}
		store.health = []observability.InstanceHealth{{Instance: "magic", LastFlush: loaderTestNow.Add(-time.Minute)}}
		store.jobs = []observability.JobRun{{Instance: "magic", Job: "fold", Result: "ok", At: loaderTestNow.Add(-time.Hour)}}
		store.client = []observability.DayTotal{{Name: "metrics.beacon", Value: "ok", N: 3}}
		v := loadTestView(t, store, testCache(store), beaconTestRegistry(), p)
		got := fmt.Sprintf("%+v", *v.Health)
		if first == "" {
			first, firstQueries = got, slices.Clone(store.queries)
			if len(v.Health.Broken) != 1 || len(v.Health.Client) != 1 || !v.Health.ClientCounted {
				t.Fatalf("broken = %+v, client %+v", v.Health.Broken, v.Health.Client)
			}
			continue
		}
		if got != first {
			t.Errorf("%+v:\n%s\nwant\n%s", p, got, first)
		}
		if !slices.EqualFunc(store.queries, firstQueries, func(a, b observability.DayQuery) bool {
			return a.Instance == b.Instance && a.To.Equal(b.To) && a.Days == b.Days && a.Step == b.Step &&
				a.Signed == b.Signed && a.Humans == b.Humans && slices.Equal(a.Names, b.Names)
		}) {
			t.Errorf("%+v: queries %+v, want %+v", p, store.queries, firstQueries)
		}
	}
}

// Silent judges its every-view counts over every reader, whatever the toggles.
func TestHealthBrokenAndQuietFromSilent(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{{Period: 0, Name: "page.view", Value: "reverse", N: 5, Days: 3}}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 30, Anon: false})
	h := v.Health
	if !h.SilentCounted || h.SilentRead.Failed {
		t.Fatalf("silent counted %v, read %+v", h.SilentCounted, h.SilentRead)
	}
	if !slices.Equal(h.Broken, []MetricsNameLink{{Name: "arbit.view", Help: "An arbit page view.", URL: "?page=metrics&view=feature&name=arbit.view"}}) {
		t.Errorf("broken = %+v", h.Broken)
	}
	if len(h.Quiet) != 1 || h.Quiet[0].Name != "news.report" || h.Quiet[0].Help == "" {
		t.Errorf("quiet = %+v", h.Quiet)
	}
	if !slices.Contains(h.Problems, "1 count missing for 30 days although its pages were used") {
		t.Errorf("problems = %v", h.Problems)
	}
	i := slices.IndexFunc(store.queries, func(q observability.DayQuery) bool { return q.Step == 30 })
	if i < 0 || store.queries[i].Signed || store.queries[i].Humans || store.queries[i].Days != 30 || store.queries[i].Names != nil {
		t.Errorf("silent query = %+v", store.queries)
	}
	if len(v.Coverage) != 0 || len(v.Notes) != 0 {
		t.Errorf("health noted coverage it did not load: %v", v.Notes)
	}
	// Before a fold: counters and jobs, nothing judged.
	store = newFakeMetrics()
	store.folded = false
	h = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	if h.SilentCounted || h.SilentRead.Failed || h.Broken != nil || store.dayTotalCount() != 0 || store.healthCalls != 1 || len(h.Jobs) != 3 {
		t.Errorf("before a fold: %+v, %d queries", h, store.dayTotalCount())
	}
}

// L14: the beacon reasons, with an injected registry.
func TestHealthClientRowsAreReasons(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := beaconTestRegistry()
	store := newFakeMetrics()
	store.client = []observability.DayTotal{
		{Name: "metrics.client", Value: "unknown", N: 50},
		{Name: "metrics.beacon", Value: "bad_body", N: 10},
		{Name: "metrics.client", Value: "accepted", N: 950},
		{Name: "metrics.beacon", Value: "ok", N: 90},
	}
	h := loadTestView(t, store, testCache(store), names, metricsParams{View: "health", Instance: "magic", Days: 90, Anon: true}).Health
	want := []MetricsClientRow{
		{Name: "metrics.beacon", Reason: "ok", Help: "Beacon posts, by outcome.", N: 90, Share: 0.9},
		{Name: "metrics.beacon", Reason: "bad_body", Help: "Beacon posts, by outcome.", N: 10, Share: 0.1},
		{Name: "metrics.client", Reason: "accepted", Help: "Client counts, by outcome.", N: 950, Share: 0.95},
		{Name: "metrics.client", Reason: "unknown", Help: "Client counts, by outcome.", N: 50, Share: 0.05},
	}
	if !h.ClientMeasured || !slices.Equal(h.Client, want) {
		t.Errorf("client = %+v", h.Client)
	}
	i := slices.IndexFunc(store.queries, func(q observability.DayQuery) bool { return slices.Contains(q.Names, "metrics.beacon") })
	if i < 0 {
		t.Fatalf("no client query: %+v", store.queries)
	}
	q := store.queries[i]
	if !slices.Equal(q.Names, []string{"metrics.beacon", "metrics.client"}) || q.Signed || q.Humans || q.Days != 7 || !q.To.Equal(loaderTestDay) || q.Instance != "magic" {
		t.Errorf("client query = %+v", q)
	}
	store.client = nil
	if h := loadTestView(t, store, testCache(store), names, metricsParams{View: "health", Instance: "magic", Days: 90}).Health; len(h.Client) != 0 {
		t.Errorf("no rows: %+v", h.Client)
	}
	// Before 2a registers the beacon: not measured, no query.
	store = newFakeMetrics()
	h = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	if h.ClientMeasured || h.Client != nil || slices.ContainsFunc(store.queries, func(q observability.DayQuery) bool { return q.Names != nil }) || h.ScriptErrors != nil {
		t.Errorf("no beacon: %+v", h)
	}
}

// Each failed read sets its flag and message; the view still renders.
func TestFeatureHealthExploreFailedReads(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := append(featureTestRegistry(), observability.Name{Name: "metrics.beacon", Values: observability.ValueEnum, Enum: []string{"ok"}, Report: observability.ReportInternal})
	failed := MetricsRead{Failed: true, Message: metricsReadFailedText}
	for _, c := range []struct {
		label string
		p     metricsParams
		read  func(*MetricsView) []MetricsRead
	}{
		{"feature name", metricsParams{Name: "search.sort"}, func(v *MetricsView) []MetricsRead {
			return []MetricsRead{v.Feature.Read, v.Feature.TiersRead, v.Feature.DevicesRead}
		}},
		{"feature area", metricsParams{Area: "search"}, func(v *MetricsView) []MetricsRead { return []MetricsRead{v.Feature.Read} }},
		{"feature index", metricsParams{}, func(v *MetricsView) []MetricsRead { return []MetricsRead{v.Feature.Read} }},
		{"explore", metricsParams{View: "explore", Name: "auth.refuse"}, func(v *MetricsView) []MetricsRead { return []MetricsRead{v.Explore.Read} }},
		{"health", metricsParams{View: "health"}, func(v *MetricsView) []MetricsRead { return []MetricsRead{v.Health.SilentRead, v.Health.ClientRead} }},
	} {
		store := newFakeMetrics()
		store.totalsErr = errors.New("database down")
		p := c.p
		if p.View == "" {
			p.View = "feature"
		}
		p.Instance, p.Days = "magic", 90
		v := loadTestView(t, store, testCache(store), names, p)
		for i, r := range c.read(v) {
			if r != failed {
				t.Errorf("%s: read %d = %+v", c.label, i, r)
			}
		}
		if !v.Failed || len(v.Charts) != 0 {
			t.Errorf("%s: failed %v, charts %d", c.label, v.Failed, len(v.Charts))
		}
	}
	// Minute rows: counters and job runs, then the hours.
	store := newFakeMetrics()
	store.healthErr = errors.New("down")
	h := loadTestView(t, store, testCache(store), names, metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	if h.CountersRead != failed || h.Jobs != nil || h.Problems != nil || h.Counters != nil {
		t.Errorf("health read failed: %+v", h)
	}
	store = newFakeMetrics()
	store.hoursErr = errors.New("down")
	cache := testCache(store)
	v := loadTestView(t, store, cache, names, metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "auth.refuse", Hourly: true})
	if v.Explore.Read != failed || !v.Failed || v.Explore.LineID != "" {
		t.Errorf("hours failed: %+v", v.Explore)
	}
	// A failure is not cached: the next request, on the same cache, reads again.
	store.hoursErr = nil
	if v := loadTestView(t, store, cache, names, metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "auth.refuse", Hourly: true}); v.Explore.Read.Failed || v.Failed || len(store.hourCalls) != 2 {
		t.Errorf("after the error cleared: %+v, %d hour calls", v.Explore.Read, len(store.hourCalls))
	}
}

func TestPickersKeepTheFeatureName(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 90, Name: "search.sort"})
	if v.Windows[0].URL != "?page=metrics&view=feature&days=30&name=search.sort" || v.BotsLink.URL != "?page=metrics&view=feature&bots=1&name=search.sort" {
		t.Errorf("windows %+v, bots %+v", v.Windows, v.BotsLink)
	}
	v = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 90, Area: "search"})
	if v.AnonLink.URL != "?page=metrics&view=feature&anon=1&area=search" {
		t.Errorf("anon %+v", v.AnonLink)
	}
	v = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "auth.refuse", Hourly: true})
	if len(v.Instances) == 0 || v.Instances[0].URL != "?page=metrics&view=explore&hourly=1&instance=lorcana&name=auth.refuse" {
		t.Errorf("instances %+v", v.Instances)
	}
}

func TestReadMetricsParamsMarksAnUnknownName(t *testing.T) {
	withMetricsInstance(t, "magic")
	for v, want := range map[string]bool{"": false, "search.sort": false, "nope": true, "page.view' --": true} {
		p := readMetricsParams(url.Values{"name": {v}}.Get, nil)
		if p.UnknownName != want || (want && p.Name != "") {
			t.Errorf("name %q: %+v", v, p)
		}
	}
}

// An empty list is a finding only when the counts were read; the views say which.
func TestMetricsViewsSayWhetherTheyCounted(t *testing.T) {
	withMetricsInstance(t, "magic")
	counted := func(v *MetricsView) (bool, MetricsRead) {
		switch {
		case v.Remove != nil:
			return v.Remove.Counted, v.Remove.Read
		case v.Invest != nil:
			return v.Invest.Counted, v.Invest.Read
		}
		return v.Overview.Counted, v.Overview.Read
	}
	cases := []struct {
		name          string
		set           func(*fakeMetricsStore)
		count, failed bool
	}{
		{"counted", func(*fakeMetricsStore) {}, true, false},
		{"nothing complete", func(f *fakeMetricsStore) { f.folded = false }, false, false},
		{"counts failed", func(f *fakeMetricsStore) { f.totalsErr = errors.New("down") }, false, true},
		{"day unknown", func(f *fakeMetricsStore) { f.throughErr = errors.New("down") }, false, true},
	}
	for _, view := range []string{"overview", "remove", "invest"} {
		for _, c := range cases {
			store := newFakeMetrics()
			store.totals = removeFixture()
			c.set(store)
			v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: view, Instance: "magic", Days: 90})
			n, read := counted(v)
			if n != c.count || read.Failed != c.failed || (read.Failed && read.Message != metricsReadFailedText) {
				t.Errorf("%s, %s: counted %v, read %+v", view, c.name, n, read)
			}
		}
	}
}

func TestOverviewSaysWhetherStoredStateWasRead(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "overview", Instance: "magic", Days: 90}
	store := newFakeMetrics()
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p); v.Overview.StockRead.Failed {
		t.Error("an answered stock read is marked failed")
	}
	store = newFakeMetrics()
	store.totalsErr = errors.New("down")
	if v := loadTestView(t, store, testCache(store), metricsTestRegistry(), p); !v.Overview.StockRead.Failed {
		t.Error("a failed stock read is not marked")
	}
	noStock := slices.DeleteFunc(metricsTestRegistry(), func(n observability.Name) bool { return n.Family == observability.FamilyStock })
	if v := loadTestView(t, store, testCache(store), noStock, p); v.Overview.StockRead.Failed {
		t.Error("a registry with no stored-state name reads as a failed stock read")
	}
}

func TestMetricsReasonSaysWhyARowIsNotMeasured(t *testing.T) {
	cases := []struct {
		c    metricsreport.Candidate
		want string
	}{
		{metricsreport.Candidate{Class: metricsreport.ClassNotMeasured, On: metricsreport.CountedOn{Kind: metricsreport.OnNoRows}}, "No rows for this metric on this site in the window."},
		{metricsreport.Candidate{Class: metricsreport.ClassNotMeasured, On: onPages("search"), DaysMeasured: 9},
			fmt.Sprintf("9 days measured, %d needed; counted on views of the search page", metricsreport.MinDaysMeasured)},
		{metricsreport.Candidate{Class: metricsreport.ClassUnused, On: onPages("search"), DaysMeasured: 90}, ""},
	}
	for _, c := range cases {
		if got := metricsReason(c.c); got != c.want {
			t.Errorf("metricsReason(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

// onPages is what a candidate counted on views of the comma list pages is counted on.
func onPages(pages string) metricsreport.CountedOn {
	return metricsreport.CountedOn{Kind: metricsreport.OnPages, Pages: pages}
}

func TestMetricsBasisWords(t *testing.T) {
	scripts := func(on metricsreport.CountedOn) metricsreport.CountedOn { on.Scripts = true; return on }
	cases := []struct {
		on   metricsreport.CountedOn
		want string
	}{
		{metricsreport.CountedOn{Kind: metricsreport.OnFlushDays}, "days the counter ran"},
		{scripts(metricsreport.CountedOn{Kind: metricsreport.OnFlushDays}), "days the counter ran and a page loaded its scripts"},
		{metricsreport.CountedOn{Kind: metricsreport.OnEveryPage}, "views of every page"},
		{scripts(metricsreport.CountedOn{Kind: metricsreport.OnEveryPage}), "page loads with scripts, on every page"},
		{onPages("search"), "views of the search page"},
		{onPages("alerts,search"), "views of the alerts and search pages"},
		{scripts(onPages("arbit,global,reverse")), "page loads with scripts on the arbit, global and reverse pages"},
		{metricsreport.CountedOn{Kind: metricsreport.OnDenom, Name: "upload.mode"}, "priced upload views"},
		{metricsreport.CountedOn{Kind: metricsreport.OnDenom, Name: "search.result"}, "results page views"},
		{metricsreport.CountedOn{Kind: metricsreport.OnDenom, Name: "some.new_name"}, "some.new_name"},
		{metricsreport.CountedOn{Kind: metricsreport.OnNoRows}, "no rows for this metric on this site in the window"},
	}
	for _, tc := range cases {
		if got := metricsBasisWords(tc.on); got != tc.want {
			t.Errorf("metricsBasisWords(%+v) = %q, want %q", tc.on, got, tc.want)
		}
	}
	// every kind the package gives has its words, whatever its Basis sentence says
	for _, n := range observability.All() {
		for _, c := range metricsreport.Remove(metricsreport.Expand([]observability.Name{n}, metricsTestLists), nil, nil, nil, metricsreport.Window{Days: 30}) {
			if got := metricsBasisWords(c.On); got == "nothing named" || got == "" {
				t.Errorf("%s %s %s: no words for %+v", c.Name, c.Scope, c.Value, c.On)
			}
		}
	}
}

func TestMetricsRateWords(t *testing.T) {
	for text, want := range map[string]string{
		"0.00% of search.result":                                  "0.00% of results page views",
		"0.50% of upload.mode (of a wider population; see help)":  "0.50% of priced upload views (of a wider population; see help)",
		"0.8 per 1,000 api.call":                                  "0.8 per 1,000 price API calls",
		"1.25% of requests":                                       "1.25% of requests",
		"0.8 per 1,000 loads":                                     "0.8 per 1,000 loads",
		"0.10% of no.such.name":                                   "0.10% of no.such.name",
		"0.10% of no.such.name (of a wider population; see help)": "0.10% of no.such.name (of a wider population; see help)",
		"search.result":                                           "search.result",
		"":                                                        "",
	} {
		if got := metricsRateWords(text); got != want {
			t.Errorf("metricsRateWords(%q) = %q, want %q", text, got, want)
		}
	}
	// the candidate rows and the area page print the words
	r := metricsCandidateRow(metricsreport.Candidate{Name: "search.sort", RateText: "0.00% of search.result"}, nil, 60, metricsParams{View: "remove"})
	if r.RateText != "0.00% of results page views" {
		t.Errorf("candidate rate %q", r.RateText)
	}
}

func TestMetricsCandidateRowLinksAndWords(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "overview", Instance: "magic", Days: 30}
	c := metricsreport.Candidate{Name: "search.sort", Scope: "Search Page", Value: `a"b<c>`, Denom: 305, On: metricsreport.CountedOn{Kind: metricsreport.OnEveryPage}}
	r := metricsCandidateRow(c, nil, 60, p)
	if r.Anchor != "rm-search.sort--search_page--a_b_c_" {
		t.Errorf("anchor %q", r.Anchor)
	}
	if r.RemoveURL != "?page=metrics&view=remove&days=30#"+r.Anchor {
		t.Errorf("remove link with no area %q", r.RemoveURL)
	}
	c.Area = "search"
	if r := metricsCandidateRow(c, nil, 60, p); r.RemoveURL != "?page=metrics&view=remove&area=search&days=30#"+r.Anchor {
		t.Errorf("remove link %q", r.RemoveURL)
	}
	c.Area = ""
	if r.OutOf != "305 views of every page" || r.CountedOn != "views of every page" {
		t.Errorf("out of %q, counted on %q", r.OutOf, r.CountedOn)
	}
	c.Denom, c.On = 0, metricsreport.CountedOn{Kind: metricsreport.OnFlushDays}
	if r := metricsCandidateRow(c, nil, 60, p); r.OutOf != "" || r.CountedOn != "days the counter ran" {
		t.Errorf("counted on days: out of %q, counted on %q", r.OutOf, r.CountedOn)
	}
}

func TestMetricsSummaryCountsAnAreaByClass(t *testing.T) {
	row := func(class string) MetricsCandidateRow {
		return MetricsCandidateRow{Candidate: metricsreport.Candidate{Class: class}}
	}
	kinds := []MetricsRemoveKind{
		{Rows: []MetricsCandidateRow{row(metricsreport.ClassUnused), row(metricsreport.ClassUnusedSoFar)}},
		{Rows: []MetricsCandidateRow{row(metricsreport.ClassRare), row(metricsreport.ClassUnused)}},
	}
	if s := metricsSummary(kinds); s != "2 unused, 1 rare, 1 unused so far" {
		t.Errorf("summary %q", s)
	}
	if s := metricsSummary([]MetricsRemoveKind{{Rows: []MetricsCandidateRow{row(metricsreport.ClassUnusedSoFar)}}}); s != "1 unused so far" {
		t.Errorf("unused so far only: summary %q", s)
	}
	areas := []MetricsRemoveArea{{Kinds: kinds}, {Kinds: []MetricsRemoveKind{{Rows: []MetricsCandidateRow{row(metricsreport.ClassRare)}}}}}
	if s := metricsTotal(areas); s != "5 candidates: 2 unused, 2 rare, 1 unused so far" {
		t.Errorf("total %q", s)
	}
	if s := metricsTotal(areas[1:]); s != "1 candidate, rare" {
		t.Errorf("one candidate: total %q", s)
	}
	// W3: one class holding every row is said once
	soFar := []MetricsRemoveArea{{Kinds: []MetricsRemoveKind{{Rows: []MetricsCandidateRow{row(metricsreport.ClassUnusedSoFar), row(metricsreport.ClassUnusedSoFar)}}}}}
	if s := metricsTotal(soFar); s != "2 candidates, all unused so far" {
		t.Errorf("one class: total %q", s)
	}
	if s := metricsTotal(nil); s != "" {
		t.Errorf("no candidates: total %q", s)
	}
}

// One rule: a job's row and its Problems line come from the same judgment.
func TestHealthJobRowsAgreeWithProblems(t *testing.T) {
	withMetricsInstance(t, "magic")
	night := time.Date(2026, 11, 11, 0, 40, 0, 0, time.UTC)
	run := func(inst, result string, at time.Time) observability.JobRun {
		return observability.JobRun{Instance: inst, Job: "fold", Result: result, At: at}
	}
	for _, c := range []struct {
		label  string
		runs   []observability.JobRun
		status string
	}{
		{"an ok and a fail in the same minute", []observability.JobRun{run("magic", "fail", night), run("lorcana", "ok", night)}, metricsreport.JobOK},
		{"a fail after the last ok", []observability.JobRun{run("magic", "ok", night), run("magic", "fail", night.Add(time.Hour))}, metricsreport.JobFailed},
		{"more than one ok a night", []observability.JobRun{run("magic", "ok", night), run("lorcana", "ok", night.Add(time.Minute))}, metricsreport.JobOK},
		{"no run at all", nil, metricsreport.JobNoRun},
		{"an ok exactly at the threshold", []observability.JobRun{run("magic", "ok", loaderTestNow.Add(-metricsreport.StaleJob))}, metricsreport.JobOK},
		{"an ok a second past it", []observability.JobRun{run("magic", "ok", loaderTestNow.Add(-metricsreport.StaleJob-time.Second))}, metricsreport.JobOverdue},
	} {
		store := newFakeMetrics()
		store.jobs = c.runs
		h := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
		if len(h.Jobs) == 0 || h.Jobs[0].Job != "fold" {
			t.Fatalf("%s: jobs %+v", c.label, h.Jobs)
		}
		row := h.Jobs[0]
		listed := slices.ContainsFunc(h.Problems, func(s string) bool { return strings.HasPrefix(s, "Job fold") })
		if row.Status != c.status || (row.Problem == "") != (c.status == metricsreport.JobOK) || listed != (row.Problem != "") ||
			(row.Problem != "" && !slices.Contains(h.Problems, row.Problem)) || row.Threshold != metricsreport.StaleJob {
			t.Errorf("%s: row %+v, problems %v", c.label, row, h.Problems)
		}
	}
}

// beaconTestRegistry is featureTestRegistry with the beacon's two reason names, as 2a will register them.
func beaconTestRegistry() []observability.Name {
	return append(featureTestRegistry(),
		observability.Name{Name: "metrics.beacon", Values: observability.ValueEnum, Enum: []string{"ok", "bad_body", "too_many"}, Report: observability.ReportInternal, Help: "Beacon posts, by outcome."},
		observability.Name{Name: "metrics.client", Values: observability.ValueEnum, Enum: []string{"accepted", "unknown", "family", "value", "count"}, Report: observability.ReportInternal, Help: "Client counts, by outcome."},
	)
}

// The viewed instance and this site's own always have a counter row, saying why when empty.
func TestHealthSaysWhenACounterWroteNothing(t *testing.T) {
	withMetricsInstance(t, "magic")
	savedCounter := FeatureCounter
	FeatureCounter = nil
	t.Cleanup(func() { FeatureCounter = savedCounter })
	store := newFakeMetrics()
	store.health = []observability.InstanceHealth{{Instance: "pokemon", LastFlush: loaderTestNow}}
	h := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "lorcana", Days: 90}).Health
	want := []MetricsCounterRow{
		{Instance: "pokemon", LastFlush: loaderTestNow, Live: true, RowsNote: "none yesterday; saved today"},
		{Instance: "lorcana", Current: true, NoRows: true, Reason: metricsNoCountsText},
		{Instance: "magic", NoRows: true, Reason: metricsCounterOffText},
	}
	if !slices.Equal(h.Counters, want) {
		t.Errorf("counters = %+v", h.Counters)
	}
	// With this site's counter running, its empty row says only that no counts came.
	rows := withFeatureCounter(t) // sets this site's instance to "test"
	if rows == nil {
		t.Fatal("no counter")
	}
	h = loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "test", Days: 90}).Health
	if len(h.Counters) != 2 || h.Counters[1] != (MetricsCounterRow{Instance: "test", Current: true, NoRows: true, Reason: metricsNoCountsText}) {
		t.Errorf("counter on: %+v", h.Counters)
	}
	// A failed read lists no rows at all, rather than calling every instance empty.
	store.healthErr = errors.New("down")
	if h := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "test", Days: 90}).Health; h.Counters != nil || !h.CountersRead.Failed {
		t.Errorf("read failed: %+v", h.Counters)
	}
}

// Every block of the three views tells counted, nothing complete yet and could not be read apart.
func TestNewViewsTellEmptyFromUnread(t *testing.T) {
	withMetricsInstance(t, "magic")
	type state struct{ counted, failed bool }
	blocks := func(v *MetricsView) map[string]state {
		out := map[string]state{}
		if f := v.Feature; f != nil {
			out["feature"] = state{f.Counted, f.Read.Failed}
		}
		if e := v.Explore; e != nil {
			out["explore"] = state{e.Counted, e.Read.Failed}
		}
		if h := v.Health; h != nil {
			out["silent"] = state{h.SilentCounted, h.SilentRead.Failed}
			out["client"] = state{h.ClientCounted, h.ClientRead.Failed}
		}
		return out
	}
	for _, p := range []metricsParams{
		{View: "feature"}, {View: "feature", Area: "search"}, {View: "feature", Name: "search.sort"},
		{View: "explore", Name: "auth.refuse"}, {View: "health"},
	} {
		p.Instance, p.Days = "magic", 90
		for _, c := range []struct {
			label string
			setup func(*fakeMetricsStore)
			want  state
		}{
			{"counted", func(*fakeMetricsStore) {}, state{true, false}},
			{"nothing complete yet", func(f *fakeMetricsStore) { f.folded, f.through = false, time.Time{} }, state{false, false}},
			{"newest day unread", func(f *fakeMetricsStore) { f.throughErr = errors.New("down") }, state{false, true}},
			{"counts unread", func(f *fakeMetricsStore) { f.totalsErr = errors.New("down") }, state{false, true}},
		} {
			store := newFakeMetrics()
			c.setup(store)
			v := loadTestView(t, store, testCache(store), beaconTestRegistry(), p)
			got := blocks(v)
			if len(got) == 0 {
				t.Fatalf("%+v: no blocks", p)
			}
			for name, st := range got {
				if st != c.want {
					t.Errorf("%s %+v, %s: %s = %+v, want %+v", p.View, p, c.label, name, st, c.want)
				}
			}
		}
	}
	// Minute rows and stored state do not wait for a fold.
	store := newFakeMetrics()
	store.folded = false
	if v := loadTestView(t, store, testCache(store), beaconTestRegistry(), metricsParams{View: "explore", Instance: "magic", Days: 90, Name: "auth.refuse", Hourly: true}); !v.Explore.Counted {
		t.Error("hourly rows before a fold are not counted")
	}
	if v := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 90, Name: "stock.rows"}); !v.Feature.Counted {
		t.Error("a stored-state name before a fold is not counted")
	}
}

// Finding 2: a metric page is one cache entry, shared by Feature and Explore, and a full click-through
// of the registry, by day and by hour, leaves the Overview's entries in the cache.
func TestAClickThroughKeepsTheCache(t *testing.T) {
	withMetricsInstance(t, "magic")
	names := observability.All()
	store := newFakeMetrics()
	clock := &testClock{t: loaderTestNow}
	cache := metricsreport.NewCache(store.FoldStamp, clock.now)
	load := func(p metricsParams) *MetricsView {
		t.Helper()
		p.Instance, p.Days = "magic", 90
		return loadMetricsViewFor(context.Background(), store, cache, names, metricsTestLists, p, clock.now())
	}
	load(metricsParams{View: "overview"})
	overview := store.dayTotalCount()
	areas := map[string]bool{}
	for _, n := range names {
		load(metricsParams{View: "feature", Name: n.Name})
		before := store.dayTotalCount()
		load(metricsParams{View: "explore", Name: n.Name})
		if store.dayTotalCount() != before {
			t.Fatalf("%s: Explore read again what Feature read", n.Name)
		}
		load(metricsParams{View: "explore", Name: n.Name, Hourly: true})
		if n.Area != "" && !areas[n.Area] {
			areas[n.Area] = true
			load(metricsParams{View: "feature", Area: n.Area})
		}
	}
	load(metricsParams{View: "feature"})
	before := store.dayTotalCount()
	load(metricsParams{View: "overview"})
	if store.dayTotalCount() != before {
		t.Errorf("the click-through emptied the cache: the Overview read %d queries again (it reads %d cold)", store.dayTotalCount()-before, overview)
	}
	// The hourly key holds no hour: a load just past the hour within the minute is served.
	calls := len(store.hourCalls)
	clock.add(59*time.Minute + 30*time.Second) // 12:59:30
	load(metricsParams{View: "explore", Name: "auth.refuse", Hourly: true})
	clock.add(40 * time.Second) // 13:00:10
	v := load(metricsParams{View: "explore", Name: "auth.refuse", Hourly: true})
	if len(store.hourCalls) != calls+1 || !v.Explore.HoursFrom.Equal(metricsHourSince(clock.now())) {
		t.Errorf("hour calls %d then %d, from %v", calls, len(store.hourCalls), v.Explore.HoursFrom)
	}
}

func TestMetricsJobStatusWords(t *testing.T) {
	for status, want := range map[string]string{
		metricsreport.JobOK:      "ran on time",
		metricsreport.JobNoRun:   "no run in the last 14 days",
		metricsreport.JobFailed:  "last run failed",
		metricsreport.JobOverdue: "overdue: no successful run in 36 hours",
		"other":                  "other",
	} {
		if got := metricsJobStatusWords(status, metricsreport.StaleJob); got != want {
			t.Errorf("%s: %q, want %q", status, got, want)
		}
	}
}

// Health is called checked only when every block was read on a complete day.
func TestHealthSaysWhatItCouldNotCheck(t *testing.T) {
	withMetricsInstance(t, "magic")
	notYet := func(what string) string { return what + " are checked only after the first nightly summary has run." }
	for _, c := range []struct {
		label string
		setup func(*fakeMetricsStore)
		want  []string
	}{
		{"everything read", func(*fakeMetricsStore) {}, nil},
		{"nothing complete yet", func(f *fakeMetricsStore) { f.folded, f.through = false, time.Time{} },
			[]string{notYet("Missing counts"), notYet("Browser report outcomes")}},
		{"newest day unread", func(f *fakeMetricsStore) { f.throughErr = errors.New("down") },
			[]string{"Missing counts could not be read.", "Browser report outcomes could not be read."}},
		{"counters unread", func(f *fakeMetricsStore) { f.healthErr = errors.New("down") },
			[]string{"Counters and job runs could not be read."}},
		{"counts unread", func(f *fakeMetricsStore) { f.totalsErr = errors.New("down") },
			[]string{"Missing counts could not be read.", "Browser report outcomes could not be read."}},
	} {
		store := newFakeMetrics()
		c.setup(store)
		h := loadTestView(t, store, testCache(store), beaconTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
		if !slices.Equal(h.Unchecked, c.want) || h.Checked != (len(c.want) == 0) {
			t.Errorf("%s: checked %v, unchecked %q, want %q", c.label, h.Checked, h.Unchecked, c.want)
		}
	}
	// Without the beacon registered, its block is not measured, which is not a gap in the check.
	store := newFakeMetrics()
	if h := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health; !h.Checked {
		t.Errorf("unchecked %q without the beacon", h.Unchecked)
	}
}

func TestMetricsJobRowsSayTheirStatus(t *testing.T) {
	rows := metricsJobRows([]string{"fold", "stock"}, []observability.JobRun{{Instance: "magic", Job: "fold", Result: "fail", At: loaderTestNow}}, loaderTestNow)
	if len(rows) != 2 || rows[0].StatusText != "last run failed" || rows[1].StatusText != "no run in the last 14 days" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestChartPointsPairEachLabelWithItsCount(t *testing.T) {
	v := &MetricsView{Charts: []MetricsChart{
		{ID: "metrics-spark-0", Labels: []string{"a"}, Series: []MetricsSeries{{Data: []int64{9}}}},
		{ID: "metrics-days", Labels: []string{"2026-11-09", "2026-11-10", "extra"}, Series: []MetricsSeries{{Data: []int64{3, 4}}, {Data: []int64{7, 7}}}},
		{ID: "empty", Labels: []string{"x"}},
	}}
	if got := v.ChartPoints("metrics-days"); !slices.Equal(got, []MetricsPoint{{"2026-11-09", 3}, {"2026-11-10", 4}}) {
		t.Errorf("points = %+v", got)
	}
	for _, id := range []string{"", "missing", "empty"} {
		if got := v.ChartPoints(id); got != nil {
			t.Errorf("%q: %+v", id, got)
		}
	}
	var none *MetricsView
	if none.ChartPoints("metrics-days") != nil {
		t.Error("a nil view has points")
	}
}

// An area row's NoRate is set only on a counted day name with no rate.
func TestAreaRowsSayWhyTheyHaveNoRate(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Value: "alpha", N: 5, Days: 20},
		{Period: 0, Name: "search.result", Value: "found", N: 1000, Days: 30},
	}
	v := loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 30, Area: "search"})
	got := map[string]string{}
	for _, r := range v.Feature.Names {
		got[r.Name] = r.NoRate
	}
	want := map[string]string{
		"search.sort":   "",
		"search.filter": metricsreport.NoRateEmpty,
		"search.result": metricsreport.NoRateDays,
	}
	if !maps.Equal(got, want) {
		t.Errorf("no rate = %v, want %v", got, want)
	}
	store.folded, store.through = false, time.Time{}
	for _, r := range loadTestView(t, store, testCache(store), featureTestRegistry(), metricsParams{View: "feature", Instance: "magic", Days: 30, Area: "search"}).Feature.Names {
		if r.NoRate != "" {
			t.Errorf("%s before a fold: %q", r.Name, r.NoRate)
		}
	}
}

func TestMetricsRowsNote(t *testing.T) {
	for _, c := range []struct {
		h    observability.InstanceHealth
		want string
	}{
		{observability.InstanceHealth{Rows: 0, LastFlush: loaderTestNow}, "none yesterday; saved today"},
		{observability.InstanceHealth{Rows: 12, LastFlush: loaderTestNow}, ""},
		{observability.InstanceHealth{}, ""},
	} {
		if got := metricsRowsNote(c.h); got != c.want {
			t.Errorf("%+v: %q, want %q", c.h, got, c.want)
		}
	}
}

func TestMetricsRunWords(t *testing.T) {
	at := time.Date(2026, 11, 11, 10, 0, 0, 0, time.FixedZone("x", 3600))
	for _, c := range []struct {
		r    observability.JobRun
		want string
	}{
		{observability.JobRun{}, "none in 14 days"},
		{observability.JobRun{Instance: "magic", Result: "ok", At: at}, "Nov 11 09:00, succeeded on magic"},
		{observability.JobRun{Instance: "lorcana", Result: "fail", At: at}, "Nov 11 09:00, failed on lorcana"},
	} {
		if got := metricsRunWords(c.r); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
	if metricsWhen(time.Time{}) != "none in 14 days" || metricsWhen(at) != "Nov 11 09:00" {
		t.Error("metricsWhen")
	}
}

// The legend under the counters takes its words from the registry.
func TestHealthCarriesTheCounterHelp(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	h := loadTestView(t, store, testCache(store), observability.All(), metricsParams{View: "health", Instance: "magic", Days: 90}).Health
	dropped, okD := observability.Lookup("metrics.dropped")
	rejected, okR := observability.Lookup("metrics.rejected")
	if !okD || !okR || h.DroppedHelp != dropped.Help || h.RejectedHelp != rejected.Help || h.DroppedHelp == "" {
		t.Errorf("help %q %q", h.DroppedHelp, h.RejectedHelp)
	}
}

func TestChartsLoadOnTheMetricsViewsOnly(t *testing.T) {
	const tag = "chart.js@4.5.1/dist/chart.umd.min.js"
	v := &MetricsView{View: "explore", Explore: &MetricsExplore{Name: "http.status", LineID: "metrics-explore"},
		Charts: []MetricsChart{{ID: "metrics-explore", Kind: "line", Labels: []string{"11-10"}, Series: []MetricsSeries{{Label: "http.status", Data: []int64{7}}}}}}
	on := metricsPage(t, v)
	for _, want := range []string{tag, "window.BAN_ADMIN_METRICS", `"id":"metrics-explore"`, `"kind":"line"`, `"data":[7]`, `/js/admin-metrics.js?hash=`} {
		if !strings.Contains(on, want) {
			t.Errorf("the metrics page lacks %q", want)
		}
	}
	for _, page := range []string{"dashboard", "usage", "searches"} {
		if html := renderAdminPage(t, PageVars{Page: page}); strings.Contains(html, tag) || strings.Contains(html, "admin-metrics.js") {
			t.Errorf("the %s tab loads the chart scripts", page)
		}
	}
	if off := renderAdminPage(t, PageVars{Page: "metrics"}); strings.Contains(off, tag) {
		t.Error("with metrics off the chart library still loads")
	}
	// a view that drew no chart loads nothing
	if none := metricsPage(t, &MetricsView{View: "health", Health: &MetricsHealth{}}); strings.Contains(none, tag) || strings.Contains(none, "BAN_ADMIN_METRICS") || strings.Contains(none, "admin-metrics.js") {
		t.Error("a view with no chart loads the chart scripts")
	}
	// on a phone neither page set emits them
	for _, key := range []bool{false, true} {
		tmpl := metricsCachedSet(t, key)
		var buf bytes.Buffer
		vars := PageVars{Title: "Admin", UserNav: &NavElem{}, Page: "metrics", IsMobile: true, AdminVars: AdminVars{Metrics: v}}
		if err := tmpl.ExecuteTemplate(&buf, tmpl.Name(), vars); err != nil {
			t.Fatalf("rendering %s on mobile: %v", tmpl.Name(), err)
		}
		if html := buf.String(); strings.Contains(html, tag) || strings.Contains(html, "BAN_ADMIN_METRICS") || strings.Contains(html, "admin-metrics.js") {
			t.Errorf("%s on mobile loads the chart scripts", tmpl.Name())
		}
	}
}

// The pinned tag is search.html's, so the two cannot drift apart.
func TestChartTagMatchesSearch(t *testing.T) {
	// the whole tag, so an attribute added to search's (integrity, crossorigin) must be copied here too
	tag := regexp.MustCompile(`<script[^>]*chart\.js@[^>]*></script>`)
	search, errS := os.ReadFile("templates/search.html")
	admin, errA := os.ReadFile("templates/partials/admin-metrics.html")
	mobile, errM := os.ReadFile("js/mobile-chart.js")
	if errS != nil || errA != nil || errM != nil {
		t.Fatalf("reading the pins: %v %v %v", errS, errA, errM)
	}
	s, a := tag.FindAll(search, -1), tag.FindAll(admin, -1)
	if len(s) != 1 || len(a) != 1 || !bytes.Equal(s[0], a[0]) {
		t.Errorf("search's tag %q, the metrics section's %q", s, a)
	}
	// the phone chart loads the same version by URL
	url := regexp.MustCompile(`https://cdn\.jsdelivr\.net/npm/chart\.js@[0-9.]+/dist/chart\.umd\.min\.js`)
	if u := url.Find(mobile); len(s) == 0 || u == nil || !bytes.Contains(s[0], u) {
		t.Errorf("js/mobile-chart.js loads %q, search %q", u, s)
	}
}

// A label cannot close the script element or its string, and counts stay numbers.
func TestChartDataIsEscapedInTheScript(t *testing.T) {
	const evil = "</script><script>alert(1)</script>\"'&\n</SCRIPT><!-- \\    "
	v := &MetricsView{View: "explore", Explore: &MetricsExplore{Name: "http.status", LineID: "metrics-explore"},
		Charts: []MetricsChart{{ID: "metrics-explore", Kind: "line", Labels: []string{evil, "11-10"}, Series: []MetricsSeries{{Label: evil, Data: []int64{7, 1234567890123}}}}}}
	html := metricsPage(t, v)
	const open = "window.BAN_ADMIN_METRICS = { charts: "
	start := strings.Index(html, open)
	if start < 0 {
		t.Fatal("no data object")
	}
	rest := html[start+len(open):]
	end := strings.Index(rest, "</script>")
	if end < 0 {
		t.Fatal("the data script is not closed")
	}
	body := strings.TrimSpace(rest[:end])
	if !strings.HasSuffix(body, "};") {
		t.Fatalf("the data script holds more than the object: %q", body)
	}
	data := strings.TrimSpace(strings.TrimSuffix(body, "};"))
	// a quote is safe inside a JSON string once its double quote is escaped, which the round trip proves
	for _, bad := range []string{"<", ">", "\n", "&", " ", " "} {
		if strings.Contains(data, bad) {
			t.Errorf("the data holds a raw %q: %s", bad, data)
		}
	}
	var got []MetricsChart
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("the data is not JSON: %v\n%s", err, data)
	}
	if len(got) != 1 || len(got[0].Labels) != 2 || got[0].Labels[0] != evil || got[0].Series[0].Label != evil {
		t.Errorf("the labels did not survive: %+v", got)
	}
	if !strings.Contains(data, `"data":[7,1234567890123]`) {
		t.Errorf("the counts are not bare numbers: %s", data)
	}
	// the page around it is unchanged: one data script, then the deferred page script
	if strings.Count(html, "BAN_ADMIN_METRICS") != 1 || !strings.Contains(rest[end:], `src="/js/admin-metrics.js?hash=`) {
		t.Error("the page script does not follow the data")
	}
}

func TestCleanReviewNote(t *testing.T) {
	if got := cleanReviewNote("  the bot\r\n sorts\tthis way \x00 "); got != "the bot sorts this way" {
		t.Errorf("got %q", got)
	}
	long := cleanReviewNote(strings.Repeat("é", 5000))
	if n := utf8.RuneCountInString(long); n != 200 || !utf8.ValidString(long) {
		t.Errorf("a 5,000-character note is cut to %d runes, valid %v, want 200", n, utf8.ValidString(long))
	}
	if got := cleanReviewNote("right\u202eto left\u200bjoined \ufeff"); got != "rightto leftjoined" {
		t.Errorf("format characters cleaned to %q", got)
	}
	if got := cleanReviewNote("ok\xff\xfenot"); got != "ok�not" {
		t.Errorf("invalid UTF-8 cleaned to %q", got)
	}
}

// reviewDone runs adminMetricsReview for instance and checks done says whether it redirected.
func reviewDone(t *testing.T, target, instance string, form url.Values, store *fakeMetricsStore) (*httptest.ResponseRecorder, PageVars) {
	t.Helper()
	var pv PageVars
	rec := httptest.NewRecorder()
	lists := metricsreport.Lists{Pages: []string{"search", "screener"}}
	done := adminMetricsReview(context.Background(), rec, postForm(target, form), store, lists, metricsParams{View: "remove", Instance: instance, Days: 90}, &pv)
	if redirected := rec.Header().Get("Location") != ""; done != redirected {
		t.Errorf("done %v, redirected %v", done, redirected)
	}
	return rec, pv
}

func reviewPostTo(t *testing.T, target string, form url.Values) (*httptest.ResponseRecorder, *fakeMetricsStore, PageVars) {
	t.Helper()
	store := &fakeMetricsStore{}
	rec, pv := reviewDone(t, target, "lorcana", form, store)
	return rec, store, pv
}

func reviewPost(t *testing.T, form url.Values) (*httptest.ResponseRecorder, *fakeMetricsStore, PageVars) {
	t.Helper()
	return reviewPostTo(t, "/admin?page=metrics&view=remove", form)
}

func TestReviewIsSavedAndRedirects(t *testing.T) {
	withMetricsInstance(t, "magic")
	rec, store, pv := reviewPost(t, url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"watch"}, "reviewNote": {strings.Repeat("n", 300)}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin?page=metrics&view=remove&area=site&instance=lorcana&saved=1#rm-page.view----screener" {
		t.Fatalf("status %d to %q, warning %q", rec.Code, rec.Header().Get("Location"), pv.WarningMessage)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved %d reviews", len(store.saved))
	}
	got := store.saved[0]
	if got.Instance != "lorcana" || got.Name != "page.view" || got.Value != "screener" || got.Scope != "" || got.Verdict != "watch" || len(got.Note) != 200 {
		t.Errorf("saved %+v", got)
	}
}

// The redirect is built from the validated params alone, whatever else the request names.
func TestReviewRedirectIgnoresWhatTheFormNames(t *testing.T) {
	withMetricsInstance(t, "lorcana")
	form := url.Values{"reviewName": {"page.view"}, "reviewValue": {"search"}, "reviewVerdict": {"keep"},
		"return": {"https://evil.example/"}, "view": {"https://evil.example/"}}
	r := postForm("/admin?page=metrics&view=remove&days=30", form)
	r.Header.Set("Referer", "https://evil.example/")
	rec := httptest.NewRecorder()
	var pv PageVars
	lists := metricsreport.Lists{Pages: []string{"search"}}
	if !adminMetricsReview(context.Background(), rec, r, &fakeMetricsStore{}, lists, metricsParams{View: "remove", Instance: "lorcana", Days: 30}, &pv) {
		t.Error("a saved review did not answer")
	}
	if got := rec.Header().Get("Location"); got != "/admin?page=metrics&view=remove&area=site&days=30&saved=1#rm-page.view----search" {
		t.Errorf("redirected to %q, warning %q", got, pv.WarningMessage)
	}
}

func TestReviewRefusals(t *testing.T) {
	for name, form := range map[string]url.Values{
		"unknown name":    {"reviewName": {"no.such"}, "reviewVerdict": {"keep"}},
		"not a candidate": {"reviewName": {"http.status"}, "reviewValue": {"5xx"}, "reviewVerdict": {"keep"}},
		"not a unit":      {"reviewName": {"page.view"}, "reviewValue": {"../etc"}, "reviewVerdict": {"keep"}},
		"a stray scope":   {"reviewName": {"page.view"}, "reviewScope": {"<b>x</b>"}, "reviewValue": {"screener"}, "reviewVerdict": {"keep"}},
		"bad verdict":     {"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"maybe"}},
		"no verdict":      {"reviewName": {"page.view"}, "reviewValue": {"screener"}},
	} {
		rec, store, pv := reviewPost(t, form)
		if len(store.saved) != 0 || len(store.deleted) != 0 || !strings.HasPrefix(pv.WarningMessage, "Review not saved") || rec.Header().Get("Location") != "" {
			t.Errorf("%s: saved %d, warning %q", name, len(store.saved), pv.WarningMessage)
		}
		for field, sent := range form {
			if field != "reviewVerdict" && strings.Contains(pv.WarningMessage, sent[0]) {
				t.Errorf("%s: the warning %q echoes %q", name, pv.WarningMessage, sent[0])
			}
		}
	}
}

// An instance the picker does not offer is refused for a write, not saved under this site's.
func TestReviewForAnUnknownSiteIsRefused(t *testing.T) {
	form := url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"keep"}}
	for _, target := range []string{"/admin?page=metrics&view=remove&instance=nowhere", "/admin?page=metrics&view=remove&instance=shared"} {
		rec, store, pv := reviewPostTo(t, target, form)
		if len(store.saved) != 0 || pv.WarningMessage != metricsReviewNoSite || rec.Header().Get("Location") != "" {
			t.Errorf("%s: saved %d, warning %q", target, len(store.saved), pv.WarningMessage)
		}
	}
	// the instance the params validated is the one written
	_, store, pv := reviewPostTo(t, "/admin?page=metrics&view=remove&instance=lorcana", form)
	if len(store.saved) != 1 || store.saved[0].Instance != "lorcana" {
		t.Errorf("a review for a listed site: saved %+v, warning %q", store.saved, pv.WarningMessage)
	}
}

// With no instance_name there is no site to file a mark under: save and clear are both refused.
func TestReviewWithNoSiteIsRefused(t *testing.T) {
	for _, verdict := range []string{"keep", "clear"} {
		store := &fakeMetricsStore{}
		rec, pv := reviewDone(t, "/admin?page=metrics&view=remove", "", url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {verdict}}, store)
		if len(store.saved)+len(store.deleted) != 0 || pv.WarningMessage != metricsReviewNoSite || rec.Code == http.StatusSeeOther {
			t.Errorf("%s: saved %d, deleted %d, status %d, warning %q", verdict, len(store.saved), len(store.deleted), rec.Code, pv.WarningMessage)
		}
	}
}

func TestReviewClearDeletes(t *testing.T) {
	rec, store, pv := reviewPost(t, url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"clear"}, "reviewNote": {"ignored"}})
	if rec.Code != http.StatusSeeOther || len(store.saved) != 0 {
		t.Fatalf("status %d, saved %d, warning %q", rec.Code, len(store.saved), pv.WarningMessage)
	}
	if want := []string{"lorcana|page.view||screener"}; !slices.Equal(store.deleted, want) {
		t.Errorf("deleted %q, want %q", store.deleted, want)
	}
}

// A redirect says which it did, and the Remove view prints a fixed line for it and nothing else.
func TestReviewConfirmation(t *testing.T) {
	withMetricsInstance(t, "lorcana")
	saved, _, _ := reviewPost(t, url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"keep"}})
	cleared, _, _ := reviewPost(t, url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"clear"}})
	if got := saved.Header().Get("Location"); got != "/admin?page=metrics&view=remove&area=site&saved=1#rm-page.view----screener" {
		t.Errorf("saved: redirected to %q", got)
	}
	if got := cleared.Header().Get("Location"); got != "/admin?page=metrics&view=remove&area=site&cleared=1#rm-page.view----screener" {
		t.Errorf("cleared: redirected to %q", got)
	}

	store := newFakeMetrics()
	store.reviews = []observability.Review{{Instance: "lorcana", Name: "sets.sort", Value: "name", Verdict: "keep"}}
	names := []observability.Name{{Name: "sets.sort", Area: "search", Values: observability.ValueEnum, Enum: []string{"date", "name"}, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "option"}}
	load := func(query string) *MetricsView {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		p := readMetricsParams(q.Get, []string{"lorcana"})
		cache := metricsreport.NewCache(store.FoldStamp, func() time.Time { return loaderTestNow })
		return loadMetricsViewFor(context.Background(), store, cache, names, metricsreport.Lists{}, p, loaderTestNow)
	}
	// only the Reviewed group can open: Not measured never does
	const reviewedOpen = `<details class="admin-section admin-metrics-more-rows" open>`
	for query, want := range map[string]string{
		"view=remove&saved=1":                metricsReviewSaved,
		"view=remove&cleared=1":              metricsReviewCleared,
		"view=remove":                        "",
		"view=remove&saved=yes&cleared=true": "",
		"view=remove&saved=<b>x</b>":         "",
		"view=overview&saved=1":              "",
	} {
		v := load(query)
		if v.Confirm != want {
			t.Errorf("%s: confirm %q, want %q", query, v.Confirm, want)
		}
		for _, mobile := range []bool{false, true} {
			html := metricsSection(t, v, mobile)
			if want != "" {
				wantAll(t, html, query, `<div class="admin-msg" role="status">`+want+`</div>`)
			} else {
				wantNone(t, html, query, `role="status"`, metricsReviewSaved, metricsReviewCleared, "&lt;b&gt;")
			}
			if v.Remove != nil && strings.Contains(html, reviewedOpen) != (query == "view=remove&saved=1") {
				t.Errorf("%s mobile %v: the Reviewed group open %v", query, mobile, strings.Contains(html, reviewedOpen))
			}
		}
		// no link the page builds carries the confirmation on
		links := []MetricsLink{v.AnonLink, v.BotsLink}
		links = append(append(append(links, v.Instances...), v.Windows...), v.Views...)
		if v.Remove != nil {
			links = append(links, MetricsLink{URL: v.Remove.ReviewURL})
		}
		for _, l := range links {
			if strings.Contains(l.URL, "saved") || strings.Contains(l.URL, "cleared") {
				t.Errorf("%s: link %q carries the confirmation", query, l.URL)
			}
		}
	}
}

func TestReviewNeedsAPostBody(t *testing.T) {
	form := url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"remove"}}
	lists := metricsreport.Lists{Pages: []string{"search", "screener"}}
	for name, r := range map[string]*http.Request{
		"a GET":                      httptest.NewRequest(http.MethodGet, "/admin?page=metrics&view=remove&"+form.Encode(), nil),
		"a POST's query string only": postForm("/admin?page=metrics&view=remove&"+form.Encode(), nil),
	} {
		store := &fakeMetricsStore{}
		var pv PageVars
		rec := httptest.NewRecorder()
		if adminMetricsReview(context.Background(), rec, r, store, lists, metricsParams{View: "remove", Instance: "lorcana", Days: 90}, &pv) {
			t.Errorf("%s answered", name)
		}
		if len(store.saved)+len(store.deleted) != 0 || pv.WarningMessage != "" || rec.Header().Get("Location") != "" {
			t.Errorf("%s: saved %d, deleted %d, warning %q", name, len(store.saved), len(store.deleted), pv.WarningMessage)
		}
	}
}

func TestReviewStoreErrorIsShown(t *testing.T) {
	store := &fakeMetricsStore{err: errors.New("pq: relation feature_reviews does not exist")}
	var pv PageVars
	rec := httptest.NewRecorder()
	r := postForm("/admin?page=metrics&view=remove", url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {"keep"}})
	if adminMetricsReview(context.Background(), rec, r, store, metricsreport.Lists{Pages: []string{"screener"}}, metricsParams{View: "remove", Instance: "lorcana", Days: 90}, &pv) {
		t.Error("a failed save answered")
	}
	if !strings.HasPrefix(pv.WarningMessage, "Review not saved: ") || strings.Contains(pv.WarningMessage, "pq") || rec.Header().Get("Location") != "" {
		t.Errorf("warning %q, location %q", pv.WarningMessage, rec.Header().Get("Location"))
	}
}

// withMetricsStore makes store the section's store for the test.
func withMetricsStore(t *testing.T, store metricsStore) {
	t.Helper()
	saved := metricsStoreFn
	metricsStoreFn = func() metricsStore { return store }
	t.Cleanup(func() { metricsStoreFn = saved })
}

// A form on another site cannot mark a row: Admin refuses it before the body is read.
func TestReviewFromAnotherSiteIsRefused(t *testing.T) {
	store := &fakeMetricsStore{}
	withMetricsStore(t, store)
	withSigMode(t, true, false)

	r := postForm("/admin?page=metrics&view=remove", url.Values{"reviewName": {"page.view"}, "reviewValue": {"search"}, "reviewVerdict": {"remove"}})
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	testSite.Admin(rec, r)
	if rec.Code != http.StatusForbidden || len(store.saved) != 0 {
		t.Errorf("status %d, saved %d", rec.Code, len(store.saved))
	}
}

// withMetricsTemplateCache gives render the production cache for the test.
func withMetricsTemplateCache(t *testing.T) {
	t.Helper()
	if metricsCachedSet(t, false) == nil {
		t.Fatal("no admin template")
	}
	saved := TemplateCache
	metricsTemplateCache.mu.Lock()
	TemplateCache = metricsTemplateCache.cache
	metricsTemplateCache.mu.Unlock()
	t.Cleanup(func() { TemplateCache = saved })
}

// Through the real mount, a reader without the Admin page cannot mark a row.
func TestReviewNeedsAnAdmin(t *testing.T) {
	signingEnabled(t, false)
	resetMetricsCache(t)
	withMetricsInstance(t, "lorcana")
	store := newFakeMetrics()
	withMetricsStore(t, store)
	withMetricsTemplateCache(t)
	mux := http.NewServeMux()
	testSite.mountNav(mux, ExtraNavs["Admin"])

	// a Pro signature with Admin=true written into it: base64 decodes, the HMAC does not match
	pro := signedAs(t, url.Values{"UserTier": {"Pro"}, "Search": {"true"}}, time.Now().Add(time.Hour))
	raw, err := base64.StdEncoding.DecodeString(pro)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := url.ParseQuery(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	fields.Set("Admin", "true")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))
	if _, ok := signatureIsValid(forged); ok {
		t.Fatal("the forged signature verifies")
	}

	form := url.Values{"reviewName": {"sets.sort"}, "reviewValue": {"name"}, "reviewVerdict": {"remove"}}
	for name, sig := range map[string]string{
		"no signature":       "",
		"a Pro reader":       pro,
		"a forged admin":     forged,
		"a malformed cookie": "UserTier=Root&Admin=true",
	} {
		r := postForm("/admin?page=metrics&view=remove", form)
		if sig != "" {
			r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code == http.StatusSeeOther || len(store.saved) != 0 {
			t.Errorf("%s: status %d, saved %d", name, rec.Code, len(store.saved))
		}
	}
	// the same POST with the Admin page in a valid signature saves
	r := postForm("/admin?page=metrics&view=remove", form)
	r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, url.Values{"UserTier": {"Root"}, "Admin": {"true"}}, time.Now().Add(time.Hour))})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther || len(store.saved) != 1 {
		t.Errorf("an admin: status %d, saved %d", rec.Code, len(store.saved))
	}
}

// A saved mark shows on the next request of any process: reviews are read past the cache.
func TestReviewShowsOnTheNextLoad(t *testing.T) {
	withMetricsInstance(t, "lorcana")
	store := newFakeMetrics()
	clock := &testClock{t: loaderTestNow}
	cache := metricsreport.NewCache(store.FoldStamp, clock.now)
	p := metricsParams{View: "remove", Instance: "lorcana", Days: 90}
	names := []observability.Name{{Name: "sets.sort", Area: "search", Values: observability.ValueEnum, Enum: []string{"date", "name"}, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "option"}}
	v := loadMetricsViewFor(context.Background(), store, cache, names, metricsreport.Lists{}, p, clock.now())
	if v.Remove == nil || len(v.Remove.Reviewed) != 0 {
		t.Fatalf("before the mark: %+v", v.Remove)
	}
	// another process saves the mark into the shared table
	store.mu.Lock()
	store.reviews = []observability.Review{{Instance: "lorcana", Name: "sets.sort", Value: "name", Verdict: "keep", Note: "kept"}}
	store.mu.Unlock()
	clock.add(time.Second)
	v = loadMetricsViewFor(context.Background(), store, cache, names, metricsreport.Lists{}, p, clock.now())
	if v.Remove == nil || len(v.Remove.Reviewed) != 1 || v.Remove.Reviewed[0].Note != "kept" {
		t.Errorf("after the mark, a second later on a warm cache: %+v", v.Remove)
	}
	if v.Remove.ReviewURL != "?page=metrics&view=remove" {
		t.Errorf("the form posts to %q", v.Remove.ReviewURL)
	}
}

// A refused mark reaches the section's own Message, which the mobile page prints.
func TestReviewRefusalReachesTheSection(t *testing.T) {
	resetMetricsCache(t)
	withMetricsInstance(t, "lorcana")
	withSigMode(t, true, false)
	store := newFakeMetrics()
	withMetricsStore(t, store)

	r := postForm("/admin?page=metrics&view=remove", url.Values{"reviewName": {"sets.sort"}, "reviewValue": {"name"}, "reviewVerdict": {"maybe"}})
	rec := httptest.NewRecorder()
	testSite.Admin(rec, r)
	if rec.Code != http.StatusOK || len(store.saved) != 0 || !strings.Contains(rec.Body.String(), metricsReviewNoVerdict) {
		t.Errorf("status %d, saved %d, warning shown %v", rec.Code, len(store.saved), strings.Contains(rec.Body.String(), metricsReviewNoVerdict))
	}
	v := metricsShellFor("remove")
	v.Remove, v.Message = &MetricsRemove{Counted: true}, metricsReviewNoVerdict
	wantAll(t, metricsSection(t, v, true), "the mobile section", `<div class="admin-msg admin-msg-error">`+metricsReviewNoVerdict+`</div>`)
	wantNone(t, metricsSection(t, v, false), "the desktop section", metricsReviewNoVerdict)
}

// A3: page hits that fail alone are said where their sections are, never "Nothing to report".
func TestPageHitsThatFailAreSaid(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = append(fullRows("metrics.flush", "", "", 1, 6), fullRows("page.view", "", "search", 900, 6)...)
	store.visitsErr = errors.New("slow")
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "invest", Instance: "magic", Days: 90})
	if !v.Invest.Counted || !v.Invest.VisitsRead.Failed {
		t.Fatalf("invest counted %v, visits read %+v", v.Invest.Counted, v.Invest.VisitsRead)
	}
	for _, sec := range v.Invest.Sections {
		failed := strings.Contains(sec.Empty, "page hits could not be read")
		if want := sec.Key == metricsreport.SectionMobile || sec.Key == metricsreport.SectionDepth; failed != want {
			t.Errorf("%s: %q", sec.Key, sec.Empty)
		}
	}
	html := metricsPage(t, v)
	wantAll(t, html, "invest with no page hits", "The page hits could not be read just now, so this is not known; reload the page to try again.")
	ov := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if !ov.Overview.VisitsRead.Failed {
		t.Errorf("overview visits read %+v", ov.Overview.VisitsRead)
	}
	wantAll(t, metricsPage(t, ov), "overview with no page hits", "The page hits could not be read just now, so the phone and depth rows are left out.")
}

// A3: a tier split that fails alone says so in each Tiers cell.
func TestTierSplitThatFailsIsSaid(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = append(fullRows("metrics.flush", "", "", 1, 6), fullRows("auth.refuse", "search", "no_access", 30, 6)...)
	store.tiersErr = errors.New("slow")
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "invest", Instance: "magic", Days: 90})
	walls := v.Invest.Sections[0]
	if !walls.HasTiers || len(walls.Rows) == 0 || walls.Rows[0].Tiers != metricsTiersFailedText {
		t.Errorf("walls %+v", walls)
	}
	store.totals = append(store.totals, fullRows("page.view", "", "alerts", 0, 6)...)
	r := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	if len(r.Remove.Areas) == 0 {
		t.Fatal("no remove rows")
	}
	for _, a := range r.Remove.Areas {
		for _, k := range a.Kinds {
			if !k.HasTiers || k.Rows[0].Tiers != metricsTiersFailedText {
				t.Errorf("remove %s %s: %+v", a.Area, k.Kind, k.Rows[0])
			}
		}
	}
}

// A4: Growing and New say what they could not compare, with the numbers, before they can.
func TestGrowingAndNewSayWhyTheyCannotCompare(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	// 45 days: the newest 30-day period full, the one before 15 days
	store.totals = append(fullRows("metrics.flush", "", "", 1, 1), observability.DayTotal{Period: 1, Name: "metrics.flush", N: 1, Days: 15})
	sections := func() map[string]MetricsInvestSection {
		v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "invest", Instance: "magic", Days: 30})
		got := map[string]MetricsInvestSection{}
		for _, sec := range v.Invest.Sections {
			got[sec.Key] = sec
		}
		return got
	}
	if g := sections()[metricsreport.SectionGrowing]; g.Empty != "Nothing to report" {
		t.Errorf("15 counted days before is enough to compare: %q", g.Empty)
	}
	store.totals[1].Days = 13
	got := sections()
	want := fmt.Sprintf("Not enough counted days to compare yet: it needs %d in each of the last two 30-day periods; the earlier has 13, the later 30.", metricsreport.MinDaysMeasured)
	if g := got[metricsreport.SectionGrowing]; g.Empty != want || !strings.Contains(g.Note, "whatever the window above") {
		t.Errorf("growing %q, note %q", g.Empty, g.Note)
	}
	want = fmt.Sprintf("Not enough counted days to compare yet: it needs %d in the 30 days before the window; they have 13.", metricsreport.MinDaysMeasured)
	if n := got[metricsreport.SectionNew]; n.Empty != want {
		t.Errorf("new %q", n.Empty)
	}
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "invest", Instance: "magic", Days: 30})
	wantAll(t, metricsPage(t, v), "invest before it can compare",
		"The last 30 complete days against the 30 before, per counted day, whatever the window above.", "it needs 14 in each")
}

// A6: Last seen names a day or the days read, never "never".
func TestLastSeenSaysWhatWasRead(t *testing.T) {
	if got := metricsLastSeen(time.Time{}, 60); got != "not in the last 60 days" {
		t.Errorf("none: %q", got)
	}
	if got := metricsLastSeen(loaderTestDay, 60); got != "Nov 10, 2026" {
		t.Errorf("a day: %q", got)
	}
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = removeFixture()
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "remove", Instance: "magic", Days: 90})
	html := metricsPage(t, v)
	wantAll(t, html, "remove at 90 days", "not in the last 180 days")
	wantNone(t, html, "remove at 90 days", ">never<")
}

// A7: before any candidate could be classed, the empty Remove view says how many wait.
func TestRemoveEmptySaysWhatWaits(t *testing.T) {
	names := metricsTestRegistry()
	w := metricsreport.Window{Days: 30, Signed: true, Humans: true}
	young := append(fullRows("metrics.flush", "", "", 1, 1), fullRows("page.view", "", "search", 900, 1)...)
	for i := range young {
		young[i].Days = 9
	}
	got := metricsRemoveEmpty(names, metricsTestLists, young, w)
	if !strings.HasPrefix(got, "No candidate has been measured long enough to be classed yet: ") ||
		!strings.Contains(got, fmt.Sprintf("waiting for %d measured days, and the most any has is 9.", metricsreport.MinDaysMeasured)) {
		t.Errorf("young: %q", got)
	}
	for i := range young {
		young[i].Days = 30
	}
	if got := metricsRemoveEmpty(names, metricsTestLists, young, w); got != "Nothing is unused or rare in this window." {
		t.Errorf("measured: %q", got)
	}
}

// A8: a site with no instance name says so and reads nothing of its own.
func TestNoInstanceNameIsSaid(t *testing.T) {
	withMetricsInstance(t, "")
	store := newFakeMetrics()
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Days: 90})
	if v.NoInstance != metricsNoInstanceText || v.Overview != nil || store.dayTotalCount() != 0 || store.throughCalls != 0 || store.reviewCalls != 0 {
		t.Errorf("no instance: %+v, %d queries", v, store.dayTotalCount())
	}
	html := metricsPage(t, v)
	wantAll(t, html, "no instance", metricsNoInstanceText, "lorcana")
	wantNone(t, html, "no instance", metricsReadFailedText, "could not be read")
}

// A9: stored state that stopped says when it last ran, or that none ran, not "not measured".
func TestStaleStoredStateIsSaid(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = fullRows("metrics.flush", "", "", 1, 6)
	last := loaderTestDay.AddDate(0, 0, -8)
	store.stockLast = []observability.DayTotal{{Name: "stock.rows", N: 5, Days: 1, First: last, Last: last}}
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	want := fmt.Sprintf("the nightly count has not run in the last %d days; the last one counted Nov 2, 2026", metricsStockDays)
	if v.Overview.StockStale != want || !slices.Contains(v.Notes, "Stored state: "+want+".") || slices.Contains(v.Notes, "Stored state: not measured yet.") {
		t.Errorf("stale %q, notes %v", v.Overview.StockStale, v.Notes)
	}
	html := metricsPage(t, v)
	wantAll(t, html, "stale stored state", "Stored state: "+want+".", "no recent count")
	wantNone(t, html, "stale stored state", "Stored state: not measured.")
	store.stockLast = nil
	v = loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if v.Overview.StockStale != fmt.Sprintf("no nightly count has run in the last %d days", metricsStockLookBack) {
		t.Errorf("none in the look-back: %q", v.Overview.StockStale)
	}
}

// A9: a stored-state name whose parts are not a partition heads its counts Rows and shows no share.
func TestStockPartsThatAreNoPartitionAreNotShares(t *testing.T) {
	day := loaderTestDay
	names := []observability.Name{
		{Name: "stock.pref", Family: observability.FamilyStock, Values: observability.ValueEnum, Enum: []string{"a", "b"}},
		{Name: "stock.favorites", Family: observability.FamilyStock, Values: observability.ValueBucket, Enum: []string{"0", "1+"}},
	}
	rows := []observability.DayTotal{
		{Name: "stock.pref", Value: "a", N: 8, Days: 1, First: day, Last: day}, {Name: "stock.pref", Value: "b", N: 6, Days: 1, First: day, Last: day},
		{Name: "stock.favorites", Value: "0", N: 8, Days: 1, First: day, Last: day}, {Name: "stock.favorites", Value: "1+", N: 2, Days: 1, First: day, Last: day},
	}
	_, groups := metricsStockGroups(names, rows)
	if len(groups) != 2 || !groups[0].Several || groups[1].Several {
		t.Fatalf("groups %+v", groups)
	}
	v := metricsShellFor("overview")
	v.Overview = &MetricsOverview{LiveKnown: true, Stock: groups, StockDay: day}
	html := metricsPage(t, v)
	if strings.Count(html, `<th class="num">Rows</th>`) != 1 || strings.Count(html, `<th class="num">Share</th>`) != 1 {
		t.Errorf("one Rows table and one Share table:\n%s", html)
	}
}

// D1: one deadline over a Metrics request, made from the request.
func TestMetricsRequestHasOneDeadline(t *testing.T) {
	ctx, cancel := metricsContext(httptest.NewRequest(http.MethodGet, "/admin?page=metrics", nil))
	defer cancel()
	dl, ok := ctx.Deadline()
	if left := time.Until(dl); !ok || left > metricsRequestTimeout || left < metricsRequestTimeout-5*time.Second || metricsRequestTimeout != 20*time.Second {
		t.Errorf("deadline %v away, set %v", left, ok)
	}
}

// D1: past the deadline, every load fails as unread and the view still renders.
func TestAnEndedRequestReadsNothingAndRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, view := range []string{"overview", "remove", "invest", "feature", "health", "explore"} {
		v := loadMetricsViewFor(ctx, store, testCache(store), metricsTestRegistry(), metricsTestLists, metricsParams{View: view, Instance: "magic", Days: 90, Name: "search.sort"}, loaderTestNow)
		if !v.Failed {
			t.Errorf("%s: not marked failed", view)
		}
		metricsPage(t, v)
	}
	if n := store.dayTotalCount(); n != 0 || store.throughCalls != 0 || len(store.visitCalls) != 0 {
		t.Errorf("an ended request reached the store: %d queries, %d through, %d visits", n, store.throughCalls, len(store.visitCalls))
	}
}

// blockingStore holds every bundle load until released, saying when the first one started.
type blockingStore struct {
	*fakeMetricsStore
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockingStore) DayTotals(ctx context.Context, q observability.DayQuery) ([]observability.DayTotal, error) {
	if q.Step == 30 && q.Days > 30 {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.fakeMetricsStore.DayTotals(ctx, q)
}

// D1: a request whose deadline passes during a hung load returns, and its page renders; the load goes on for others.
func TestAHungLoadDoesNotHoldTheRequest(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := &blockingStore{fakeMetricsStore: newFakeMetrics(), entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(store.release) })
	cache := testCache(store)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *MetricsView, 1)
	go func() {
		done <- loadMetricsViewFor(ctx, store, cache, metricsTestRegistry(), metricsTestLists, metricsParams{View: "remove", Instance: "magic", Days: 90}, loaderTestNow)
	}()
	<-store.entered
	cancel()
	select {
	case v := <-done:
		if !v.Failed || !v.Remove.Read.Failed {
			t.Errorf("failed %v, remove read %+v", v.Failed, v.Remove.Read)
		}
		wantAll(t, metricsPage(t, v), "a hung load", metricsReadFailedText)
	case <-time.After(10 * time.Second):
		t.Fatal("the request waited on the hung load past its own end")
	}
}

// C1: every mark of the instance is listed, one whose unit is gone by its stored key, clear only.
func TestAReviewWhoseRowIsGoneIsListed(t *testing.T) {
	withMetricsInstance(t, "magic")
	reviews := []observability.Review{
		{Instance: "magic", Name: "page.view", Value: "hidden", Verdict: "remove", Note: "page hidden"},
		{Instance: "magic", Name: "retired.name", Scope: "s<b>", Value: "v", Verdict: "keep"},
		{Instance: "magic", Name: "search.sort", Value: "alpha", Verdict: "watch"},
	}
	p := metricsParams{View: "remove", Instance: "magic", Days: 90}
	view := buildMetricsRemove(metricsTestRegistry(), metricsTestLists, removeFixture(), nil, true, reviews, 180, p)
	var gone, kept []string
	for _, r := range view.Reviewed {
		if r.Gone {
			gone = append(gone, r.Key)
		} else {
			kept = append(kept, r.Key)
		}
	}
	if !slices.Equal(gone, []string{"page.view||hidden", "retired.name|s<b>|v"}) || !slices.Equal(kept, []string{"search.sort||alpha"}) {
		t.Fatalf("gone %q, kept %q", gone, kept)
	}
	v := metricsShellFor("remove")
	v.Remove = view
	v.Remove.Counted = true
	html := metricsSection(t, v, false)
	wantAll(t, html, "a gone mark", "Reviewed (3)", `<span class="admin-mono">retired.name</span> on s&lt;b&gt;: v <span class="admin-metrics-dim">no longer listed</span>`,
		`<input type="hidden" name="reviewVerdict" value="clear">`, "page hidden")
	wantNone(t, html, "a gone mark", "s<b>")
	if n := strings.Count(html, `name="reviewVerdict" value="clear"`); n != 2 {
		t.Errorf("%d clear-only forms, want 2", n)
	}
}

// C1: a clear takes a stored mark for a unit no longer listed; a save still needs a candidate.
func TestAReviewWhoseRowIsGoneCanBeCleared(t *testing.T) {
	stored := []observability.Review{{Instance: "lorcana", Name: "retired.name", Scope: "s", Value: "v", Verdict: "keep"}}
	form := url.Values{"reviewName": {"retired.name"}, "reviewScope": {"s"}, "reviewValue": {"v"}, "reviewVerdict": {"clear"}}
	store := &fakeMetricsStore{reviews: stored}
	rec, pv := reviewDone(t, "/admin?page=metrics&view=remove", "lorcana", form, store)
	if rec.Code != http.StatusSeeOther || !slices.Equal(store.deleted, []string{"lorcana|retired.name|s|v"}) {
		t.Errorf("clear: status %d, deleted %q, warning %q", rec.Code, store.deleted, pv.WarningMessage)
	}
	form.Set("reviewVerdict", "watch")
	store = &fakeMetricsStore{reviews: stored}
	if rec, pv := reviewDone(t, "/admin?page=metrics&view=remove", "lorcana", form, store); rec.Code == http.StatusSeeOther || len(store.saved) != 0 || pv.WarningMessage != metricsReviewNoCandidate {
		t.Errorf("save: status %d, saved %d, warning %q", rec.Code, len(store.saved), pv.WarningMessage)
	}
	form.Set("reviewVerdict", "clear")
	form.Set("reviewValue", "unstored")
	store = &fakeMetricsStore{reviews: stored}
	if rec, pv := reviewDone(t, "/admin?page=metrics&view=remove", "lorcana", form, store); rec.Code == http.StatusSeeOther || len(store.deleted) != 0 || pv.WarningMessage != metricsReviewNoCandidate {
		t.Errorf("clear of an unstored key: status %d, deleted %q, warning %q", rec.Code, store.deleted, pv.WarningMessage)
	}
}

// N1: a look-back that fails says stored state could not be read, in the block and the note.
func TestAFailedStockLookBackIsNotAFinding(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = fullRows("metrics.flush", "", "", 1, 6)
	store.stockLastErr = errors.New("slow")
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 90})
	if v.Overview.StockStale != "" || !v.Overview.StockRead.Failed || !slices.Contains(v.Notes, "Stored state: could not be read.") {
		t.Errorf("stale %q, read %+v, notes %v", v.Overview.StockStale, v.Overview.StockRead, v.Notes)
	}
	html := metricsPage(t, v)
	wantAll(t, html, "a failed look-back", "Stored state: could not be read.", metricsReadFailedText)
	wantNone(t, html, "a failed look-back", "nightly count", "Stored state: not measured")
}

// N2: a review write runs on the request's own context, so a page deadline already passed does not fail it.
func TestAReviewWriteOutlivesThePageDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, verdict := range []string{"keep", "clear"} {
		store := &fakeMetricsStore{}
		var pv PageVars
		rec := httptest.NewRecorder()
		form := url.Values{"reviewName": {"page.view"}, "reviewValue": {"screener"}, "reviewVerdict": {verdict}}
		done := adminMetricsReview(ctx, rec, postForm("/admin?page=metrics&view=remove", form), store, metricsreport.Lists{Pages: []string{"screener"}},
			metricsParams{View: "remove", Instance: "lorcana", Days: 90}, &pv)
		if !done || rec.Code != http.StatusSeeOther || len(store.saved)+len(store.deleted) != 1 {
			t.Errorf("%s: done %v, status %d, saved %d, deleted %d, warning %q", verdict, done, rec.Code, len(store.saved), len(store.deleted), pv.WarningMessage)
		}
	}
}

// O1: the minute rows' reach comes from Go, never a literal in a partial.
func TestPartialsWriteNoMinuteDays(t *testing.T) {
	files, err := filepath.Glob("templates/partials/admin-metrics*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("listing the partials: %v", err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(src); strings.Contains(s, "14 days") || strings.Contains(s, " 14 ") {
			t.Errorf("%s writes the 14 itself", f)
		}
	}
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	h := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "health", Instance: "magic", Days: 90})
	want := fmt.Sprintf("Job runs reach back %d days", metricsreport.MinuteDays)
	wantAll(t, metricsPage(t, h), "health", want, fmt.Sprintf("last %d days, on any site", metricsreport.MinuteDays))
}

// O4: the Overview says its phone rows cover the last 30 complete days whatever the window.
func TestOverviewSaysWhatThePhoneRowsCover(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = fullRows("metrics.flush", "", "", 1, 6)
	v := loadTestView(t, store, testCache(store), metricsTestRegistry(), metricsParams{View: "overview", Instance: "magic", Days: 180})
	wantAll(t, metricsPage(t, v), "the overview", "Phone rows cover the last 30 complete days of page hits, whatever the window above.")
}
