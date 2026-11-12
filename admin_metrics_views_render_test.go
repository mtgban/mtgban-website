package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/metricsreport"
	"github.com/mtgban/mtgban-website/observability"
)

// renderViewRegistry is featureTestRegistry with an area whose only name is not counted in Areas.
func renderViewRegistry() []observability.Name {
	return append(featureTestRegistry(),
		observability.Name{Name: "site.build", Area: "ops", Report: observability.ReportContext, Help: "The build the site runs."})
}

// renderView loads a view the way the admin page does, from a fake store's rows.
func renderView(t *testing.T, store *fakeMetricsStore, names []observability.Name, p metricsParams) *MetricsView {
	t.Helper()
	if p.Instance == "" {
		p.Instance = "magic"
	}
	if p.Days == 0 {
		p.Days = 30
	}
	return loadTestView(t, store, testCache(store), names, p)
}

const metricsNotYet = "No complete day yet: the first nightly summary has not run."

// metricsAreasNoteStart opens the line that says what an Areas number is.
const metricsAreasNoteStart = "Each number is a sum of everything counted in the area."

func TestFeatureIndexRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{{Period: 0, Name: "search.sort", Value: "alpha", N: 7, Days: 3}}
	v := renderView(t, store, renderViewRegistry(), metricsParams{View: "feature"})
	html := metricsPage(t, v)
	wantAll(t, html, "a counted index", `<th class="num">Counted events</th>`, `<td class="num admin-mono">7</td>`, metricsAreasNoteStart,
		hrefOf(v.Feature.Areas[0].URL)+">search</a>", "<h2>Other areas</h2>", hrefOf("?page=metrics&view=feature&area=ops&days=30")+">ops</a>",
		"events counted in the window")
	wantNone(t, html, "a counted index", metricsNotYet, metricsReadFailedText)

	store = newFakeMetrics()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "feature"}))
	wantAll(t, html, "an index before a fold", metricsNotYet, ">search</a>")
	wantNone(t, html, "an index before a fold", "Counted events</th>", `<td class="num admin-mono">0</td>`, "events counted in the window")

	store = newFakeMetrics()
	store.totalsErr = errors.New("down")
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "feature"}))
	wantAll(t, html, "an index that could not be read", metricsReadFailedText, ">search</a>")
	wantNone(t, html, "an index that could not be read", "Counted events</th>", metricsNotYet)
}

// areaFixture is the search area's counts and lines, and the account area's stored state.
func areaFixture() *fakeMetricsStore {
	store := newFakeMetrics()
	store.totals = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Value: "alpha", N: 5, Days: 20},
		{Period: 0, Name: "search.result", Value: "found", N: 1000, Days: 30},
	}
	store.named = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Value: "alpha", N: 3, Days: 1},
		{Period: 2, Name: "search.sort", Value: "alpha", N: 2, Days: 1},
	}
	store.stock = stockFixture()
	return store
}

func TestFeatureAreaRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	v := renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature", Area: "search"})
	html := metricsPage(t, v)
	wantAll(t, html, "a counted area", "<h2>search</h2>", "3 metrics",
		hrefOf(v.Feature.Names[0].URL)+` class="admin-mono">search.sort</a>`,
		`<span class="admin-metrics-help">Order the results were sorted in.</span>`,
		"Server, option", "0.50% of results page views",
		// search.filter is counted against page views, which had none; search.result on days
		"no rate: what it is counted against had no rows in this window", "no rate, measured in days",
		`<canvas id="metrics-spark-0"`, "<th>Last 30 days</th>",
		// the numbers behind each line, as a table
		`<span class="admin-mono">search.sort</span> <span class="admin-metrics-dim">by day, 30 days</span>`,
		`<tr><td class="admin-mono">2026-11-10</td><td class="num admin-mono">3</td></tr>`)
	wantNone(t, html, "a counted area", "0.0%", metricsNotYet, metricsReadFailedText, "too few to say")
	if mobile := metricsSection(t, v, true); strings.Contains(mobile, "<canvas") || !strings.Contains(mobile, "2026-11-10") {
		t.Error("the mobile area page draws a canvas or lacks the table")
	}

	// A stored-state name is its standing count on the newest day, never a sum.
	html = metricsPage(t, renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature", Area: "account"}))
	wantAll(t, html, "a stored-state row", `<td class="num admin-mono">400</td>`, "standing count on Nov 10, 2026, not a sum", "Stored state")

	store := areaFixture()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "feature", Area: "search"}))
	wantAll(t, html, "an area before a fold", metricsNotYet, "no complete day yet</span>")
	wantNone(t, html, "an area before a fold", `<td class="num admin-mono">0</td>`, "0.50%", "no rate", "<canvas", metricsReadFailedText)

	store = areaFixture()
	store.totalsErr = errors.New("down")
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "feature", Area: "search"}))
	wantAll(t, html, "an area that could not be read", metricsReadFailedText, "could not be read</span>")
	wantNone(t, html, "an area that could not be read", `<td class="num admin-mono">0</td>`, "no rate", metricsNotYet)
}

// nameFixture is search.sort's rows and splits.
func nameFixture() *fakeMetricsStore {
	store := newFakeMetrics()
	store.named = []observability.DayTotal{
		{Period: 0, Name: "search.sort", Scope: "search", Value: "alpha", N: 30, Days: 1, First: loaderTestDay, Last: loaderTestDay},
		{Period: 3, Name: "search.sort", Scope: "sets", Value: "alpha", N: 10, Days: 1},
	}
	store.byTier = []observability.DayTotal{{Name: "search.sort", Tier: "Any", N: 30}, {Name: "search.sort", Tier: "Legacy", N: 10}}
	store.byDevice = []observability.DayTotal{{Name: "search.sort", Device: "desktop", N: 40}}
	return store
}

func TestFeatureNameRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "feature", Name: "search.sort"}
	v := renderView(t, nameFixture(), renderViewRegistry(), p)
	html := metricsPage(t, v)
	wantAll(t, html, "a counted name",
		`<h2 class="admin-mono">search.sort</h2>`, "Server, option",
		`<p class="admin-metrics-lead">Order the results were sorted in.</p>`,
		hrefOf(v.Feature.AreaURL)+">Area: search</a>", hrefOf(v.Feature.ExploreURL)+">Explore every scope and value</a>",
		`Total in the last 30 days through Nov 10, 2026: <span class="admin-mono">40</span>`,
		`<canvas id="metrics-days"`, "The numbers by day (30 days)",
		`<tr><td class="admin-mono">2026-11-07</td><td class="num admin-mono">10</td></tr>`,
		"<h2>By value</h2>", "<h2>By scope</h2>", "<h2>By reader tier</h2>", "<h2>By device</h2>",
		`<td class="admin-metrics-name">alpha</td><td class="num admin-mono">40</td><td class="num admin-mono">100.0%</td>`,
		`<td class="admin-metrics-name">price</td><td class="num admin-mono">0</td>`,
		`<td class="admin-metrics-name">Any</td><td class="num admin-mono">30</td><td class="num admin-mono">75.0%</td>`)
	wantNone(t, html, "a counted name", metricsNotYet, metricsReadFailedText, "standing count")
	if mobile := metricsSection(t, v, true); strings.Contains(mobile, "<canvas") || !strings.Contains(mobile, "2026-11-07") {
		t.Error("the mobile name page draws a canvas or lacks the table")
	}

	html = metricsPage(t, renderView(t, newFakeMetrics(), renderViewRegistry(), p))
	wantAll(t, html, "a counted name with no rows", "No rows for this metric in the last 30 days.")
	wantNone(t, html, "a counted name with no rows", "Total in", "<h2>By value</h2>", "0.0%")

	store := nameFixture()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a name before a fold", metricsNotYet, "Order the results were sorted in.")
	wantNone(t, html, "a name before a fold", "Total in", "No rows", "<h2>By value</h2>", "<canvas")

	store = nameFixture()
	store.totalsErr = errors.New("down")
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a name that could not be read", metricsReadFailedText)
	wantNone(t, html, "a name that could not be read", "Total in", "No rows", "<h2>By value</h2>", metricsNotYet)
}

func TestFeatureStoredStateNameRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	store.stock = stockFixture()
	p := metricsParams{View: "feature", Instance: "lorcana", Name: "stock.rows"}
	html := metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a stored-state name",
		`Standing count on Nov 10, 2026: <span class="admin-mono">400</span>`,
		"It is not a sum over the window", "standing count each night", "Stored state",
		"Stored-state counts are not split by reader tier or device.",
		`<td class="admin-metrics-name">magic</td><td class="num admin-mono">300</td><td class="num admin-mono">75.0%</td>`)
	wantNone(t, html, "a stored-state name", "Total in the last", "<h2>By reader tier</h2>", "pokemon")

	html = metricsPage(t, renderView(t, newFakeMetrics(), renderViewRegistry(), p))
	wantAll(t, html, "a stored-state name with no row", "No row of this metric on the newest stored-state day.")
	wantNone(t, html, "a stored-state name with no row", "Standing count on", "<canvas")
}

// An unknown name says so and never echoes what was asked for.
func TestUnknownMetricNameRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	const asked = `nope&"><b>x</b>`
	for _, view := range []string{"feature", "explore"} {
		p := readMetricsParams(url.Values{"view": {view}, "name": {asked}}.Get, []string{"magic"})
		html := metricsPage(t, renderView(t, newFakeMetrics(), renderViewRegistry(), p))
		wantAll(t, html, view, "No such metric: the name asked for is not in this site's list of metrics.")
		wantNone(t, html, view, "nope", "<b>x</b>", "&lt;b&gt;")
	}
}

// healthyStore is every counter, job and check fine.
func healthyStore() *fakeMetricsStore {
	store := newFakeMetrics()
	store.health = []observability.InstanceHealth{{Instance: "magic", LastFlush: loaderTestNow.Add(-time.Minute), Rows: 1200, Rejected: 2}}
	for _, job := range []string{"fold", "stock", "events_rollup"} {
		store.jobs = append(store.jobs, observability.JobRun{Instance: "magic", Job: job, Result: "ok", At: loaderTestNow.Add(-time.Hour)})
	}
	return store
}

func TestHealthRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "health"}
	v := renderView(t, healthyStore(), renderViewRegistry(), p)
	if !v.Health.Checked || len(v.Health.Problems) != 0 {
		t.Fatalf("health = %+v", v.Health)
	}
	html := metricsPage(t, v)
	wantAll(t, html, "a healthy view",
		"Health always covers every reader and bot, and the window, reader and bot settings do not change it.",
		"<h2>Problems for magic</h2>", "<p>No problems found.</p>", "none found",
		`<th class="num">Rows yesterday</th>`, "Rows are yesterday's only.",
		`<td class="admin-metrics-name">magic <span class="admin-metrics-dim">(this view)</span></td>`, "<td>live</td>",
		`<td class="admin-mono">Nov 11 11:59</td>`, `<td class="num admin-mono">1200</td>`,
		`<td class="admin-mono">fold</td>`, "ran on time", "Nov 11 11:00, succeeded on magic",
		// L10
		"Scheduled only where the user-state database is configured.",
		// both every-view counts are quiet: their pages had no views
		"Missing, and their pages had no views", hrefOf("?page=metrics&view=feature&name=news.report")+` class="admin-mono">news.report</a>`,
		"Client: not measured.", "Script errors: not measured.")
	wantNone(t, html, "a healthy view", "could not be fully checked", "Missing although their pages had views", "<canvas",
		// the window, reader and bot settings do nothing here, so they are not offered
		`aria-label="Window"`, `aria-label="Readers"`, `aria-label="Bots"`, "Include bots", "last 30 days")
	wantAll(t, html, "a healthy view", `aria-label="Site"`)

	// Nothing complete yet: no claim that nothing is wrong.
	store := healthyStore()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "health before a fold", "Health could not be fully checked:", "not fully checked",
		"<li>Missing counts are checked only after the first nightly summary has run.</li>", metricsNotYet)
	wantNone(t, html, "health before a fold", "No problems found", "none found", "Every count checked has rows")

	// Counters unread: neither tables nor a clean bill.
	store = healthyStore()
	store.healthErr = errors.New("down")
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "unread counters", "<li>Counters and job runs could not be read.</li>", metricsReadFailedText)
	wantNone(t, html, "unread counters", "No problems found", "ran on time", "(this view)", "This build has no metrics jobs")

	// The missing-counts read failed, and the problems found are still listed.
	store = healthyStore()
	store.totalsErr = errors.New("down")
	store.health[0].Dropped = 3
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a failed silent read", "<li>Counters: 3 events dropped since yesterday</li>",
		"Health could not be fully checked, so there may be more:", "<li>Missing counts could not be read.</li>")
	wantNone(t, html, "a failed silent read", "No problems found", "Every count checked has rows")

	// A broken count, read on a complete day.
	store = healthyStore()
	store.totals = []observability.DayTotal{{Period: 0, Name: "page.view", Value: "reverse", N: 5, Days: 3}}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a broken count", "Missing although their pages had views", "An arbit page view.",
		"<li>1 count missing for 30 days although its pages were used</li>")
	wantNone(t, html, "a broken count", "No problems found")
}

func TestHealthJobAndCounterRowsRender(t *testing.T) {
	withMetricsInstance(t, "magic")
	savedCounter := FeatureCounter
	FeatureCounter = nil
	t.Cleanup(func() { FeatureCounter = savedCounter })
	store := newFakeMetrics()
	store.health = []observability.InstanceHealth{{Instance: "pokemon", LastFlush: loaderTestNow.Add(-time.Hour), Dropped: 4, FlushFailed: 1}}
	store.jobs = []observability.JobRun{
		{Instance: "magic", Job: "fold", Result: "ok", At: loaderTestNow.Add(-time.Hour)},
		{Instance: "lorcana", Job: "stock", Result: "ok", At: loaderTestNow.Add(-50 * time.Hour)},
		{Instance: "lorcana", Job: "stock", Result: "fail", At: loaderTestNow.Add(-2 * time.Hour)},
	}
	v := renderView(t, store, renderViewRegistry(), metricsParams{View: "health", Instance: "lorcana"})
	if len(v.Health.Jobs) != 3 || v.Health.Jobs[1].Problem == "" || v.Health.Jobs[2].Problem == "" {
		t.Fatalf("jobs = %+v", v.Health.Jobs)
	}
	html := metricsPage(t, v)
	wantAll(t, html, "health rows",
		// rows with nothing written print their reason, not zeros
		`<td colspan="6" class="admin-metrics-wrap">No counts received since the start of yesterday.</td>`,
		`<td colspan="6" class="admin-metrics-wrap">The counter is not running on this site.</td>`,
		`lorcana <span class="admin-metrics-dim">(this view)</span>`,
		"<td>not saving</td>", `<td class="num admin-mono">4</td>`,
		"ran on time", "last run failed", "no run in the last 14 days",
		"Nov 11 10:00, failed on lorcana", `<td class="admin-metrics-wrap">Nov 9 10:00</td>`,
		`<td class="admin-metrics-wrap">none in 14 days</td>`,
		// a job's problem is said once, in the problems list, not again in its row
		"<li>"+v.Health.Jobs[1].Problem+"</li>", "<li>"+v.Health.Jobs[2].Problem+"</li>",
		`<span class="admin-metrics-dim">Scheduled only where the user-state database is configured.</span>`)
	wantNone(t, html, "health rows", "<td class=\"admin-metrics-wrap\">"+v.Health.Jobs[1].Problem, ">never<", "flush")
	// events_rollup never ran: both its last run and its last success say so
	if n := strings.Count(html, `<td class="admin-metrics-wrap">none in 14 days</td>`); n != 2 {
		t.Errorf("none in 14 days %d times, want 2", n)
	}
	if strings.Count(html, v.Health.Jobs[1].Problem) != 1 {
		t.Errorf("the stock job's problem is said %d times", strings.Count(html, v.Health.Jobs[1].Problem))
	}

	store.jobs = []observability.JobRun{{Instance: "magic", Job: "fold", Result: "ok", At: loaderTestNow.Add(-40 * time.Hour)}}
	wantAll(t, metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "health"})), "an overdue job",
		"overdue: no successful run in 36 hours")

	var noJobs []observability.Name
	for _, n := range renderViewRegistry() {
		if n.Name != "job.run" {
			noJobs = append(noJobs, n)
		}
	}
	wantAll(t, metricsPage(t, renderView(t, store, noJobs, metricsParams{View: "health"})), "no job.run",
		"This build has no metrics jobs.")
}

func TestHealthClientRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := healthyStore()
	store.client = []observability.DayTotal{{Name: "metrics.client", Value: "unknown", N: 50}, {Name: "metrics.client", Value: "accepted", N: 950}}
	html := metricsPage(t, renderView(t, store, beaconTestRegistry(), metricsParams{View: "health"}))
	wantAll(t, html, "client rows", `<td class="admin-metrics-wrap">unknown</td><td class="num admin-mono">50</td><td class="num admin-mono">5.0%</td>`,
		`<span class="admin-metrics-help">Client counts, by outcome.</span>`, "<p>No problems found.</p>")
	wantNone(t, html, "client rows", "Client: not measured")

	store.client = nil
	wantAll(t, metricsPage(t, renderView(t, store, beaconTestRegistry(), metricsParams{View: "health"})), "no client rows",
		"<p>No reports in the last 7 complete days.</p>")

	store = healthyStore()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, beaconTestRegistry(), metricsParams{View: "health"}))
	wantAll(t, html, "client before a fold", "<li>Browser report outcomes are checked only after the first nightly summary has run.</li>")
	wantNone(t, html, "client before a fold", "No reports in", "No problems found")
}

func TestExploreRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "explore", Instance: "lorcana", Days: 90, Bots: true}
	v := renderView(t, newFakeMetrics(), renderViewRegistry(), p)
	html := metricsPage(t, v)
	wantAll(t, html, "the picker",
		`<form method="GET" action="/admin" class="admin-metrics-picker">`,
		`<input type="hidden" name="page" value="metrics">`, `<input type="hidden" name="view" value="explore">`,
		`<input type="hidden" name="bots" value="1">`, `<input type="hidden" name="instance" value="lorcana">`,
		`<select id="metrics-explore-name" name="name">`, `<optgroup label="Server: search">`,
		`<option value="search.sort">search.sort</option>`, "<h2>Every metric</h2>",
		`<summary>Stored state: account <span class="admin-metrics-dim">1</span></summary>`)
	wantNone(t, html, "the picker", `name="days"`, `name="hourly"`, "No such metric", "<canvas")
	for _, g := range v.Explore.Groups {
		for _, n := range g.Names {
			wantAll(t, html, "the picker", hrefOf(n.URL)+` class="admin-mono">`+n.Label+"</a>")
		}
	}

	store := newFakeMetrics()
	store.named = []observability.DayTotal{
		{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 10, Days: 1},
		{Period: 5, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 20, Days: 1},
		{Period: 1, Name: "auth.refuse", Scope: "arbit", Value: "", N: 10, Days: 1},
	}
	p = metricsParams{View: "explore", Days: 90, Name: "auth.refuse"}
	v = renderView(t, store, renderViewRegistry(), p)
	html = metricsPage(t, v)
	wantAll(t, html, "one name by day",
		`<option value="auth.refuse" selected>auth.refuse</option>`,
		`<h2 class="admin-mono">auth.refuse</h2>`, "last 90 days through Nov 10, 2026",
		`<p class="admin-metrics-lead">Requests refused at the door.</p>`,
		hrefOf(v.Explore.FeatureURL)+">Feature page</a>", hrefOf(v.Explore.HourlyLink.URL)+">By hour, last 14 days</a>",
		`Total: <span class="admin-mono">40</span>`, "By scope and value (2)",
		`<td class="admin-metrics-wrap">search</td><td class="admin-metrics-wrap">no_access</td><td class="num admin-mono">30</td><td class="num admin-mono">75.0%</td>`,
		`<span class="admin-metrics-dim">no value</span>`,
		`<canvas id="metrics-explore"`, "The numbers by day (90 days)", "<th>Day</th>")
	if mobile := metricsSection(t, v, true); strings.Contains(mobile, "<canvas") || !strings.Contains(mobile, "The numbers by day") {
		t.Error("the mobile explore page draws a canvas or lacks the table")
	}

	html = metricsPage(t, renderView(t, newFakeMetrics(), renderViewRegistry(), p))
	wantAll(t, html, "a name with no rows", "No rows for this metric in the last 90 days.")
	wantNone(t, html, "a name with no rows", "Total:", "0.0%")

	store = newFakeMetrics()
	store.folded, store.through = false, time.Time{}
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a name before a fold", metricsNotYet)
	wantNone(t, html, "a name before a fold", "Total:", "No rows")

	store = newFakeMetrics()
	store.totalsErr = errors.New("down")
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), p))
	wantAll(t, html, "a name that could not be read", metricsReadFailedText)
	wantNone(t, html, "a name that could not be read", "Total:", "No rows", metricsNotYet)
}

func TestExploreHourlyRenders(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := newFakeMetrics()
	since := time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC)
	store.hours = []observability.HourTotal{{Hour: since, Scope: "search", Value: "no_access", N: 3}}
	p := metricsParams{View: "explore", Days: 90, Name: "auth.refuse", Hourly: true}
	v := renderView(t, store, renderViewRegistry(), p)
	if v.Explore.HourlyLink.URL != "?page=metrics&view=explore&name=auth.refuse" {
		t.Errorf("the by-day link is %q", v.Explore.HourlyLink.URL)
	}
	html := metricsPage(t, v)
	wantAll(t, html, "the hourly view",
		"by hour since Oct 28 13:00 UTC", "showing by hour, last 14 days; <a "+hrefOf(v.Explore.HourlyLink.URL)+">show by day</a>",
		"does not wait for the nightly summary", `<input type="hidden" name="hourly" value="1">`,
		"<h2>By hour</h2>", "The numbers by hour (336 hours, UTC)", "<th>Hour</th>",
		`<tr><td class="admin-mono">2026-10-28 13:00</td><td class="num admin-mono">3</td></tr>`,
		// a group link keeps the hourly view, except for a stored-state name, which has none
		hrefOf("?page=metrics&view=explore&hourly=1&name=search.sort"), hrefOf("?page=metrics&view=explore&name=stock.rows"))
	wantNone(t, html, "the hourly view", ">By hour, last 14 days</a>", "last 90 days through")

	store = newFakeMetrics()
	store.stock = stockFixture()
	html = metricsPage(t, renderView(t, store, renderViewRegistry(), metricsParams{View: "explore", Days: 90, Name: "stock.rows", Hourly: true}))
	wantAll(t, html, "a stored-state name", "standing count on Nov 10, 2026", "not a sum over the window", "standing count each night",
		`<td class="admin-metrics-wrap">magic</td>`)
	wantNone(t, html, "a stored-state name", "By hour, last 14 days", "pokemon")
}

func TestMetricsViewsTextIsEscaped(t *testing.T) {
	const evil = `x&y'"><script>alert(1)</script>`
	const escaped = `x&amp;y&#39;&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`
	views := map[string]*MetricsView{}

	area := metricsShellFor("feature")
	area.Feature = &MetricsFeature{Area: evil, Counted: true, Names: []MetricsNameRow{
		{Name: evil, Kind: evil, Help: evil, Family: evil, Counted: true, Count: 3, RateText: evil, SparkID: evil, URL: "?page=metrics&view=feature&name=" + url.QueryEscape(evil)},
		{Name: "b", Counted: true, NoRate: evil}}}
	area.Charts = []MetricsChart{{ID: evil, Labels: []string{evil}, Series: []MetricsSeries{{Data: []int64{1}}}}}
	views["feature area"] = area

	name := metricsShellFor("feature")
	n := observability.Name{Name: evil, Help: evil, Kind: evil, Area: evil}
	name.Feature = &MetricsFeature{Name: &n, Family: evil, Counted: true, HasRows: true, Total: 1, DaysID: evil,
		AreaURL: "?page=metrics&view=feature&area=" + url.QueryEscape(evil), ExploreURL: "?x",
		Values: []MetricsShare{{Label: evil, N: 1, Share: 1}}, Tiers: []MetricsShare{{Label: evil, N: 1, Share: 1}}}
	views["feature name"] = name

	index := metricsShellFor("feature")
	index.Feature = &MetricsFeature{Counted: true, Areas: []MetricsAreaRow{{Area: evil, URL: "?a"}}, OtherAreas: []MetricsAreaRow{{Area: evil, URL: "?b"}}}
	views["feature index"] = index

	health := metricsShellFor("health")
	health.Health = &MetricsHealth{Problems: []string{evil}, Unchecked: []string{evil},
		Counters:      []MetricsCounterRow{{Instance: evil, Current: true}, {Instance: "b", NoRows: true, Reason: evil}},
		Jobs:          []MetricsJobRow{{Job: evil, StatusText: evil, Instance: evil, Result: "fail", At: metricsRenderDay, Runners: []string{evil}, Problem: evil, Note: evil}},
		SilentCounted: true, Broken: []MetricsNameLink{{Name: evil, Help: evil, URL: "?c"}},
		ClientMeasured: true, ClientCounted: true, Client: []MetricsClientRow{{Name: evil, Reason: evil, Help: evil, N: 1, Share: 1}}}
	views["health"] = health

	explore := metricsShellFor("explore")
	explore.Explore = &MetricsExplore{Name: evil, Help: evil, Counted: true, Total: 1, LineID: evil, FeatureURL: "?d",
		Hidden:     []MetricsField{{Key: evil, Value: evil}},
		Groups:     []MetricsNameGroup{{Label: evil, Names: []MetricsLink{{Label: evil, URL: "?e"}}}},
		Rows:       []MetricsExploreRow{{Scope: evil, Value: evil, N: 1, Share: 1}},
		HourlyLink: MetricsLink{Label: evil, URL: "?f"}}
	explore.Charts = []MetricsChart{{ID: evil, Labels: []string{evil}, Series: []MetricsSeries{{Data: []int64{1}}}}}
	views["explore"] = explore

	attrs := map[string][]string{
		"feature area": {`id="` + escaped + `"`, `aria-label="` + escaped + ` by day"`, hrefOf(area.Feature.Names[0].URL)},
		"feature name": {`id="` + escaped + `"`, hrefOf(name.Feature.AreaURL)},
		"health":       {`<tr title="` + escaped + `">`},
		"explore": {`id="` + escaped + `"`, `<optgroup label="` + escaped + `">`, `<option value="` + escaped + `">`,
			`name="` + escaped + `" value="` + escaped + `"`},
	}
	for label, v := range views {
		html := metricsPage(t, v)
		wantNone(t, html, label, "<script>alert(1)", `"><script`, `'"><`)
		wantAll(t, html, label, ">"+escaped+"<")
		wantAll(t, html, label, attrs[label]...)
	}
}

// A view the shell does not know renders the shell and nothing else.
func TestMetricsShellIgnoresAnUnknownView(t *testing.T) {
	v := metricsShellFor("overview")
	v.View = "trends"
	html := metricsSection(t, v, false)
	wantAll(t, html, "an unknown view", `class="admin-metrics"`)
	wantNone(t, html, "an unknown view", "admin-section")
}

// -dev parses per request through the same file list; the new views render what the cache does.
func TestMetricsNewViewsDevRenderMatchesTheCache(t *testing.T) {
	withMetricsInstance(t, "magic")
	for _, v := range []*MetricsView{
		renderView(t, nameFixture(), renderViewRegistry(), metricsParams{View: "feature", Name: "search.sort"}),
		renderView(t, healthyStore(), renderViewRegistry(), metricsParams{View: "health"}),
		renderView(t, newFakeMetrics(), renderViewRegistry(), metricsParams{View: "explore", Name: "auth.refuse"}),
	} {
		dev := lfOnly(renderAdminPage(t, PageVars{Page: "metrics", AdminVars: AdminVars{Metrics: v}}))
		if cached := metricsPage(t, v); dev != cached {
			t.Errorf("%s: the dev render and the cached render differ", v.View)
		}
	}
}

// A counter that saved today with no rows yesterday does not read as a live 0, and the legend explains two columns.
func TestHealthCounterRowsSayWhatTheyCover(t *testing.T) {
	withMetricsInstance(t, "magic")
	store := healthyStore()
	store.health[0].Rows = 0
	names := append(renderViewRegistry(),
		observability.Name{Name: "metrics.dropped", Report: observability.ReportInternal, Help: "Counts dropped because the counter was full."},
		observability.Name{Name: "metrics.rejected", Report: observability.ReportInternal, Help: "Counts the registry refused to store."})
	html := metricsPage(t, renderView(t, store, names, metricsParams{View: "health"}))
	wantAll(t, html, "a counter started today",
		`<td class="num admin-mono"><span class="admin-metrics-dim">none yesterday; saved today</span></td>`,
		"<li>Dropped: Counts dropped because the counter was full.</li>", "<li>Rejected: Counts the registry refused to store.</li>")
	wantNone(t, html, "a counter started today", `<td class="num admin-mono">0</td><td class="num admin-mono">0</td><td class="num admin-mono">0</td><td class="num admin-mono">2</td>`)
	wantNone(t, metricsPage(t, renderView(t, healthyStore(), renderViewRegistry(), metricsParams{View: "health"})), "no registry help", "<li>Dropped:")
}

// Each share table heads its first column with what its rows are.
func TestShareTablesNameTheirRows(t *testing.T) {
	withMetricsInstance(t, "magic")
	html := metricsPage(t, renderView(t, nameFixture(), renderViewRegistry(), metricsParams{View: "feature", Name: "search.sort"}))
	wantAll(t, html, "the name page", "<th>Value</th>", "<th>Scope</th>", "<th>Tier</th>", "<th>Device</th>")
	wantNone(t, html, "the name page", "<th>Part</th>")
}

// One metric reads the same on every view: a missing rate gives the package's reason on Remove and the Overview.
func TestRemoveAndOverviewSayWhyARateIsMissing(t *testing.T) {
	names := append(renderRemoveRegistry(),
		observability.Name{Name: "upload.extra", Area: "upload", Values: observability.ValueEnum, Enum: []string{"on"}, Report: observability.ReportCandidate, Kind: "option", Denom: "upload.mode", Help: "An upload extra."},
		observability.Name{Name: "upload.mode", Area: "upload", Values: observability.ValueEnum, Enum: []string{"buy"}, Report: observability.ReportSignal, Help: "Upload views."})
	rows := fullRows("metrics.flush", "", "", 1440, 3)
	rows = append(rows, fullRows("page.view", "", "sets", 100, 3)...)
	rows = append(rows, fullRows("bot.cmd", "", "price", 5, 3)...)
	// the base of upload.extra was measured on every day and counted nothing
	rows = append(rows, fullRows("upload.mode", "", "buy", 0, 3)...)
	p := metricsParams{View: "remove", Instance: observabilityInstance, Days: 90}
	remove := metricsShellFor("remove")
	remove.Remove = buildMetricsRemove(names, metricsTestLists, rows, nil, true, nil, 60, p)
	remove.Remove.Counted = true
	var top []MetricsCandidateRow
	byName := map[string]string{}
	for _, a := range remove.Remove.Areas {
		for _, k := range a.Kinds {
			top = append(top, k.Rows...)
			for _, r := range k.Rows {
				byName[r.Name] = r.NoRate
			}
		}
	}
	if byName["upload.extra"] != metricsreport.NoRateEmpty || byName["bot.cmd"] != metricsreport.NoRateDays {
		t.Fatalf("no rate = %v", byName)
	}
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, Counted: true, Remove: top}
	for label, v := range map[string]*MetricsView{"remove": remove, "overview": ov} {
		html := metricsPage(t, v)
		wantAll(t, html, label, `<span class="admin-metrics-dim">`+metricsreport.NoRateEmpty+`</span>`, `<span class="admin-metrics-dim">`+metricsreport.NoRateDays+`</span>`)
	}
	// the Feature area page gives upload.extra the same words
	withMetricsInstance(t, observabilityInstance)
	store := newFakeMetrics()
	store.totals = rows
	area := renderView(t, store, names, metricsParams{View: "feature", Instance: observabilityInstance, Area: "upload", Days: 90})
	if len(area.Feature.Names) == 0 || area.Feature.Names[0].NoRate != byName["upload.extra"] {
		t.Errorf("feature rows = %+v", area.Feature.Names)
	}
}
