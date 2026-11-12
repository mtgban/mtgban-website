package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/metricsreport"
	"github.com/mtgban/mtgban-website/observability"
)

// metricsTemplateCache is the production cache, built by the first test that renders.
var metricsTemplateCache struct {
	mu    sync.Mutex
	cache map[string]*template.Template
}

// metricsCachedSet is the cached admin page, desktop or mobile; building it swaps DevMode for the test.
func metricsCachedSet(t *testing.T, mobile bool) *template.Template {
	t.Helper()
	metricsTemplateCache.mu.Lock()
	defer metricsTemplateCache.mu.Unlock()
	if metricsTemplateCache.cache == nil {
		saved := DevMode
		DevMode = false
		t.Cleanup(func() { DevMode = saved })
		built, err := buildTemplateCache()
		if err != nil {
			t.Fatalf("building the template cache: %v", err)
		}
		metricsTemplateCache.cache = built
	}
	cache := metricsTemplateCache.cache
	key := "admin.html"
	if mobile {
		key = "mobile/admin.html"
	}
	tmpl, ok := cache[key]
	if !ok {
		t.Fatalf("the cache has no %s", key)
	}
	return tmpl
}

// metricsPage renders the whole desktop admin page from the cache at the metrics tab.
func metricsPage(t *testing.T, v *MetricsView) string {
	t.Helper()
	tmpl := metricsCachedSet(t, false)
	var buf bytes.Buffer
	vars := PageVars{Title: "Admin", UserNav: &NavElem{}, Page: "metrics", AdminVars: AdminVars{Metrics: v}}
	if err := tmpl.ExecuteTemplate(&buf, tmpl.Name(), vars); err != nil {
		t.Fatalf("rendering admin.html: %v", err)
	}
	return lfOnly(buf.String())
}

// lfOnly is rendered HTML with CRLF line ends made LF, so a match does not depend on the checkout's.
func lfOnly(html string) string {
	return strings.ReplaceAll(html, "\r\n", "\n")
}

// metricsSection executes the shell alone, called with PageVars, from the desktop or mobile set.
func metricsSection(t *testing.T, v *MetricsView, mobile bool) string {
	t.Helper()
	var buf bytes.Buffer
	vars := PageVars{Page: "metrics", IsMobile: mobile, AdminVars: AdminVars{Metrics: v}}
	if err := metricsCachedSet(t, mobile).ExecuteTemplate(&buf, "admin-metrics", vars); err != nil {
		t.Fatalf("rendering admin-metrics (mobile=%v): %v", mobile, err)
	}
	return lfOnly(buf.String())
}

var metricsRenderDay = time.Date(2026, time.March, 4, 0, 0, 0, 0, time.UTC)

// metricsShellFor is a folded view's shell for view, as the loader builds it.
func metricsShellFor(view string) *MetricsView {
	p := metricsParams{View: view, Instance: observabilityInstance, Days: metricsDefaultDays}
	v := newMetricsView(p, []string{observabilityInstance})
	v.Folded, v.FoldedKnown, v.Through = true, true, metricsRenderDay
	return v
}

// hrefOf is how html/template prints a link the view built.
func hrefOf(u string) string {
	return `href="` + strings.ReplaceAll(u, "&", "&amp;") + `"`
}

func wantAll(t *testing.T, html, what string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(html, w) {
			t.Errorf("%s lacks %q", what, w)
		}
	}
}

func wantNone(t *testing.T, html, what string, nots ...string) {
	t.Helper()
	for _, w := range nots {
		if strings.Contains(html, w) {
			t.Errorf("%s holds %q", what, w)
		}
	}
}

func TestMetricsTabIsItsOwnPage(t *testing.T) {
	dash := renderAdminPage(t, PageVars{Page: "dashboard"})
	wantAll(t, dash, "the dashboard", "location.href='?page=metrics'", `id="panel-metrics"`)
	wantNone(t, dash, "the dashboard", "Feature metrics are off", `class="admin-metrics"`)
	off := metricsPage(t, nil)
	wantAll(t, off, "metrics with no store", "Feature metrics are off: this site has no instance_name, no observability database, or the feature tables could not be created.")
}

func TestMetricsShellLinksKeepWhatDiffers(t *testing.T) {
	withMetricsInstance(t, "magic")
	p := metricsParams{View: "remove", Instance: "lorcana", Days: 30, Anon: true}
	v := newMetricsView(p, []string{"magic", "lorcana"})
	v.Folded, v.FoldedKnown, v.Through, v.Remove = true, true, metricsRenderDay, &MetricsRemove{}
	html := metricsPage(t, v)

	for _, group := range [][]MetricsLink{v.Instances, v.Windows, v.Views} {
		for _, l := range group {
			wantAll(t, html, "the shell", hrefOf(l.URL))
		}
	}
	wantAll(t, html, "the shell",
		"lorcana &middot; last 30 days &middot; counts complete through Mar 4, 2026",
		// this site's instance and the default window drop out of the link
		hrefOf("?page=metrics&view=remove&anon=1&days=30"),
		hrefOf("?page=metrics&view=remove&anon=1&instance=lorcana"),
		// Signed in drops anon; Include bots adds bots and keeps the rest
		hrefOf("?page=metrics&view=remove&days=30&instance=lorcana")+`>Signed in</a>`,
		hrefOf("?page=metrics&view=remove&anon=1&bots=1&days=30&instance=lorcana")+`>Include bots</a>`,
		// the active choices link to the page as it is
		hrefOf("?page=metrics&view=remove&anon=1&days=30&instance=lorcana")+` class="active">Include anonymous</a>`,
		hrefOf("?page=metrics&view=remove&anon=1&days=30&instance=lorcana")+` class="active">Humans</a>`,
		hrefOf("?page=metrics&view=invest&anon=1&days=30&instance=lorcana")+`>Invest</a>`,
		`class="active" aria-current="page">Remove</a>`,
	)
	wantNone(t, html, "a folded shell", "No day has been folded yet", "A query did not answer")
}

func TestMetricsShellStates(t *testing.T) {
	v := metricsShellFor("invest")
	v.Folded, v.Through = false, time.Time{}
	v.Failed = true
	v.Notes = []string{"Controls: not measured yet.", "Settings: not measured yet."}
	v.Invest = &MetricsInvest{Sections: metricsSections(nil)}
	html := metricsPage(t, v)
	wantAll(t, html, "an unfolded, failed shell",
		"no complete day yet", "No complete day yet: the first nightly summary has not run.",
		"A query did not answer; what is below may be missing a part.",
		`<div class="admin-msg">Controls: not measured yet.</div>`,
		`<div class="admin-msg">Settings: not measured yet.</div>`)
	wantNone(t, html, "an unfolded shell", "through Jan 1, 0001")
	wantNone(t, metricsSection(t, v, false), "an unfolded section", "fold")
}

func TestOverviewRenders(t *testing.T) {
	v := metricsShellFor("overview")
	v.Notes = []string{"Controls: not measured yet."}
	v.Overview = &MetricsOverview{Live: true, LiveKnown: true, Counted: true, DaysData: 37, DigestReady: true, NothingChanged: metricsreport.NothingChanged,
		Remove: []MetricsCandidateRow{{Candidate: metricsreport.Candidate{Name: "search.sort", Value: "alpha", Class: metricsreport.ClassUnused,
			Area: "search", Help: "Sort order picked on search", RateText: "0.00% of requests", Denom: 300}, URL: "?page=metrics&view=feature&name=search.sort"}},
		Invest: []MetricsSignalRow{{Signal: metricsreport.Signal{Section: metricsreport.SectionFailures, Label: "Empty searches", Count: 30, Denom: 200,
			Help: "Searches that found nothing"}, RateText: "15.0%"}},
		Areas:    []MetricsAreaRow{{Area: "search", Events: 1200, URL: "?page=metrics&view=feature&area=search"}},
		StockDay: metricsRenderDay,
		Stock: []MetricsStockGroup{{Name: "stock.pref", Help: "Saved preferences", Total: 40,
			Rows: []MetricsShare{{Label: "magic dark", N: 10, Share: 0.25}, {Label: "magic light", N: 30, Share: 0.75}}}},
		MoreRows: []MetricsMoreArea{{Area: "upload", Rows: 4}},
	}
	html := metricsPage(t, v)
	wantAll(t, html, "the overview",
		"Counters live", "37 days of data", "Controls: not measured yet.", metricsreport.NothingChanged,
		"last 7 days against the 7 before, signed-in",
		"Consider removing", "Consider investing", "search.sort", "alpha", "and 4 more in upload",
		`title="Sort order picked on search"`, "unused", "0.00% of requests",
		"Empty searches", "15.0%", `title="Searches that found nothing"`,
		hrefOf("?page=metrics&view=feature&area=search")+`>search</a>`,
		"Stored state, all sites", "counts from Mar 4, 2026", "<details>", "stock.pref", "Saved preferences",
		"magic dark", "25.0%", "75.0%",
		// the area number is counted events, said to be no ranking of use
		`<th class="num">Counted events</th>`, metricsAreasNoteStart, "not which area is used more")
	wantNone(t, html, "the overview", ">Uses<", "uses in the window")
}

// Each Overview block's empty line, in every state its counts can be in.
func TestOverviewEmptyBlocksSayWhy(t *testing.T) {
	const counted, notYet = "Nothing unused or rare in this window", "No complete day yet: the first nightly summary has not run."
	v := metricsShellFor("overview")
	v.Overview = &MetricsOverview{LiveKnown: true, Counted: true, NothingChanged: metricsreport.NothingChanged, RemoveEmpty: counted}
	html := metricsPage(t, v)
	wantAll(t, html, "counted and empty", counted, "Nothing to report in this window", "No area has rows in this window", "0 days of data",
		"Stored state: not measured.", ">not measured</span>", "The digest could not be built")
	wantNone(t, html, "counted and empty", notYet, metricsReadFailedText, metricsreport.NothingChanged)

	v.Folded, v.Through = false, time.Time{}
	v.Overview = &MetricsOverview{LiveKnown: true, NothingChanged: metricsreport.NothingChanged}
	html = metricsPage(t, v)
	wantAll(t, html, "nothing complete yet", notYet)
	wantNone(t, html, "nothing complete yet", counted, "days of data", metricsReadFailedText)

	v = metricsShellFor("overview")
	v.Overview = &MetricsOverview{LiveKnown: true, Read: metricsRead(false), StockRead: metricsRead(false)}
	html = metricsPage(t, v)
	wantAll(t, html, "a failed read", metricsReadFailedText, ">could not be read</span>")
	wantNone(t, html, "a failed read", counted, notYet, "days of data", "Stored state: not measured.", ">not measured</span>")

	v.Overview = &MetricsOverview{DigestReady: true, NothingChanged: metricsreport.NothingChanged,
		Changes: metricsreport.Digest{Sections: []metricsreport.DigestSection{{Title: "Moved most", Lines: []string{"search.sort: 4 to 12"}}}}}
	html = metricsPage(t, v)
	wantAll(t, html, "a digest with lines", "<h3>Moved most</h3>", "<li>search.sort: 4 to 12</li>")
	wantNone(t, html, "a digest with lines", metricsreport.NothingChanged)

	v.Overview = &MetricsOverview{LiveKnown: true, LastFlush: time.Date(2026, time.March, 4, 9, 30, 0, 0, time.UTC)}
	wantAll(t, metricsPage(t, v), "a stale counter", "Counters not saving, last saved Mar 4 09:30 UTC")
}

// renderRemoveRegistry has a count-measured option, a day-measured control, a page-list control and pages.
func renderRemoveRegistry() []observability.Name {
	return []observability.Name{
		{Name: "metrics.flush", Report: observability.ReportInternal},
		{Name: "page.view", Values: observability.ValuePage, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "page", Area: "site", Help: "Page views, by page."},
		{Name: "search.sort", Area: "search", Values: observability.ValueEnum, Enum: []string{"alpha", "price"}, Report: observability.ReportCandidate, Kind: "option", Page: "*", Help: "Order the results were sorted in."},
		{Name: "search.view", Area: "search", Values: observability.ValueEnum, Enum: []string{"grid"}, Report: observability.ReportCandidate, Kind: "control", Page: "search", Help: "Result layout picked."},
		{Name: "bot.cmd", Area: "bot", Values: observability.ValueEnum, Enum: []string{"price", "help"}, Report: observability.ReportCandidate, Kind: "control", Help: "Bot commands run."},
	}
}

// renderRemoveView builds the Remove view the way the loader does, from rows.
func renderRemoveView(t *testing.T) *MetricsView {
	t.Helper()
	return renderRemoveViewFor(t, metricsParams{View: "remove", Instance: observabilityInstance, Days: 90})
}

// renderRemoveViewFor is renderRemoveView for params p.
func renderRemoveViewFor(t *testing.T, p metricsParams) *MetricsView {
	t.Helper()
	rows := fullRows("metrics.flush", "", "", 1440, 3)
	rows = append(rows, fullRows("page.view", "", "sets", 100, 3)...)
	rows = append(rows, observability.DayTotal{Name: "page.view", Value: "search", N: 5, Days: 9, First: loaderTestDay.AddDate(0, 0, -8), Last: loaderTestDay})
	rows = append(rows, fullRows("search.sort", "", "alpha", 1, 1)...)
	rows = append(rows, fullRows("bot.cmd", "", "price", 5, 3)...)
	reviews := []observability.Review{{Name: "bot.cmd", Value: "price", Verdict: "keep", Note: "used by the guide"}}
	v := metricsShellFor("remove")
	v.Remove = buildMetricsRemove(renderRemoveRegistry(), metricsTestLists, rows, nil, true, reviews, 60, p)
	v.Remove.Counted = true
	v.Remove.ReviewURL = p.link("remove")
	return v
}

func TestRemoveRenders(t *testing.T) {
	html := metricsPage(t, renderRemoveView(t))
	wantAll(t, html, "the remove view",
		// one line counts every area's rows; each area is a closed details whose summary counts its rows
		`<p class="admin-metrics-total">4 candidates: 3 unused, 1 rare. Open an area to see its rows.</p>`,
		`<details class="admin-section admin-metrics-area">`+"\n"+`<summary class="admin-section-header"><h2>site</h2> <span class="count">1 unused</span></summary>`,
		`<summary class="admin-section-header"><h2>search</h2> <span class="count">1 unused, 1 rare</span></summary>`,
		`<summary class="admin-section-header"><h2>bot</h2> <span class="count">1 unused</span></summary>`,
		// Help is printed as text on every row (M3), not only as a tooltip
		`<span class="admin-metrics-help">Order the results were sorted in.</span>`,
		`<span class="admin-metrics-help">Bot commands run.</span>`,
		`<span class="admin-metrics-help">Result layout picked.</span>`,
		"search.sort</a>: price", `<td class="admin-metrics-class">unused</td>`, `<td class="admin-metrics-class">rare</td>`,
		// counted against page views: a rate and the count it is out of
		"<th>Out of</th>", "305 views of every page", "0.00% of requests", "0.32% of requests", "90 days; counted on views of every page",
		// counted on days: no rate, no count to be out of
		"no rate, measured in days", "90 days; counted on days the counter ran",
		`id="rm-search.sort----price"`, `id="rm-bot.cmd----help"`,
		"<td>not in the last 60 days</td>",
		// one name and every setting, none of which has sent a snapshot here
		fmt.Sprintf("Not measured (%d, %d of them settings)", 1+preferenceSettings(), preferenceSettings()), "9 days measured, 14 needed; counted on views of the search page",
		"Not measured yet: no browser has reported its settings on the upload page.",
		"Reviewed (1)", `<td class="admin-metrics-class">keep</td>`, "used by the guide",
		// each row and each reviewed row has a folded review form that posts to this view
		`<th>Review</th>`, `<details class="admin-metrics-review-box">`+"\n"+`<summary>Review</summary>`,
		`<summary>Marked keep</summary>`, `<form method="POST" action="/admin?page=metrics&amp;view=remove" class="admin-metrics-review">`,
		`name="reviewNote" maxlength="`+strconv.Itoa(observability.ReviewNoteMax)+`"`,
		`<option value="keep">keep</option>`, `<option value="remove">remove</option>`, `<option value="watch">watch</option>`,
		`<input type="hidden" name="reviewName" value="search.sort">`, `<input type="hidden" name="reviewValue" value="price">`,
		`>Mark reviewed</button>`, `<label>Verdict<span class="admin-metrics-hidden"> for search.sort price</span>`,
		// the reviewed row's form holds its verdict and note, and can clear the mark
		`<option value="keep" selected>keep</option>`, `<option value="clear">clear the mark</option>`,
		`value="used by the guide"`, `>Save the mark</button>`)
	wantNone(t, html, "the remove view", "too few to say", "0.0%", "Denominator", "ui.load", "flushed")
	section := metricsSection(t, renderRemoveView(t), false)
	wantNone(t, section, "the remove section", "onclick", "onsubmit", "<script", `admin-metrics-area" open`, `admin-metrics-review-box" open`)
	if n := strings.Count(section, `<details class="admin-metrics-review-box">`); n != 5 {
		t.Errorf("%d folded review forms, want 5", n)
	}
	if n := strings.Count(section, `<form method="POST" action="/admin?page=metrics&amp;view=remove"`); n != 5 {
		t.Errorf("%d review forms, want one on each of the 4 candidate rows and the reviewed row", n)
	}
	// name rows that are not measured come before the setting rows, even one named after state.set
	late := observability.Name{Name: "upload.late", Area: "search", Values: observability.ValueEnum, Enum: []string{"a"},
		Report: observability.ReportCandidate, Kind: "control", Page: "search", Help: "Named after the settings."}
	v := renderRemoveView(t)
	rows := append(fullRows("metrics.flush", "", "", 1440, 3),
		observability.DayTotal{Name: "page.view", Value: "search", N: 5, Days: 9, First: loaderTestDay.AddDate(0, 0, -8), Last: loaderTestDay})
	v.Remove = buildMetricsRemove(append(renderRemoveRegistry(), late), metricsTestLists, rows, nil, true, nil, 60,
		metricsParams{View: "remove", Instance: observabilityInstance, Days: 90})
	if v.Remove.NotMeasuredSettings != preferenceSettings() {
		t.Errorf("%d setting rows counted, want %d", v.Remove.NotMeasuredSettings, preferenceSettings())
	}
	for _, mobile := range []bool{false, true} {
		html := metricsSection(t, v, mobile)
		summary := fmt.Sprintf("Not measured (%d, %d of them settings)", len(v.Remove.NotMeasured), preferenceSettings())
		name := strings.Index(html, "Named after the settings.")
		setting := strings.Index(html, `id="rm-state.set--`)
		if !strings.Contains(html, summary) || name < 0 || setting < 0 || name > setting {
			t.Errorf("mobile %v: want %q and the name row (at %d) before the first setting row (at %d)", mobile, summary, name, setting)
		}
	}
}

// The note is the only free text stored: escaped where it is shown and where the form holds it.
func TestReviewNoteIsEscaped(t *testing.T) {
	const note = "<script>alert(\"x\")</script> it's a & b\nline"
	v := renderRemoveView(t)
	v.Remove.Reviewed[0].Note = note
	for _, mobile := range []bool{false, true} {
		html := metricsSection(t, v, mobile)
		esc := template.HTMLEscapeString(note)
		cell := `<td class="admin-metrics-wrap">`
		if mobile {
			cell = `<td class="admin-metrics-wrap" data-label="Note">`
		}
		wantAll(t, html, "a reviewed row", cell+esc+`</td>`, `value="`+esc+`"`)
		wantNone(t, html, "a reviewed row", "<script>alert", `it's`, `"x"`, " & b")
	}
}

// When the marks could not be read, no form is offered.
func TestReviewFormsNeedTheMarks(t *testing.T) {
	v := renderRemoveView(t)
	v.Remove.ReviewsFailed, v.Remove.Reviewed = true, nil
	html := metricsPage(t, v)
	wantAll(t, html, "reviews failed", "Review marks could not be read")
	wantNone(t, html, "reviews failed", "<form method=\"POST\"", "reviewNote", "<th>Review</th>")
}

// Each Remove group's empty line, in every state its counts can be in.
func TestRemoveEmptyStates(t *testing.T) {
	const notYet = "No complete day yet: the first nightly summary has not run."
	v := metricsShellFor("remove")
	v.Remove = &MetricsRemove{Counted: true, Empty: "Nothing is unused or rare in this window."}
	html := metricsPage(t, v)
	wantAll(t, html, "counted and empty", "Nothing is unused or rare in this window.",
		"Not measured (0)", "Every candidate is measured.", "Reviewed (0)", "Nothing has been reviewed.")
	wantNone(t, html, "counted and empty", notYet, metricsReadFailedText)

	v.Folded, v.Through = false, time.Time{}
	v.Remove = &MetricsRemove{Read: metricsRead(true)}
	html = metricsPage(t, v)
	wantAll(t, html, "nothing complete yet", notYet)
	wantNone(t, html, "nothing complete yet", "Nothing is unused or rare", "Every candidate is measured.", "Nothing has been reviewed.")

	v = metricsShellFor("remove")
	v.Remove = &MetricsRemove{Read: metricsRead(false)}
	html = metricsPage(t, v)
	wantAll(t, html, "a failed read", metricsReadFailedText)
	wantNone(t, html, "a failed read", "Nothing is unused or rare", "Every candidate is measured.", "Nothing has been reviewed.", notYet)

	v.Remove = &MetricsRemove{Counted: true, ReviewsFailed: true}
	html = metricsPage(t, v)
	wantAll(t, html, "reviews failed", "Review marks could not be read.", "Every candidate is measured.")
	wantNone(t, html, "reviews failed", "Nothing has been reviewed.")
}

// Each Invest section's empty line, in every state its counts can be in.
func TestInvestEmptyStates(t *testing.T) {
	v := metricsShellFor("invest")
	v.Invest = &MetricsInvest{Sections: metricsSections(nil), Counted: true}
	wantAll(t, metricsPage(t, v), "counted and empty", "Nothing to report")
	v.Invest = &MetricsInvest{Sections: metricsSections(nil)}
	html := metricsPage(t, v)
	wantAll(t, html, "nothing complete yet", "No complete day yet: the first nightly summary has not run.")
	wantNone(t, html, "nothing complete yet", "Nothing to report")
	v.Invest.Read = metricsRead(false)
	html = metricsPage(t, v)
	wantAll(t, html, "a failed read", metricsReadFailedText)
	wantNone(t, html, "a failed read", "Nothing to report", "No complete day yet")
}

func TestInvestRenders(t *testing.T) {
	v := metricsShellFor("invest")
	v.Invest = &MetricsInvest{Sections: metricsSections([]MetricsSignalRow{
		{Signal: metricsreport.Signal{Section: metricsreport.SectionWalls, Label: "Search hit the free cap", Name: "search.wall",
			Evidence: "Free 40", Count: 52, Denom: 3000, Previous: 30, Rate: 0.0173, Help: "A reader met a tier limit"},
			RateText: "1.7%", Tiers: "Any 12, Legacy 3", Trend: "up", PrevText: "30 in 30 counted days, up", URL: "?page=metrics&view=feature&name=search.wall"},
		{Signal: metricsreport.Signal{Section: metricsreport.SectionFailures, Label: "Script errors", NotMeasured: true}},
		{Signal: metricsreport.Signal{Section: metricsreport.SectionMobile, Label: "arbit", Count: 3, Denom: 5}},
	})}
	v.Invest.Counted = true
	html := metricsPage(t, v)
	wantAll(t, html, "the invest view",
		"<h2>Walls</h2>", "<h2>Failures</h2>", "<h2>Phones on desktop pages</h2>", "<h2>Growing</h2>", "<h2>New</h2>", "<h2>Depth, pages only</h2>",
		hrefOf("?page=metrics&view=feature&name=search.wall")+">Search hit the free cap</a>",
		`<span class="admin-metrics-help">A reader met a tier limit</span>`,
		"1.7%", "30 in 30 counted days, up", "Free 40", "Any 12, Legacy 3",
		"Script errors", ">not measured</td>",
		"too few to say",
		"Nothing to report",
		"Signed-in readers, from page hits over the last 30 complete days, whatever the window above; the toggles do not apply.")
	wantNone(t, html, "the invest view", "0.0%")
}

func TestMetricsTextIsEscaped(t *testing.T) {
	const evil = `x&y'"><script>alert(1)</script>`
	const escaped = `x&amp;y&#39;&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`
	p := metricsParams{View: "remove", Instance: observabilityInstance, Days: 90}
	row := metricsCandidateRow(metricsreport.Candidate{Name: evil, Scope: evil, Value: evil, Area: evil, Kind: evil,
		Help: evil, Class: metricsreport.ClassUnused, RateText: evil, Basis: evil, On: metricsreport.CountedOn{Kind: metricsreport.OnDenom, Name: evil}, Denom: 5}, nil, 60, p)
	row.Tiers = evil
	notMeasured := row
	notMeasured.Class, notMeasured.Reason = metricsreport.ClassNotMeasured, evil
	reviewed := row
	reviewed.Class, reviewed.Verdict, reviewed.Note = metricsreport.ClassReviewed, evil, evil
	signal := MetricsSignalRow{Signal: metricsreport.Signal{Section: metricsreport.SectionWalls, Label: evil, Evidence: evil, Help: evil, Denom: 500},
		RateText: evil, Tiers: evil, Trend: evil}

	views := map[string]*MetricsView{}
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{DigestReady: true, Counted: true, Remove: []MetricsCandidateRow{row},
		Invest: []MetricsSignalRow{signal}, Areas: []MetricsAreaRow{{Area: evil}}, StockDay: metricsRenderDay,
		Changes:  metricsreport.Digest{Sections: []metricsreport.DigestSection{{Title: evil, Lines: []string{evil}}}},
		Stock:    []MetricsStockGroup{{Name: evil, Help: evil, Rows: []MetricsShare{{Label: evil}}}},
		MoreRows: []MetricsMoreArea{{Area: evil, Rows: 1}}}
	views["overview"] = ov
	rm := metricsShellFor("remove")
	rm.Remove = &MetricsRemove{Counted: true, Areas: []MetricsRemoveArea{{Area: evil, Summary: evil, Kinds: []MetricsRemoveKind{{Kind: evil, Rows: []MetricsCandidateRow{row}}}}},
		NotMeasured: []MetricsCandidateRow{notMeasured}, Reviewed: []MetricsCandidateRow{reviewed}}
	views["remove"] = rm
	inv := metricsShellFor("invest")
	inv.Invest = &MetricsInvest{Counted: true, Sections: metricsSections([]MetricsSignalRow{signal})}
	views["invest"] = inv

	ids := regexp.MustCompile(`(?:id="|#)(rm-[^"]*)"`)
	safeID := regexp.MustCompile(`^rm-[a-z0-9_.-]*$`)
	for name, v := range views {
		q := p
		q.Instance = evil
		v.Instance, v.Notes = evil, []string{evil}
		v.Instances = []MetricsLink{{Label: evil, URL: q.link(name)}}
		html := metricsPage(t, v)
		wantNone(t, html, name, "<script>alert(1)", `"><script`, `'"><`)
		// in a text node, in a title attribute, and in a link's query string
		wantAll(t, html, name, ">"+escaped+"<", hrefOf(q.link(name)))
		if name == "overview" {
			wantAll(t, html, name, `title="`+escaped+`"`)
		}
		if name == "invest" {
			wantAll(t, html, name, `<tr title="`+escaped+`">`)
		}
		found := ids.FindAllStringSubmatch(html, -1)
		if name != "invest" && len(found) == 0 {
			t.Errorf("%s: no row id or row link", name)
		}
		for _, id := range found {
			if !safeID.MatchString(id[1]) {
				t.Errorf("%s: row id %q holds more than [a-z0-9_.-]", name, id[1])
			}
		}
	}
}

// M12: the shell and each view execute from the desktop and the mobile set, called with PageVars.
func TestMetricsPartialsRenderOnMobileAndDesktop(t *testing.T) {
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{}
	rm := metricsShellFor("remove")
	rm.Remove = &MetricsRemove{}
	inv := metricsShellFor("invest")
	inv.Invest = &MetricsInvest{Sections: metricsSections(nil)}
	withMetricsInstance(t, "magic")
	feature := func(p metricsParams) *MetricsView {
		p.View = "feature"
		return renderView(t, areaFixture(), renderViewRegistry(), p)
	}
	cases := []struct {
		v    *MetricsView
		want string
	}{
		{nil, "Feature metrics are off"},
		{ov, "Consider removing"},
		{rm, "Not measured (0)"},
		{inv, "Depth, pages only"},
		{feature(metricsParams{}), "Other areas"},
		{feature(metricsParams{Area: "search"}), "0.50% of results page views"},
		{renderView(t, nameFixture(), renderViewRegistry(), metricsParams{View: "feature", Name: "search.sort"}), "The numbers by day"},
		{renderView(t, healthyStore(), renderViewRegistry(), metricsParams{View: "health"}), "No problems found."},
		{renderView(t, newFakeMetrics(), renderViewRegistry(), metricsParams{View: "explore", Name: "auth.refuse"}), "Every metric"},
	}
	for _, mobile := range []bool{false, true} {
		for _, c := range cases {
			html := metricsSection(t, c.v, mobile)
			wantAll(t, html, "the section", c.want)
			if mobile {
				wantNone(t, html, "the mobile section", "<canvas")
			}
		}
	}
}

// -dev parses per request through the same file list; it must render what the cache does.
func TestMetricsDevRenderMatchesTheCache(t *testing.T) {
	v := metricsShellFor("remove")
	v.Remove = &MetricsRemove{}
	dev := lfOnly(renderAdminPage(t, PageVars{Page: "metrics", AdminVars: AdminVars{Metrics: v}}))
	if cached := metricsPage(t, v); dev != cached {
		t.Error("the dev render and the cached render differ")
	}
}

func TestMetricsShellSaysWhenTheFoldedDayIsUnknown(t *testing.T) {
	v := metricsShellFor("remove")
	v.Folded, v.FoldedKnown, v.Through, v.Failed = false, false, time.Time{}, true
	v.Remove = &MetricsRemove{Read: metricsRead(false)}
	html := metricsPage(t, v)
	wantAll(t, html, "an unknown folded day", "The newest complete day could not be read, so the counts that need it are empty.", metricsReadFailedText)
	wantNone(t, html, "an unknown folded day", "No complete day yet", "no complete day yet")

	v.FoldedKnown, v.Remove = true, &MetricsRemove{}
	html = metricsPage(t, v)
	wantAll(t, html, "a known unfolded day", "No complete day yet: the first nightly summary has not run.", "no complete day yet")
	wantNone(t, html, "a known unfolded day", "could not be read")
}

func TestOverviewSaysWhenHealthIsUnknown(t *testing.T) {
	v := metricsShellFor("overview")
	v.Overview = &MetricsOverview{NothingChanged: metricsreport.NothingChanged}
	html := metricsPage(t, v)
	wantAll(t, html, "unknown health", "Counter health could not be read")
	wantNone(t, html, "unknown health", "Counters live", "Counters not saving")

	v.Overview.LiveKnown = true
	html = metricsPage(t, v)
	wantAll(t, html, "known health", "Counters not saving")
	wantNone(t, html, "known health", "Counter health could not be read")
	v.Overview.Live = true
	wantAll(t, metricsPage(t, v), "live health", "Counters live")

	v.Folded, v.FoldedKnown = false, false
	v.Overview.Read = metricsRead(false)
	html = metricsPage(t, v)
	wantAll(t, html, "an overview with an unknown fold", "The digest could not be built", metricsReadFailedText)
	wantNone(t, html, "an overview with an unknown fold", "No complete day yet")
}

func TestPagesNoteIsShownOnlyWhenSet(t *testing.T) {
	const note = "Pages with no views are not listed for another site: a hidden page and an unused page look the same from here."
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true}
	rm := metricsShellFor("remove")
	rm.Remove = &MetricsRemove{}
	for name, v := range map[string]*MetricsView{"overview": ov, "remove": rm} {
		wantNone(t, metricsPage(t, v), name+" without a note", "Pages with no views")
		v.PagesNote = note
		wantAll(t, metricsPage(t, v), name+" with a note", note)
	}
}

func TestReviewsFailedIsSaid(t *testing.T) {
	const said = "Review marks could not be read, so rows already reviewed may appear again."
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, NothingChanged: metricsreport.NothingChanged}
	rm := metricsShellFor("remove")
	rm.Remove = &MetricsRemove{}
	wantNone(t, metricsPage(t, ov), "an overview with reviews", said)
	wantNone(t, metricsPage(t, rm), "a remove view with reviews", said)

	ov.Overview.ReviewsFailed = true
	html := metricsPage(t, ov)
	wantAll(t, html, "an overview without reviews", said, "The digest could not be built: the review marks could not be read.")
	wantNone(t, html, "an overview without reviews", metricsreport.NothingChanged)
	rm.Remove.ReviewsFailed = true
	wantAll(t, metricsPage(t, rm), "a remove view without reviews", said)
}

func TestOverviewMoreRows(t *testing.T) {
	v := metricsShellFor("overview")
	v.Overview = &MetricsOverview{LiveKnown: true, MoreRows: []MetricsMoreArea{{Area: "upload", Rows: 4}, {Area: "", Rows: 2}}}
	html := metricsPage(t, v)
	wantAll(t, html, "more rows", "<li>and 4 more in upload</li>", "<li>and 2 more in no area</li>")
	v.Overview.MoreRows = nil
	wantNone(t, metricsPage(t, v), "no more rows", "admin-metrics-more")
}

// Areas start closed; the one the page was asked for with area= starts open.
func TestRemoveAreasStartClosedUnlessAsked(t *testing.T) {
	section := metricsSection(t, renderRemoveViewFor(t, metricsParams{View: "remove", Instance: observabilityInstance, Days: 90, Area: "search"}), false)
	wantAll(t, section, "area=search",
		`<details class="admin-section admin-metrics-area" open>`+"\n"+`<summary class="admin-section-header"><h2>search</h2>`,
		`<details class="admin-section admin-metrics-area">`+"\n"+`<summary class="admin-section-header"><h2>site</h2>`,
		`<details class="admin-section admin-metrics-area">`+"\n"+`<summary class="admin-section-header"><h2>bot</h2>`)
	if n := strings.Count(section, `admin-metrics-area" open`); n != 1 {
		t.Errorf("%d open areas, want only search", n)
	}
	// the area is read through the validated params: an unknown one opens nothing
	p := readMetricsParams(url.Values{"view": {"remove"}, "area": {"<b>x</b>"}}.Get, nil)
	if p.Area != "" {
		t.Errorf("area %q from an unknown value", p.Area)
	}
	wantNone(t, metricsSection(t, renderRemoveViewFor(t, p), false), "an unknown area", `admin-metrics-area" open`, "&lt;b&gt;")
	// the picker and tab links do not carry the area
	v := newMetricsView(metricsParams{View: "remove", Instance: observabilityInstance, Days: 90, Area: "search"}, []string{observabilityInstance})
	for _, l := range append(append(v.Windows, v.Views...), v.AnonLink, v.BotsLink) {
		if strings.Contains(l.URL, "area=") {
			t.Errorf("link %q carries the area", l.URL)
		}
	}
}

// The Overview's "what this counts" link lands on the Remove row of the same candidate.
func TestOverviewRowsLinkToTheirRemoveRow(t *testing.T) {
	remove := renderRemoveView(t)
	var top []MetricsCandidateRow
	for _, a := range remove.Remove.Areas {
		for _, k := range a.Kinds {
			top = append(top, k.Rows...)
		}
	}
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, Counted: true, Remove: top}
	overview := metricsPage(t, ov)
	frags := regexp.MustCompile(`href="\?page=metrics&amp;view=remove&amp;area=([a-z]+)#([^"]+)">what this counts</a>`).FindAllStringSubmatch(overview, -1)
	if len(frags) != len(top) || len(top) == 0 {
		t.Fatalf("%d what-this-counts links for %d rows", len(frags), len(top))
	}
	for _, f := range frags {
		// the link opens the row's area, and the row is inside it
		section := metricsSection(t, renderRemoveViewFor(t, metricsParams{View: "remove", Instance: observabilityInstance, Days: 90, Area: f[1]}), false)
		i := strings.Index(section, `admin-metrics-area" open>`+"\n"+`<summary class="admin-section-header"><h2>`+f[1]+`</h2>`)
		row := strings.Index(section, `id="`+f[2]+`"`)
		end := strings.Index(section[max(i, 0)+1:], `<details class="admin-section`)
		if end < 0 {
			end = len(section)
		}
		if i < 0 || row < i || row > i+1+end {
			t.Errorf("the link to %s#%s does not land in an open area holding its row", f[1], f[2])
		}
	}
}

// Every column has a header, a link-only column a hidden one.
func TestMetricsTablesHaveAHeaderPerColumn(t *testing.T) {
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, Counted: true}
	inv := metricsShellFor("invest")
	inv.Invest = &MetricsInvest{Counted: true, Sections: metricsSections([]MetricsSignalRow{
		{Signal: metricsreport.Signal{Section: metricsreport.SectionWalls, Label: "Search hit the free cap", Count: 3, Denom: 60}, RateText: "5.0%"}})}
	head := regexp.MustCompile(`<thead><tr>(.*?)</tr></thead>`)
	withMetricsInstance(t, "magic")
	explore := newFakeMetrics()
	explore.named = []observability.DayTotal{{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 10, Days: 1}}
	beacon := healthyStore()
	beacon.client = []observability.DayTotal{{Name: "metrics.client", Value: "unknown", N: 50}}
	beacon.totals = []observability.DayTotal{{Period: 0, Name: "page.view", Value: "reverse", N: 5, Days: 3}}
	for name, v := range map[string]*MetricsView{"overview": ov, "remove": renderRemoveView(t), "invest": inv,
		"feature index": renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature"}),
		"feature area":  renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature", Area: "search"}),
		"feature name":  renderView(t, nameFixture(), renderViewRegistry(), metricsParams{View: "feature", Name: "search.sort"}),
		"health":        renderView(t, beacon, beaconTestRegistry(), metricsParams{View: "health"}),
		"explore":       renderView(t, explore, renderViewRegistry(), metricsParams{View: "explore", Name: "auth.refuse"}),
	} {
		html := metricsSection(t, v, false)
		heads := head.FindAllStringSubmatch(html, -1)
		if len(heads) == 0 {
			t.Errorf("%s: no table headers", name)
		}
		for _, h := range heads {
			if strings.Contains(h[1], "<th></th>") || strings.Contains(h[1], `"></th>`) {
				t.Errorf("%s: an empty header in %s", name, h[1])
			}
		}
	}
}

// A column empty in every row of its table is left out, header and cells together.
func TestEmptyColumnsAreLeftOut(t *testing.T) {
	v := renderRemoveView(t)
	for _, a := range v.Remove.Areas {
		for _, k := range a.Kinds {
			if k.HasTiers {
				t.Errorf("%s %s: tiers column with no tier line", a.Area, k.Kind)
			}
			want := slices.ContainsFunc(k.Rows, func(r MetricsCandidateRow) bool { return r.OutOf != "" })
			if k.HasOutOf != want {
				t.Errorf("%s %s: HasOutOf %v, want %v", a.Area, k.Kind, k.HasOutOf, want)
			}
		}
	}
	section := metricsSection(t, v, false)
	wantNone(t, section, "no tier lines", "<th>Tiers</th>")
	// search's option is counted on views and keeps Out of; bot's control is counted on days and drops it
	if got := strings.Count(section, "<th>Out of</th>"); got != 1 {
		t.Errorf("%d Out of headers, want 1", got)
	}
	v.Remove.Areas[0].Kinds[0].Rows[0].Tiers = "Any 3"
	v.Remove.Areas[0].Kinds[0].HasTiers = true
	wantAll(t, metricsSection(t, v, false), "a tier line", "<th>Tiers</th>", "<td class=\"admin-metrics-wrap\">Any 3</td>")

	rows := []MetricsSignalRow{
		{Signal: metricsreport.Signal{Section: metricsreport.SectionWalls, Label: "wall", Count: 3, Denom: 60, Previous: 2, Evidence: "seen twice"}, Tiers: "Any 3", Trend: "up", PrevText: "2 in 30 counted days, up"},
		{Signal: metricsreport.Signal{Section: metricsreport.SectionFailures, Label: "failure", Count: 1, Denom: 60}},
		{Signal: metricsreport.Signal{Section: metricsreport.SectionFailures, Label: "unmeasured", NotMeasured: true, Evidence: "ignored"}},
	}
	sections := metricsSections(rows)
	walls, failures := sections[0], sections[1]
	if !walls.HasTiers || !walls.HasPrevious || !walls.HasEvidence || walls.Span != 6 {
		t.Errorf("walls %+v", walls)
	}
	if failures.HasTiers || failures.HasPrevious || failures.HasEvidence || failures.Span != 3 {
		t.Errorf("failures %+v", failures)
	}
	inv := metricsShellFor("invest")
	inv.Invest = &MetricsInvest{Counted: true, Sections: sections}
	html := metricsSection(t, inv, false)
	for _, th := range []string{"<th>Tiers</th>", "<th>Previous</th>", "<th>Evidence</th>"} {
		if got := strings.Count(html, th); got != 1 {
			t.Errorf("%d %s on invest, want only the walls one", got, th)
		}
	}
	wantAll(t, html, "a not-measured row", `<td colspan="3" class="admin-metrics-dim">not measured</td>`)

	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, Counted: true, Invest: rows[1:2]}
	wantNone(t, metricsSection(t, ov, false), "no evidence", "<th>Evidence</th>")
	ov.Overview.Invest, ov.Overview.InvestEvidence = rows[:1], true
	wantAll(t, metricsSection(t, ov, false), "evidence", "<th>Evidence</th>", "seen twice")
}

// preferenceSettings is how many settings Remove lists a row for.
func preferenceSettings() int {
	n := 0
	for _, s := range observability.Settings() {
		if observability.IsSetting(s.Name) {
			n++
		}
	}
	return n
}

// settingRemoveView is the Remove view with one rare upload setting among name rows.
func settingRemoveView(t *testing.T) *MetricsView {
	t.Helper()
	p := metricsParams{View: "remove", Instance: observabilityInstance, Days: 90}
	names := append(renderRemoveRegistry(), observability.Name{Name: "upload.unpack", Area: "upload", Report: observability.ReportCandidate, Kind: "control", Help: "An upload opened its sealed rows."})
	rows := fullRows("metrics.flush", "", "", 1440, 3)
	rows = append(rows, fullRows("page.view", "", "sets", 100, 3)...)
	rows = append(rows, fullRows("state.reader", "upload", "", 300, 3)...)
	rows = append(rows, fullRows("upload.value_set", "", "maxqty", 31, 1)...)
	rows = append(rows, observability.DayTotal{Name: "state.set", Scope: "UploadMaxQty", Value: "set", N: 2, Days: 2, First: loaderTestDay.AddDate(0, 0, -1), Last: loaderTestDay})
	v := metricsShellFor("remove")
	v.Remove = buildMetricsRemove(names, metricsTestLists, rows, nil, true, nil, 60, p)
	v.Remove.Counted = true
	v.Remove.ReviewURL = p.link("remove")
	return v
}

// rowHTML is the rendered table row with that anchor.
func rowHTML(t *testing.T, html, anchor string) string {
	t.Helper()
	_, after, ok := strings.Cut(html, `<tr id="`+anchor+`">`)
	if !ok {
		t.Fatalf("no row %s", anchor)
	}
	row, _, _ := strings.Cut(after, "</tr>")
	return row
}

func TestRemoveRendersTheThreeNumbers(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		html := metricsSection(t, settingRemoveView(t), mobile)
		what := fmt.Sprintf("the remove view (mobile %v)", mobile)
		maxQty := rowHTML(t, html, "rm-state.set--uploadmaxqty--")
		wantAll(t, maxQty, what+": UploadMaxQty",
			`state.set</a> on UploadMaxQty`, `<span class="admin-metrics-help">kept in a cookie, read on the upload page</span>`,
			`<span class="admin-metrics-help">off default 2 of 900 reader-days; changes not counted; ran in 31 requests</span>`,
			"0.22% of reader-days", "900 browsers that reported their settings that day, on the upload page",
			"90 days; counted on browsers that reported their settings that day, on the upload page", ">rare<")
		// a setting with no fact counts neither its changes nor its requests
		alt := rowHTML(t, html, "rm-state.set--uploadaltprice--")
		if n := strings.Count(alt, "not counted"); n != 2 {
			t.Errorf("%s: UploadAltPrice says not counted %d times, want 2: %s", what, n, alt)
		}
		wantAll(t, alt, what+": UploadAltPrice", "off default 0 of 900 reader-days", ">unused<")
		// a root setting with no snapshot yet is not measured, and says so in words
		notMeasured := rowHTML(t, html, "rm-state.set--searchdefaultsort--")
		wantAll(t, notMeasured, what+": SearchDefaultSort", "0 days measured; changes not counted; ran in 0 requests",
			"Not measured yet: no browser has reported its settings on any page.")
		// a row of another kind has none of the three
		for _, anchor := range []string{"rm-page.view----alerts", "rm-upload.unpack----"} {
			wantNone(t, rowHTML(t, html, anchor), what+": "+anchor, "reader-days", "not counted", "ran in", "browsers that reported")
		}
		if mobile {
			wantAll(t, maxQty, what, `data-label="Out of"`, `data-label="Rate"`, `data-label="Measured"`)
		}
		wantNone(t, html, what, "nothing named")
	}
	page := metricsPage(t, settingRemoveView(t))
	wantAll(t, page, "the remove page", `<summary class="admin-section-header"><h2>upload</h2>`)
}

func TestRemoveViewDecoratesASettingRow(t *testing.T) {
	v := settingRemoveView(t).Remove
	var upload *MetricsRemoveArea
	for i := range v.Areas {
		if v.Areas[i].Area == "upload" {
			upload = &v.Areas[i]
		}
	}
	if upload == nil || len(upload.Kinds) == 0 || upload.Kinds[0].Kind != "setting" {
		t.Fatalf("upload area = %+v: its setting kind comes first", upload)
	}
	var row *MetricsCandidateRow
	for i, r := range upload.Kinds[0].Rows {
		if r.Scope == "UploadMaxQty" {
			row = &upload.Kinds[0].Rows[i]
		}
	}
	if row == nil {
		t.Fatal("no UploadMaxQty row")
	}
	if row.RateText != "0.22% of reader-days" || row.Key != "state.set|UploadMaxQty|" || row.URL != "?page=metrics&view=feature&name=state.set" ||
		row.Class != metricsreport.ClassRare || row.Anchor != "rm-state.set--uploadmaxqty--" || row.Reason != "" {
		t.Errorf("row = %+v", row)
	}
	if !slices.Equal(row.Numbers, []string{"off default 2 of 900 reader-days", "changes not counted", "ran in 31 requests"}) {
		t.Errorf("numbers = %q", row.Numbers)
	}
	for _, r := range v.NotMeasured {
		if r.Name == "state.set" && r.Scope == "SleepersEditionList" {
			if r.Reason != "Not measured yet: no browser has reported its settings on the sleepers page." {
				t.Errorf("reason %q", r.Reason)
			}
		}
		if r.Name != "state.set" && r.Numbers != nil {
			t.Errorf("a name's row has numbers: %+v", r)
		}
	}
	// some days measured, too few: the days and the words
	c := metricsreport.Candidate{Name: "state.set", Scope: "SleepersEditionList", Class: metricsreport.ClassNotMeasured, DaysMeasured: 10,
		On: metricsreport.CountedOn{Kind: metricsreport.OnReaders, Pages: "sleepers"}, Changes: 3, Requests: -1}
	if got := metricsReason(c); got != "10 days measured, 14 needed; counted on browsers that reported their settings that day, on the sleepers page" {
		t.Errorf("reason %q", got)
	}
	if got := metricsSettingNumbers(c); !slices.Equal(got, []string{"10 days measured", "changed 3", "requests not counted"}) {
		t.Errorf("numbers %q", got)
	}
}
