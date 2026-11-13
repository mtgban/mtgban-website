package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/metricsreport"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
	"github.com/mtgban/mtgban-website/observability"
)

// renderMobileAdminPage renders the mobile admin page from the production cache.
func renderMobileAdminPage(t *testing.T, vars PageVars) string {
	t.Helper()
	tmpl := metricsCachedSet(t, true)
	vars.Title, vars.IsMobile, vars.UserNav = "Admin", true, &NavElem{}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, tmpl.Name(), vars); err != nil {
		t.Fatalf("rendering the mobile admin: %v", err)
	}
	return lfOnly(buf.String())
}

// renderMobileAdminDev renders the mobile admin page the way -dev parses it, per request.
func renderMobileAdminDev(t *testing.T, vars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("admin.html", true)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing the mobile admin: %v", err)
	}
	vars.Title, vars.IsMobile, vars.UserNav = "Admin", true, &NavElem{}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, baseName, vars); err != nil {
		t.Fatalf("rendering the mobile admin: %v", err)
	}
	return lfOnly(buf.String())
}

// mobileMetricsViews is one view of each kind, with rows, as the loader builds them.
func mobileMetricsViews(t *testing.T) map[string]*MetricsView {
	t.Helper()
	withMetricsInstance(t, "magic")
	ov := metricsShellFor("overview")
	ov.Overview = &MetricsOverview{LiveKnown: true, Live: true, Counted: true}
	inv := metricsShellFor("invest")
	inv.Invest = &MetricsInvest{Counted: true, Sections: metricsSections([]MetricsSignalRow{
		{Signal: metricsreport.Signal{Section: metricsreport.SectionWalls, Label: "Search hit the free cap", Count: 3, Denom: 60}, RateText: "5.0%", Tiers: "Any 3"}})}
	explore := newFakeMetrics()
	explore.named = []observability.DayTotal{{Period: 0, Name: "auth.refuse", Scope: "search", Value: "no_access", N: 10, Days: 1}}
	health := healthyStore()
	health.client = []observability.DayTotal{{Name: "metrics.client", Value: "unknown", N: 50}}
	return map[string]*MetricsView{
		"overview":      ov,
		"remove":        renderRemoveView(t),
		"invest":        inv,
		"feature index": renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature"}),
		"feature area":  renderView(t, areaFixture(), renderViewRegistry(), metricsParams{View: "feature", Area: "search"}),
		"feature name":  renderView(t, nameFixture(), renderViewRegistry(), metricsParams{View: "feature", Name: "search.sort"}),
		"health":        renderView(t, health, beaconTestRegistry(), metricsParams{View: "health"}),
		"explore":       renderView(t, explore, renderViewRegistry(), metricsParams{View: "explore", Name: "auth.refuse"}),
	}
}

// What the chart scripts would put on a page; none of it belongs on a phone.
var mobileChartMarks = []string{"<canvas", "chart.umd.min.js", "admin-metrics.js", "BAN_ADMIN_METRICS", "admin-metrics-chart", "admin-metrics-spark"}

func TestMobileAdminLinksToMetrics(t *testing.T) {
	html := renderMobileAdminPage(t, PageVars{Page: ""})
	if !strings.Contains(html, `<a class="m-admin-tool-btn" href="?page=metrics">Open metrics</a>`) {
		t.Error("the mobile admin does not link to metrics")
	}
	wantNone(t, html, "the mobile admin off the metrics page", "Feature metrics are off", `class="admin-metrics"`)
}

func TestMobileMetricsHasTablesAndNoCharts(t *testing.T) {
	v := &MetricsView{View: "feature", Instance: "magic", Days: 90, Folded: true, FoldedKnown: true,
		Views:  []MetricsLink{{Label: "Remove", URL: "?page=metrics&view=remove"}},
		Charts: []MetricsChart{{ID: "metrics-days", Kind: "line", Labels: []string{"11-10"}, Series: []MetricsSeries{{Label: "search.sort", Data: []int64{12}}}}},
		Feature: &MetricsFeature{Name: &observability.Name{Name: "search.sort", Help: "the sort a search ran with"}, Counted: true, HasRows: true, Total: 12,
			Values: []MetricsShare{{Label: "alpha", N: 12, Share: 1}}, DaysID: "metrics-days"}}
	html := renderMobileAdminPage(t, PageVars{Page: "metrics", AdminVars: AdminVars{Metrics: v}})
	wantAll(t, html, "the mobile metrics page", "<h2>Metrics</h2>", "search.sort", "the sort a search ran with", "alpha",
		"?page=metrics&amp;view=remove", "The numbers by day (1 days)", `<td class="admin-mono">11-10</td>`)
	wantNone(t, html, "the mobile metrics page", mobileChartMarks...)
	wantNone(t, html, "the mobile metrics page", "Open metrics")
}

// Every view renders inside the mobile page, through the cache and the -dev parse alike.
func TestMobileAdminRendersEveryMetricsView(t *testing.T) {
	scripts := strings.Count(renderMobileAdminPage(t, PageVars{Page: ""}), "<script")
	views := mobileMetricsViews(t)
	views["off"] = nil
	for name, v := range views {
		vars := PageVars{Page: "metrics", AdminVars: AdminVars{Metrics: v}}
		html := renderMobileAdminPage(t, vars)
		if v == nil {
			wantAll(t, html, name, "Feature metrics are off")
		} else {
			wantAll(t, html, name, `<div class="admin-metrics">`, `aria-label="Views"`)
		}
		wantNone(t, html, name, mobileChartMarks...)
		if n := strings.Count(html, "<script"); n != scripts {
			t.Errorf("%s: %d script tags, the page without metrics has %d", name, n, scripts)
		}
		if dev := renderMobileAdminDev(t, vars); dev != html {
			t.Errorf("%s: the -dev render and the cached render differ", name)
		}
	}
}

// Mobile admin prints no WarningMessage, so a refused review is said by the section (L6).
func TestMobileMetricsShowsTheMessage(t *testing.T) {
	v := renderRemoveView(t)
	v.Message = `That mark was refused <b>&</b>.`
	html := renderMobileAdminPage(t, PageVars{Page: "metrics", WarningMessage: "a warning", AdminVars: AdminVars{Metrics: v}})
	wantAll(t, html, "the mobile metrics page", `<div class="admin-msg admin-msg-error">That mark was refused &lt;b&gt;&amp;&lt;/b&gt;.</div>`)
	wantNone(t, html, "the mobile metrics page", "<b>&</b>")
}

func TestMobileRemoveKeepsTheReviewForm(t *testing.T) {
	html := renderMobileAdminPage(t, PageVars{Page: "metrics", AdminVars: AdminVars{Metrics: renderRemoveView(t)}})
	wantAll(t, html, "the mobile remove view", `name="reviewVerdict"`, `method="POST"`, `name="reviewNote"`,
		`<form method="POST" action="/admin?page=metrics&amp;view=remove" class="admin-metrics-review">`,
		// the wide tables become cards, each value labelled with its column's fixed header
		`<table class="table-data admin-table admin-metrics-remove admin-metrics-stack">`,
		`<td class="admin-metrics-class" data-label="Class">unused</td>`, `<td data-label="Last seen">not in the last 60 days</td>`,
		`<td class="admin-metrics-class" data-label="Verdict">keep</td>`, `<td class="admin-metrics-wrap" data-label="Note">used by the guide</td>`)
	if n := strings.Count(html, `class="admin-metrics-review"`); n != 5 {
		t.Errorf("%d review forms on mobile, want 5", n)
	}
}

// A data-label holds the column's header word, never a value read from a row.
func TestMobileCardLabelsAreFixedHeaderWords(t *testing.T) {
	label := regexp.MustCompile(`data-label="([^"]*)"`)
	head := regexp.MustCompile(`<th[^>]*>([^<]*)</th>`)
	stacked := map[string]bool{}
	for name, v := range mobileMetricsViews(t) {
		html := metricsSection(t, v, true)
		stacked[name] = strings.Contains(html, "admin-metrics-stack")
		heads := map[string]bool{}
		for _, m := range head.FindAllStringSubmatch(html, -1) {
			heads[m[1]] = true
		}
		for _, m := range label.FindAllStringSubmatch(html, -1) {
			if !heads[m[1]] {
				t.Errorf("%s: data-label %q is not a header of the page", name, m[1])
			}
		}
		if stacked[name] != strings.Contains(html, "data-label=") {
			t.Errorf("%s: a stacked table without labels, or labels without a stacked table", name)
		}
	}
	for _, name := range []string{"remove", "invest", "health"} {
		if !stacked[name] {
			t.Errorf("%s: no stacked table on mobile", name)
		}
	}
}

// stripTags is s without its tags.
func stripTags(s string) string {
	return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, "")
}

// Each card cell's label is its own column's header: the Nth cell carries the Nth header's text.
func TestMobileCardLabelsMatchTheirColumn(t *testing.T) {
	table := regexp.MustCompile(`(?s)<table class="[^"]*admin-metrics-stack[^"]*">(.*?)</table>`)
	head := regexp.MustCompile(`(?s)<th[^>]*>(.*?)</th>`)
	row := regexp.MustCompile(`(?s)<tbody>.*?</tbody>`)
	tr := regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	td := regexp.MustCompile(`<td([^>]*)>`)
	label := regexp.MustCompile(`data-label="([^"]*)"`)
	unlabelled := map[string]bool{"Feature page": true, "Review": true}
	checked := 0
	for name, v := range mobileMetricsViews(t) {
		for _, tb := range table.FindAllStringSubmatch(metricsSection(t, v, true), -1) {
			var heads []string
			for _, h := range head.FindAllStringSubmatch(tb[1], -1) {
				heads = append(heads, strings.TrimSpace(stripTags(h[1])))
			}
			for _, r := range tr.FindAllStringSubmatch(row.FindString(tb[1]), -1) {
				cells := td.FindAllStringSubmatch(r[1], -1)
				if strings.Contains(r[1], "colspan=") {
					continue
				}
				if len(cells) != len(heads) {
					t.Errorf("%s: %d cells under %d headers %q", name, len(cells), len(heads), heads)
					continue
				}
				for i, c := range cells {
					m := label.FindStringSubmatch(c[1])
					switch {
					case m != nil && m[1] != heads[i]:
						t.Errorf("%s: cell %d is labelled %q under the header %q", name, i, m[1], heads[i])
					case m == nil && i > 0 && !unlabelled[heads[i]]:
						t.Errorf("%s: cell %d under %q has no label", name, i, heads[i])
					case m != nil:
						checked++
					}
				}
			}
		}
	}
	if checked < 20 {
		t.Errorf("only %d labelled cells checked", checked)
	}
}

// The card hooks are mobile only: desktop prints neither, and no desktop rule reads them.
func TestDesktopMetricsCarryNoMobileHooks(t *testing.T) {
	// every literal the partials print only under IsMobile, so a hook moved outside its guard is caught
	guarded := regexp.MustCompile(`(?s)\{\{if \$\.IsMobile\}\}(.*?)\{\{end\}\}`)
	files, err := filepath.Glob("templates/partials/admin-metrics*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("listing the partials: %v", err)
	}
	hooks := []string{"data-label", "admin-metrics-stack"}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range guarded.FindAllStringSubmatch(string(src), -1) {
			if !strings.Contains(m[1], "{{") {
				hooks = append(hooks, m[1])
			}
		}
	}
	if len(hooks) < 20 {
		t.Fatalf("only %d mobile hooks found in the partials", len(hooks))
	}
	for name, v := range mobileMetricsViews(t) {
		wantNone(t, metricsSection(t, v, false), "desktop "+name, hooks...)
	}
	for _, f := range []string{"css/admin.css", "css/main.css"} {
		css, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if bytes.Contains(css, []byte("data-label")) || bytes.Contains(css, []byte("admin-metrics-stack")) {
			t.Errorf("%s styles a mobile card hook", f)
		}
	}
}

// Classes the partials print that need no rule in admin-mobile.css.
var mobileUnstyledClasses = map[string]string{
	// printed only inside {{if not $.IsMobile}}: the chart boxes never reach a phone
	"admin-metrics-chart": "desktop only",
	"admin-metrics-spark": "desktop only",
	// row stripes and cell padding come from main.css, which the mobile base loads
	"table-data": "main.css",
	// hooks naming a block for tests and readers; admin.css gives them no rule either
	"admin-metrics-feature": "hook",
	"admin-metrics-invest":  "hook",
	"admin-metrics-names":   "hook",
	"admin-metrics-remove":  "hook",
	"admin-metrics-rows":    "hook",
	"admin-metrics-splits":  "hook",
}

// Mobile admin loads admin-mobile.css and not admin.css, so it styles every class the section prints (L6).
func TestMobileStylesheetCoversTheMetricsClasses(t *testing.T) {
	read := func(f string) string {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		return regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	}
	mobile, desktop, mainCSS := read("css/admin-mobile.css"), read("css/admin.css"), read("css/main.css")
	files, err := filepath.Glob("templates/partials/admin-metrics*.html")
	if err != nil || len(files) < 7 {
		t.Fatalf("listing the metrics partials: %v, %d files", err, len(files))
	}
	attr := regexp.MustCompile(`class="([^"]*)"`)
	action := regexp.MustCompile(`\{\{.*?\}\}`)
	classes := map[string]bool{}
	for _, f := range files {
		for _, m := range attr.FindAllStringSubmatch(read(f), -1) {
			for _, c := range strings.Fields(action.ReplaceAllString(m[1], " ")) {
				classes[c] = true
			}
		}
	}
	ruled := func(css, class string) bool {
		return regexp.MustCompile(`\.` + regexp.QuoteMeta(class) + `(?:[^-_a-zA-Z0-9]|$)`).MatchString(css)
	}
	var names []string
	for c := range classes {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		why, allowed := mobileUnstyledClasses[c]
		switch {
		case !allowed && !ruled(mobile, c):
			t.Errorf("class %q has no rule in css/admin-mobile.css", c)
		case why == "hook" && ruled(desktop, c):
			t.Errorf("class %q is listed as a bare hook but admin.css styles it", c)
		case why == "main.css" && !ruled(mainCSS, c):
			t.Errorf("class %q is listed as styled by main.css but is not", c)
		}
	}
	for c := range mobileUnstyledClasses {
		if !classes[c] {
			t.Errorf("class %q is allowed unstyled but no partial prints it", c)
		}
	}
}
