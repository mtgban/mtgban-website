package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/tmplparse"
	"github.com/mtgban/mtgban-website/observability"
)

// The sub-view table used to come back from its own query: the TopPages one
// with `AND (path LIKE 'newspaper/%' OR path LIKE 'sleepers/%')` bolted on.
// These cases pin the Go filter to the rows that SQL selected, the trailing
// slash included - `LIKE 'newspaper/%'` never matched a bare "newspaper".
func TestSubViewsOfSelectsWhatTheQueryDid(t *testing.T) {
	all := []observability.PathAgg{
		{Path: "search", Hits: 1130017, Uniques: 173},
		{Path: "sleepers/mismatch", Hits: 1207, Uniques: 26},
		{Path: "sets", Hits: 893, Uniques: 49},
		{Path: "newspaper/index", Hits: 700, Uniques: 54},
		{Path: "newspaper", Hits: 400, Uniques: 12},
		{Path: "sleepers", Hits: 300, Uniques: 9},
		{Path: "admin", Hits: 215, Uniques: 4},
		{Path: "newspaper/syp", Hits: 21, Uniques: 11},
	}

	want := []observability.PathAgg{
		{Path: "sleepers/mismatch", Hits: 1207, Uniques: 26},
		{Path: "newspaper/index", Hits: 700, Uniques: 54},
		{Path: "newspaper/syp", Hits: 21, Uniques: 11},
	}

	got := subViewsOf(all)
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TopPages orders by hits and the filter keeps that order, so the sub-view
// table stays sorted without a second sort.
func TestSubViewsOfKeepsInputOrder(t *testing.T) {
	all := []observability.PathAgg{
		{Path: "newspaper/a", Hits: 30},
		{Path: "search", Hits: 25},
		{Path: "sleepers/b", Hits: 20},
		{Path: "newspaper/c", Hits: 10},
	}

	got := subViewsOf(all)
	for i := 1; i < len(got); i++ {
		if got[i-1].Hits < got[i].Hits {
			t.Errorf("order broken at %d: %v before %v", i, got[i-1], got[i])
		}
	}
}

func TestSubViewsOfEmptyInput(t *testing.T) {
	if got := subViewsOf(nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := subViewsOf([]observability.PathAgg{{Path: "search"}}); got != nil {
		t.Errorf("got %v, want nil when nothing matches", got)
	}
}

// The Usage panel is filled only when it is the tab being asked for, so its
// button has to reach the server instead of revealing a panel the response
// never carried. Rendering both states pins that pairing together.
func TestAdminUsagePanelOnlyOnItsOwnPage(t *testing.T) {
	dash := &UsageDashboard{
		Instance: "magic",
		TopPages: []observability.PathAgg{{Path: "sleepers/gap", Hits: 405, Uniques: 19}},
		SubViews: []observability.PathAgg{{Path: "sleepers/gap", Hits: 405, Uniques: 19}},
	}

	onUsage := renderAdminPage(t, PageVars{Page: "usage", UsageStats: dash})
	for _, want := range []string{"sleepers/gap", "Top pages", "sleepers sub-views"} {
		if !strings.Contains(onUsage, want) {
			t.Errorf("the usage tab does not contain %q", want)
		}
	}

	// Nothing was loaded here, and the panel's own empty state reads
	// "telemetry is not enabled" - true of a missing database, a lie about one
	// that simply was not asked. Leave the panel out rather than say it.
	onDashboard := renderAdminPage(t, PageVars{Page: "dashboard"})
	for _, absent := range []string{"Top pages", "Observability telemetry is not enabled"} {
		if strings.Contains(onDashboard, absent) {
			t.Errorf("the dashboard tab still contains %q", absent)
		}
	}

	if !strings.Contains(onDashboard, "location.href='?page=usage'") {
		t.Error("the Usage tab does not navigate to ?page=usage")
	}
}

func renderAdminPage(t *testing.T, vars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("admin.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing admin.html: %v", err)
	}
	vars.Title = "Admin"
	vars.BetaNav = &NavElem{}
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, baseName, vars)
	if err != nil {
		t.Fatalf("rendering admin.html: %v", err)
	}
	return buf.String()
}
