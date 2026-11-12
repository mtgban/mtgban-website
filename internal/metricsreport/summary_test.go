package metricsreport

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestTop(t *testing.T) {
	var in []Signal
	for _, l := range []string{"w1", "w2", "w3", "w4", "w5"} {
		in = append(in, Signal{Section: "walls", Label: l})
	}
	in = append(in, Signal{Section: "walls", Label: "wn", NotMeasured: true}, Signal{Section: "failures", Label: "f1"},
		Signal{Section: "failures", Label: "fn", NotMeasured: true})
	for _, l := range []string{"g1", "g2", "g3", "g4"} {
		in = append(in, Signal{Section: "growing", Label: l})
	}
	if got := labels(Top(in, 6)); !slices.Equal(got, []string{"w1", "w2", "f1", "g1", "g2", "w3"}) {
		t.Errorf("Top 6 = %v", got)
	}
	if got := labels(Top(in, 3)); !slices.Equal(got, []string{"w1", "w2", "f1"}) {
		t.Errorf("Top 3 = %v", got)
	}
	if got := labels(Top(in, 100)); len(got) != 10 || slices.Contains(got, "wn") || slices.Contains(got, "fn") {
		t.Errorf("Top 100 = %v", got)
	}
	if Top(in, 0) != nil || Top(nil, 5) != nil {
		t.Error("nothing to take")
	}
	if in[0].Label != "w1" || len(in) != 12 {
		t.Error("the input is not modified")
	}
}

func TestCoverage(t *testing.T) {
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 43200, 30), tot(1, "metrics.flush", "", "", 9000, 12)}
	got := Coverage(totals, nil, w30)
	want := []FamilyCoverage{
		{Label: "Server facts", Days: 30, Measured: true, PrevDays: 12},
		{Label: "Controls"}, {Label: "Settings"}, {Label: "Stored state"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v", got)
	}
	totals = append(totals, tot(0, "ui.load", "search", "", 900, 9), tot(0, "ui.load", "sets", "", 90, 4),
		tot(0, "state.reader", "SearchDefaultTab", "", 40, 3), tot(1, "ui.load", "search", "", 9, 25))
	stock := []observability.DayTotal{tot(0, "stock.rows", "", "", 40, 1), tot(0, "stock.sessions", "", "", 9, 1)}
	got = Coverage(totals, stock, w30)
	if got[1] != (FamilyCoverage{Label: "Controls", Days: 9, Measured: true}) || got[2] != (FamilyCoverage{Label: "Settings", Days: 3, Measured: true}) ||
		got[3] != (FamilyCoverage{Label: "Stored state", Days: 1, Measured: true}) {
		t.Errorf("got %+v", got)
	}
	if got := Coverage(nil, nil, w30); len(got) != 4 || got[0].Measured || got[3].Measured {
		t.Errorf("nothing: %+v", got)
	}
	// 90 days: the server's days are summed over three periods
	w90 := Window{Days: 90}
	totals = []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30), tot(2, "metrics.flush", "", "", 1, 5), tot(3, "metrics.flush", "", "", 1, 2)}
	if got := Coverage(totals, nil, w90); got[0].Days != 65 || got[0].PrevDays != 2 {
		t.Errorf("90 days: %+v", got[0])
	}
}

func TestAreas(t *testing.T) {
	names := []observability.Name{
		option("search.sort", "", "alpha"),
		{Name: "upload_share.open", Report: observability.ReportSignal, Area: "upload"},
		{Name: "http.status", Report: observability.ReportContext},
		{Name: "news.sort", Report: observability.ReportCandidate, Area: "news"},
		{Name: "news.page", Report: observability.ReportContext, Area: "sleepers"}, // a context name's area is not listed
		{Name: "page.view", Report: observability.ReportCandidate, Area: "site"},
		{Name: "metrics.flush", Report: observability.ReportInternal},
		{Name: "stock.rows", Family: observability.FamilyStock, Report: observability.ReportContext, Area: "account"},
		{Name: "auth.refuse", Report: observability.ReportSignal, Area: "account"},         // a refusal, not use
		{Name: "upload.parse_error", Report: observability.ReportSignal, Area: "upload"},   // an error, not use
		{Name: "ratelimit.reject", Report: observability.ReportSignal, Area: "ratelimits"}, // its only name is not use: no area
	}
	totals := []observability.DayTotal{
		tot(0, "auth.refuse", "search", "unauthenticated", 70000, 30),
		tot(0, "upload.parse_error", "url", "load_error", 400, 3),
		tot(0, "ratelimit.reject", "", "page", 900, 3),
		tot(0, "search.sort", "", "alpha", 9000, 30), tot(1, "search.sort", "", "alpha", 1, 1),
		tot(0, "upload_share.open", "", "ok", 15, 3),
		tot(0, "http.status", "search", "2xx", 99999, 30),
		tot(0, "page.view", "", "search", 500000, 30),
		tot(0, "news.page", "", "1", 99, 30),
	}
	got := Areas(names, totals, w30)
	want := []AreaCount{{"search", 9000}, {"upload", 15}, {"news", 0}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// ties go by area name
	tie := Areas(names[:4], nil, w30)
	if !slices.Equal(tie, []AreaCount{{"news", 0}, {"search", 0}, {"upload", 0}}) {
		t.Errorf("ties: %+v", tie)
	}
}

func TestStock(t *testing.T) {
	names := []observability.Name{
		{Name: "stock.rows", Family: observability.FamilyStock},
		{Name: "stock.alerts", Family: observability.FamilyStock},
		{Name: "stock.favorites", Family: observability.FamilyStock},
		{Name: "search.sort"},
	}
	day := func(d int, name, scope, value string, n int64) observability.DayTotal {
		at := time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC)
		return observability.DayTotal{Period: 10 - d, Name: name, Scope: scope, Value: value, N: n, Days: 1, First: at, Last: at}
	}
	stock := []observability.DayTotal{
		day(10, "stock.alerts", "magic", "retail", 30), day(10, "stock.alerts", "magic", "buylist", 10),
		day(10, "stock.alerts", "lorcana", "retail", 10),
		day(10, "stock.rows", "", "", 400),
		day(9, "stock.rows", "", "", 390),
		day(9, "stock.favorites", "", "1-9", 80), // absent on the newest day: not resurrected
		day(10, "search.sort", "", "alpha", 5),   // not a stock name
	}
	gotDay, groups := Stock(names, stock)
	if !gotDay.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day = %v", gotDay)
	}
	if len(groups) != 2 || groups[0].Name != "stock.rows" || groups[0].Total != 400 || groups[1].Name != "stock.alerts" || groups[1].Total != 50 {
		t.Fatalf("groups = %+v", groups)
	}
	a := groups[1].Rows
	if len(a) != 3 || a[0] != (StockShare{Scope: "magic", Value: "retail", N: 30, Share: 0.6}) || a[1].Scope != "lorcana" || a[2].Value != "buylist" || a[2].Share != 0.2 {
		t.Errorf("alerts rows = %+v", a)
	}
	if groups[0].Rows[0].Share != 1 {
		t.Errorf("a name's own total: %+v", groups[0].Rows)
	}
	// a row spanning several days is a sum of standing counts and is not read
	span := []observability.DayTotal{{Name: "stock.rows", N: 1200, Days: 3, First: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), Last: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)}}
	if _, g := Stock(names, span); len(g) != 0 {
		t.Errorf("a summed row: %+v", g)
	}
	if d, g := Stock(names, nil); !d.IsZero() || g != nil {
		t.Errorf("no rows: %v %+v", d, g)
	}
}

// notUse names a registered Signal or Candidate each, and every registered Signal is
// classed as use or not, so a new one cannot rank its refusals as use unnoticed.
func TestAreaNotUseMatchesTheRegistry(t *testing.T) {
	isUse := []string{
		"search.result",     // results page views
		"upload_share.open", // share links opened
		"auth.login",        // Patreon login callbacks
		"apiplans.handoff",  // steps of a reader's handoff to the API gateway
	}
	for name := range notUse {
		n, ok := observability.Lookup(name)
		if !ok || (n.Report != observability.ReportSignal && n.Report != observability.ReportCandidate) {
			t.Errorf("%s: registered %v, report kind %d; Areas reads only Signal and Candidate names", name, ok, n.Report)
		}
	}
	for _, n := range observability.All() {
		if n.Report == observability.ReportSignal && !notUse[n.Name] && !slices.Contains(isUse, n.Name) {
			t.Errorf("%s is a Signal Areas has not classed: add it to notUse or to this test's use list", n.Name)
		}
	}
	for _, name := range isUse {
		if n, ok := observability.Lookup(name); !ok || n.Report != observability.ReportSignal || notUse[name] {
			t.Errorf("%s: no longer a Signal counted as use", name)
		}
	}
}

// The names whose parts are no partition are registered stored-state names; every other stock name is one.
func TestPartitionMatchesTheRegistry(t *testing.T) {
	for name := range severalPerRow {
		n, ok := observability.Lookup(name)
		if !ok || n.Family != observability.FamilyStock || n.Values != observability.ValueEnum || Partition(n) {
			t.Errorf("%s: %+v", name, n)
		}
	}
	for _, n := range observability.All() {
		if n.Family == observability.FamilyStock && !severalPerRow[n.Name] && strings.Contains(n.Help, "more than one") {
			t.Errorf("%s says a reader can count more than once, but its parts are shown as shares", n.Name)
		}
	}
}
