package metricsreport

import (
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// investNames are the names Invest reads, shaped as their phases register them.
func investNames() []observability.Name {
	return []observability.Name{
		{Name: "auth.refuse", Report: observability.ReportSignal, Area: "account", Values: observability.ValueEnum,
			Enum: []string{"unauthenticated", "no_access", "rate_limited", "other"}, Scope: observability.ScopeRoute, Help: "h"},
		{Name: "api.refuse", Report: observability.ReportSignal, Area: "api", Values: observability.ValueEnum,
			Enum: []string{"no_key", "bad_sig", "expired", "rate_limited", "plan"}, Scope: observability.ScopeEnum,
			Scopes: []string{"api.v1", "api.v2.history", "api.v2.newspaper"}, Help: "h"},
		{Name: "search.result", Report: observability.ReportSignal, Area: "search", Values: observability.ValueEnum,
			Enum: []string{"found", "empty", "single"}, Help: "h"},
		{Name: "upload.parse_error", Report: observability.ReportSignal, Area: "upload", Values: observability.ValueEnum,
			Enum: []string{"no_list", "load_error"}, Scope: observability.ScopeEnum, Scopes: []string{"none", "text", "file_csv", "url"}, Help: "h"},
		{Name: "upload.source", Report: observability.ReportCandidate, Area: "upload", Values: observability.ValueEnum,
			Enum: []string{"text", "file_csv", "url", "url_prefix"}, Denom: "upload.mode", Kind: "option", Help: "h"},
		{Name: "alerts.delivered", Report: observability.ReportSignal, Area: "alerts", Values: observability.ValueEnum,
			Enum: []string{"ok", "fail", "refused", "deferred"}, Scope: observability.ScopeEnum, Scopes: []string{"discord", "email"}, Help: "h"},
		{Name: "http.status", Report: observability.ReportContext, Values: observability.ValueEnum,
			Enum: []string{"2xx", "3xx", "4xx", "5xx"}, Scope: observability.ScopeRoute, Help: "h"},
		{Name: "http.duration", Report: observability.ReportContext, Values: observability.ValueBucket,
			Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Scope: observability.ScopeRoute, Help: "h"},
		{Name: "ratelimit.reject", Report: observability.ReportSignal, Area: "site", Values: observability.ValueEnum,
			Enum: []string{"page", "api", "vote"}, Help: "h"},
		{Name: "metrics.flush", Report: observability.ReportInternal, Help: "h"},
		option("search.sort", "", "chrono", "hybrid", "alpha", "retail"),
	}
}

func section(sigs []Signal, name string) []Signal {
	var out []Signal
	for _, s := range sigs {
		if s.Section == name {
			out = append(out, s)
		}
	}
	return out
}

func labels(in []Signal) []string {
	var out []string
	for _, s := range in {
		out = append(out, s.Label)
	}
	return out
}

// finiteSignals fails the test on any rate that is NaN or infinite.
func finiteSignals(t *testing.T, sigs []Signal) {
	t.Helper()
	for _, s := range sigs {
		if math.IsNaN(s.Rate) || math.IsInf(s.Rate, 0) {
			t.Errorf("%s %s: rate %v", s.Section, s.Label, s.Rate)
		}
	}
}

func TestInvestWalls(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "auth.refuse", "newspaper", "no_access", 40, 20),
		tot(1, "auth.refuse", "newspaper", "no_access", 10, 9),
		tot(0, "auth.refuse", "sleepers", "no_access", 70, 20),
		tot(0, "auth.refuse", "sleepers", "unauthenticated", 900, 30), // not a wall
		tot(0, "api.refuse", "api.v2.history", "plan", 3, 2),
		tot(0, "api.refuse", "api.v2.newspaper", "plan", 2, 1),
		tot(0, "api.refuse", "api.v1", "no_key", 400, 30), // not a wall
	}
	got := section(Invest(investNames(), totals, nil, w30), "walls")
	// measured rows by count, then the three ui. picks as not measured, in pick order
	if len(got) != 6 {
		t.Fatalf("got %d wall rows: %+v", len(got), got)
	}
	if got[0].Scope != "sleepers" || got[0].Count != 70 || got[1].Scope != "newspaper" || got[1].Previous != 10 ||
		got[2].Name != "api.refuse" || got[2].Scope != "" || got[2].Count != 5 {
		t.Errorf("measured walls = %+v", got[:3])
	}
	if got[0].Label != "Page refused for the tier: sleepers" || got[0].Value != "no_access" {
		t.Errorf("row = %+v", got[0])
	}
	// summed over its scopes, the row keeps its value, so a tier line reads plan alone
	if got[2].Value != "plan" || got[2].Label != "API call refused by plan" || got[2].Denom != 0 || got[2].Evidence != "" {
		t.Errorf("api wall = %+v", got[2])
	}
	for i, name := range []string{"ui.search.sort_locked", "ui.row.locked", "ui.upload.upsell"} {
		if r := got[3+i]; r.Name != name || !r.NotMeasured || r.Count != 0 {
			t.Errorf("row %d = %+v, want %s not measured", 3+i, r, name)
		}
	}
}

func TestInvestFailureRates(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "search.result", "", "empty", 30, 30), tot(0, "search.result", "", "found", 170, 30),
		tot(0, "http.status", "search", "5xx", 2, 2), tot(0, "http.status", "search", "2xx", 998, 30),
		tot(0, "http.status", "go", "5xx", 3, 1), tot(0, "http.status", "go", "2xx", 46, 9), // 49 requests: under the floor
		tot(0, "http.duration", "upload", "<5s", 20, 9), tot(0, "http.duration", "upload", "5s+", 5, 3), tot(0, "http.duration", "upload", "<1s", 75, 30),
		tot(0, "alerts.delivered", "email", "fail", 1, 1), tot(0, "alerts.delivered", "email", "ok", 99, 30),
		tot(0, "upload.parse_error", "file_csv", "load_error", 8, 5), tot(0, "upload.parse_error", "url", "load_error", 4, 3),
		tot(0, "upload.parse_error", "none", "no_list", 3, 2), tot(0, "upload.source", "", "text", 300, 30),
		tot(0, "ratelimit.reject", "", "vote", 8, 3),
	}
	got := section(Invest(investNames(), totals, nil, w30), "failures")
	finiteSignals(t, got)
	// rate rows by rate: slow upload 0.25, empty searches 0.15, parse errors 15/315, alerts email 0.01, 5xx search 0.002;
	// then the count row; then Offline sync failed, not measured. Script errors is WithErrors' row, not Invest's.
	wantLabels := []string{"Slow requests: upload", "Empty searches", "Upload parse errors", "Alert deliveries failed: email", "Server errors: search", "Rate limited: vote", "Offline sync failed"}
	if !slices.Equal(labels(got), wantLabels) {
		t.Fatalf("got %q, want %q", labels(got), wantLabels)
	}
	if got[0].Count != 25 || got[0].Denom != 100 || got[1].Denom != 200 || got[2].Count != 15 || got[2].Evidence != "load_error 12, no_list 3" || got[5].Denom != 0 {
		t.Errorf("numbers: %+v", got[:6])
	}
	if !got[6].NotMeasured || got[6].Name != "ui.offline.sync" {
		t.Error("the unmeasured row is flagged and keeps its name")
	}
	if got[1].Value != "empty" || got[4].Value != "5xx" || got[4].Scope != "search" || got[0].Value != "" || got[5].Value != "vote" {
		t.Errorf("keys: %+v", got[:6])
	}
}

// upload.source counts priced runs only, so an upload that failed joins the denominator;
// url_prefix is a redirect whose upload counts url again, so it is left out.
func TestInvestUploadParseErrorDenominator(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "upload.parse_error", "none", "no_list", 10, 5),
		tot(0, "upload.source", "", "text", 60, 30), tot(0, "upload.source", "", "url", 30, 20),
		tot(0, "upload.source", "", "url_prefix", 30, 20),
	}
	got := section(Invest(investNames(), totals, nil, w30), "failures")
	if got[0].Label != "Upload parse errors" || got[0].Denom != 100 || got[0].Rate != 0.1 {
		t.Errorf("parse errors = %+v", got[0])
	}
}

// deferred counts again on every retry, so it is in neither side; refused is a failure.
func TestInvestAlertDeliveries(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "alerts.delivered", "discord", "fail", 2, 2), tot(0, "alerts.delivered", "discord", "refused", 3, 2),
		tot(0, "alerts.delivered", "discord", "ok", 95, 30), tot(0, "alerts.delivered", "discord", "deferred", 4000, 30),
		tot(0, "alerts.delivered", "email", "refused", 1, 1), tot(0, "alerts.delivered", "email", "ok", 48, 30), // 49: under the floor
		tot(0, "alerts.delivered", "email", "deferred", 900, 30),
	}
	got := section(Invest(investNames(), totals, nil, w30), "failures")
	if len(got) != 2 || got[0].Label != "Alert deliveries failed: discord" || got[0].Count != 5 || got[0].Denom != 100 ||
		got[0].Rate != 0.05 || got[0].Evidence != "fail 2, refused 3" || got[0].Value != "" {
		t.Errorf("alerts = %+v", got)
	}
}

func TestInvestRateFloor(t *testing.T) {
	for _, tc := range []struct {
		ok   int64
		want bool
	}{{48, false}, {49, true}} {
		totals := []observability.DayTotal{tot(0, "http.status", "go", "5xx", 1, 1), tot(0, "http.status", "go", "2xx", tc.ok, 9)}
		got := section(Invest(investNames(), totals, nil, w30), "failures")
		if has := len(got) > 0 && got[0].Name == "http.status"; has != tc.want {
			t.Errorf("denominator %d: shown %v, want %v", tc.ok+1, has, tc.want)
		}
	}
	// a rate row needs a count
	got := section(Invest(investNames(), []observability.DayTotal{tot(0, "http.status", "go", "2xx", 900, 9)}, nil, w30), "failures")
	if len(got) != 1 || !got[0].NotMeasured {
		t.Errorf("no 5xx, no row: %+v", got)
	}
}

func TestWithErrors(t *testing.T) {
	signals := []Signal{
		{Section: "walls", Label: "w"},
		{Section: "failures", Label: "f1"}, {Section: "failures", Label: "f2"},
		{Section: "growing", Label: "g"},
	}
	off := WithErrors(signals, nil, false)
	if !slices.Equal(labels(off), []string{"w", "f1", "f2", "Script errors", "g"}) || !off[3].NotMeasured || off[3].Section != "failures" {
		t.Errorf("not measured: %+v", off)
	}
	rows := []Signal{{Section: "failures", Label: "navbar.js:42 TypeError", Count: 7}, {Section: "failures", Label: "utils.js:7 RangeError", Count: 2}}
	on := WithErrors(signals, rows, true)
	if !slices.Equal(labels(on), []string{"w", "f1", "f2", "navbar.js:42 TypeError", "utils.js:7 RangeError", "g"}) {
		t.Errorf("measured: %v", labels(on))
	}
	if got := WithErrors(signals, nil, true); len(got) != len(signals) {
		t.Errorf("measured with no errors adds no row: %v", labels(got))
	}
	if got := WithErrors(nil, nil, false); len(got) != 1 || got[0].Label != "Script errors" {
		t.Errorf("with no signals the row still shows: %+v", got)
	}
	// no failures row: after the walls, before the first later section
	if got := WithErrors([]Signal{{Section: "walls", Label: "w"}, {Section: "depth", Label: "d"}}, nil, false); !slices.Equal(labels(got), []string{"w", "Script errors", "d"}) {
		t.Errorf("no failures: %v", labels(got))
	}
	if got := WithErrors([]Signal{{Section: "walls", Label: "w"}}, nil, false); !slices.Equal(labels(got), []string{"w", "Script errors"}) {
		t.Errorf("walls only: %v", labels(got))
	}
	if len(signals) != 4 || signals[3].Label != "g" {
		t.Error("the input is not modified")
	}
}

func TestInvestMobileAndDepth(t *testing.T) {
	pages := []PageDepth{
		{Page: "arbit", Views: 200, MobileViews: 50, Visitors: 20, Once: 5, FivePlus: 9},
		{Page: "search", Views: 9000, MobileViews: 4000, Visitors: 150, Once: 60, FivePlus: 40, HasMobile: true},
		{Page: "upload", Views: 300, Visitors: 30, Once: 30},
		{Page: "screener", Views: 40, MobileViews: 30, Visitors: 4, Once: 4}, // too few views for a share
	}
	got := Invest(nil, nil, pages, w30)
	finiteSignals(t, got)
	mobile, depth := section(got, "mobile"), section(got, "depth")
	if len(mobile) != 2 || mobile[0].Label != "arbit" || mobile[0].Count != 50 || mobile[0].Denom != 200 || mobile[0].Rate != 0.25 ||
		mobile[0].Name != "page.view" || mobile[0].Value != "arbit" || !mobile[0].HasRate() {
		t.Errorf("mobile = %+v", mobile)
	}
	if mobile[1].Label != "screener" || mobile[1].Rate != 0 || mobile[1].HasRate() {
		t.Errorf("forty views is too few to say: %+v", mobile[1])
	}
	if len(depth) != 4 || depth[0].Label != "search" || depth[0].Count != 40 || depth[0].Denom != 150 || depth[2].Evidence != "5 once, 9 on five or more days" {
		t.Errorf("depth = %+v", depth)
	}
	if math.Abs(depth[0].Rate-40.0/150) > 1e-12 || !depth[0].HasRate() || depth[2].Rate != 0 || depth[2].HasRate() {
		t.Errorf("depth rates: %+v", depth)
	}
}

func TestInvestGrowingAndNew(t *testing.T) {
	names := append(investNames(), observability.Name{Name: "search.source", Report: observability.ReportContext, Area: "search", Help: "h"},
		observability.Name{Name: "news.three_day", Report: observability.ReportContext, Area: "news", Help: "h"})
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30), tot(1, "metrics.flush", "", "", 43200, 30),
		tot(0, "search.source", "search", "banbot", 75, 20), tot(1, "search.source", "search", "banbot", 50, 20), // exactly 1.5 times
		tot(0, "search.sort", "", "alpha", 49, 20), tot(1, "search.sort", "", "alpha", 10, 5), // under the floor
		tot(0, "search.sort", "", "retail", 149, 20), tot(1, "search.sort", "", "retail", 100, 20), // 1.49 times
		tot(0, "news.three_day", "", "on", 60, 12), // no rows before
	}
	got := Invest(names, totals, nil, w30)
	finiteSignals(t, got)
	growing, fresh := section(got, "growing"), section(got, "new")
	if len(growing) != 1 || growing[0].Name != "search.source" || growing[0].Count != 75 || growing[0].Previous != 50 || growing[0].Rate != 1.5 || !growing[0].HasRate() {
		t.Errorf("growing = %+v", growing)
	}
	if len(fresh) != 1 || fresh[0].Name != "news.three_day" || fresh[0].Count != 60 || !strings.HasPrefix(fresh[0].Evidence, "first seen 2026-") {
		t.Errorf("new = %+v", fresh)
	}
	if fresh[0].Evidence != "first seen 2026-10-30" {
		t.Errorf("first seen is the oldest First: %q", fresh[0].Evidence)
	}
}

func TestInvestGrowingFloor(t *testing.T) {
	flush := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30)}
	for _, tc := range []struct {
		p0   int64
		want bool
	}{{49, false}, {50, true}} {
		totals := append(slices.Clone(flush), tot(0, "ratelimit.reject", "", "vote", tc.p0, 9), tot(1, "ratelimit.reject", "", "vote", 10, 3))
		if got := section(Invest(investNames(), totals, nil, w30), "growing"); (len(got) == 1) != tc.want {
			t.Errorf("%d uses: %+v", tc.p0, got)
		}
	}
}

func TestInvestNewNeedsTheCounterToHaveRunBefore(t *testing.T) {
	names := append(investNames(), observability.Name{Name: "news.three_day", Report: observability.ReportContext, Area: "news", Help: "h"})
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 43200, 30), tot(0, "news.three_day", "", "on", 60, 12)}
	if got := section(Invest(names, totals, nil, w30), "new"); len(got) != 0 {
		t.Errorf("new with no counter before: %+v", got)
	}
	// a row in the window before: not new
	totals = append(totals, tot(1, "metrics.flush", "", "", 43200, 30), tot(1, "news.three_day", "", "off", 1, 1))
	if got := section(Invest(names, totals, nil, w30), "new"); len(got) != 0 {
		t.Errorf("seen before: %+v", got)
	}
}

func TestInvestGrowingIsPerUnitForACandidate(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30),
		tot(0, "search.sort", "search", "alpha", 200, 30), tot(1, "search.sort", "search", "alpha", 100, 30),
		tot(0, "search.sort", "search", "chrono", 9000, 30), tot(1, "search.sort", "search", "chrono", 9000, 30),
	}
	got := section(Invest(investNames(), totals, nil, w30), "growing")
	if len(got) != 1 || got[0].Value != "alpha" || got[0].Scope != "" || got[0].Label != "search.sort: alpha" || got[0].Rate != 2 {
		t.Errorf("growing = %+v", got)
	}
}

// Growth is per day the counter flushed, so a counter that started partway through
// the window before does not make every name grow.
func TestInvestGrowingIsPerCountedDay(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 15),
		tot(0, "search.sort", "", "alpha", 120, 30), tot(1, "search.sort", "", "alpha", 60, 15), // 4 a day, then 4 a day
		tot(0, "search.sort", "", "retail", 240, 30), tot(1, "search.sort", "", "retail", 60, 15), // 8 a day against 4
	}
	got := section(Invest(investNames(), totals, nil, w30), "growing")
	if len(got) != 1 || got[0].Value != "retail" || got[0].Count != 240 || got[0].Previous != 60 || got[0].Rate != 2 {
		t.Errorf("growing = %+v", got)
	}
	// the counter ran in only one of the two periods: nothing to compare
	only := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(0, "ratelimit.reject", "", "vote", 900, 30), tot(1, "ratelimit.reject", "", "vote", 1, 1)}
	if got := section(Invest(investNames(), only, nil, w30), "growing"); len(got) != 0 {
		t.Errorf("one-sided counter: %+v", got)
	}
	// no flush rows at all: nothing to compare
	if got := section(Invest(investNames(), totals[2:], nil, w30), "growing"); len(got) != 0 {
		t.Errorf("no counter: %+v", got)
	}
}

// Each period needs 14 flushed days before growth is judged: no row at all under that.
func TestInvestGrowingNeedsCountedDaysInBothPeriods(t *testing.T) {
	for _, tc := range []struct {
		d0, d1 int
		want   bool
	}{{13, 30, false}, {14, 30, true}, {30, 13, false}, {30, 14, true}} {
		totals := []observability.DayTotal{
			tot(0, "metrics.flush", "", "", 1, tc.d0), tot(1, "metrics.flush", "", "", 1, tc.d1),
			tot(0, "ratelimit.reject", "", "vote", int64(10*tc.d0), tc.d0), tot(1, "ratelimit.reject", "", "vote", int64(2*tc.d1), tc.d1), // 10 a day against 2
		}
		if got := section(Invest(investNames(), totals, nil, w30), "growing"); (len(got) == 1) != tc.want {
			t.Errorf("flushed days %d and %d: %+v", tc.d0, tc.d1, got)
		}
	}
}

func TestInvestNewNeedsAFloor(t *testing.T) {
	names := append(investNames(), observability.Name{Name: "news.three_day", Report: observability.ReportContext, Area: "news", Help: "h"})
	for _, tc := range []struct {
		n    int64
		want bool
	}{{19, false}, {20, true}} {
		totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30), tot(0, "news.three_day", "", "on", tc.n, 3)}
		if got := section(Invest(names, totals, nil, w30), "new"); (len(got) == 1) != tc.want {
			t.Errorf("%d uses: %+v", tc.n, got)
		}
	}
}

// Internal names and standing counts are never growing or new.
func TestInvestGrowingSkipsInternalAndStock(t *testing.T) {
	names := append(investNames(), observability.Name{Name: "stock.rows", Family: observability.FamilyStock, Report: observability.ReportContext, Area: "account", Help: "h"})
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 9000, 30), tot(1, "metrics.flush", "", "", 100, 30),
		tot(0, "stock.rows", "", "", 900, 1),
	}
	got := Invest(names, totals, nil, w30)
	if g, n := section(got, "growing"), section(got, "new"); len(g) != 0 || len(n) != 0 {
		t.Errorf("growing %+v new %+v", g, n)
	}
}

func TestInvestWithNothing(t *testing.T) {
	got := Invest(nil, nil, nil, w30)
	if len(got) != len(walls)+len(failures) || len(walls) != 5 || len(failures) != 7 {
		t.Fatalf("got %d rows: %+v", len(got), got)
	}
	for _, s := range got {
		if !s.NotMeasured || (s.Section != "walls" && s.Section != "failures") || s.Name == "" {
			t.Errorf("row %+v", s)
		}
	}
	// registered server picks with nothing to report give no row
	if got := Invest(investNames(), nil, nil, w30); len(got) != 4 {
		t.Errorf("registered, no rows: %+v", got)
	}
	if got := Invest(investNames(), nil, nil, Window{}); len(got) != 4 {
		t.Errorf("a zero window: %+v", got)
	}
}

// A client pick reads "not measured" until ui.load rows arrive.
func TestInvestUIPicksNeedALoad(t *testing.T) {
	names := append(investNames(),
		observability.Name{Name: "ui.load", Family: observability.FamilyUI, Report: observability.ReportInternal, Scope: observability.ScopePage, Help: "h"},
		observability.Name{Name: "ui.row.locked", Family: observability.FamilyUI, Report: observability.ReportSignal, Area: "search",
			Values: observability.ValueEnum, Enum: []string{"join", "login", "velocity_upsell"}, Help: "h"})
	totals := []observability.DayTotal{tot(0, "ui.row.locked", "", "join", 12, 4), tot(0, "ui.row.locked", "", "login", 3, 2)}
	got := section(Invest(names, totals, nil, w30), "walls")
	if len(got) != 3 || !got[1].NotMeasured || got[1].Name != "ui.row.locked" {
		t.Errorf("no ui.load yet: %+v", got)
	}
	totals = append(totals, tot(1, "ui.load", "search", "", 900, 30)) // before the window
	if got := section(Invest(names, totals, nil, w30), "walls"); len(got) != 3 || !got[1].NotMeasured {
		t.Errorf("a ui.load before the window: %+v", got)
	}
	totals = append(totals, tot(0, "ui.load", "search", "", 900, 30))
	got = section(Invest(names, totals, nil, w30), "walls")
	if len(got) != 4 || got[0].Label != "Locked row action: join" || got[0].Value != "join" || got[0].Count != 12 || got[1].Label != "Locked row action: login" ||
		!got[2].NotMeasured || got[2].Name != "ui.search.sort_locked" {
		t.Errorf("with a ui.load: %+v", got)
	}
}

func TestInvestPicksMatchTheRegistry(t *testing.T) {
	check := func(label string, p part, numerator bool) {
		n, ok := observability.Lookup(p.name)
		if !ok {
			if strings.HasPrefix(p.name, "ui.") {
				return // registered by 2b or 2d
			}
			t.Errorf("%s: %s is not registered", label, p.name)
			return
		}
		if numerator && n.Report != observability.ReportSignal && n.Report != observability.ReportContext {
			t.Errorf("%s: %s is report kind %d", label, p.name, n.Report)
		}
		for _, v := range append(slices.Clone(p.values), p.except...) {
			if !slices.Contains(n.Enum, v) {
				t.Errorf("%s: %s has no value %q", label, p.name, v)
			}
		}
	}
	for _, p := range append(slices.Clone(walls), failures...) {
		check(p.label, p.num, true)
		for _, d := range p.denom {
			check(p.label, d, false)
		}
		n, ok := observability.Lookup(p.num.name)
		if !ok {
			continue
		}
		if p.per == perScope && n.Scope == observability.ScopeNone {
			t.Errorf("%s: a row per scope of %s, which has none", p.label, p.num.name)
		}
		if p.per == perValue && n.Values == observability.ValueNone {
			t.Errorf("%s: a row per value of %s, which has none", p.label, p.num.name)
		}
	}
}

func TestInvestIsDeterministic(t *testing.T) {
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30),
		tot(0, "auth.refuse", "a", "no_access", 9, 1), tot(0, "auth.refuse", "b", "no_access", 9, 1), tot(0, "auth.refuse", "c", "no_access", 9, 1),
		tot(0, "http.status", "x", "5xx", 5, 1), tot(0, "http.status", "x", "2xx", 95, 1),
		tot(0, "http.status", "y", "5xx", 5, 1), tot(0, "http.status", "y", "2xx", 95, 1),
		tot(0, "ratelimit.reject", "", "page", 100, 9), tot(1, "ratelimit.reject", "", "page", 50, 9),
		tot(0, "ratelimit.reject", "", "vote", 100, 9), tot(1, "ratelimit.reject", "", "vote", 50, 9),
	}
	pages := []PageDepth{{Page: "a", Views: 100, MobileViews: 5, Visitors: 9}, {Page: "b", Views: 100, MobileViews: 5, Visitors: 9}}
	want := Invest(investNames(), totals, pages, w30)
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		sh, sp := slices.Clone(totals), slices.Clone(pages)
		r.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		r.Shuffle(len(sp), func(i, j int) { sp[i], sp[j] = sp[j], sp[i] })
		if got := Invest(investNames(), sh, sp, w30); !slices.Equal(got, want) {
			t.Fatalf("shuffled rows give\n%+v\nwant\n%+v", got, want)
		}
	}
}

// A 90-day window reads three periods and compares them with the three before.
func TestInvestWindowSpansItsPeriods(t *testing.T) {
	w90 := Window{Days: 90}
	totals := []observability.DayTotal{
		tot(0, "auth.refuse", "news", "no_access", 1, 1), tot(2, "auth.refuse", "news", "no_access", 2, 1),
		tot(3, "auth.refuse", "news", "no_access", 4, 1), tot(5, "auth.refuse", "news", "no_access", 8, 1),
		tot(6, "auth.refuse", "news", "no_access", 100, 1), // outside both windows
	}
	got := section(Invest(investNames(), totals, nil, w90), "walls")
	if got[0].Count != 3 || got[0].Previous != 12 {
		t.Errorf("90 days = %+v", got[0])
	}
}

func TestInvestRowsCarryHelp(t *testing.T) {
	names := investNames()
	for i := range names {
		names[i].Help = "help of " + names[i].Name
	}
	names = append(names, observability.Name{Name: "page.view", Values: observability.ValuePage, Area: "site", Help: "help of page.view"},
		observability.Name{Name: "news.three_day", Report: observability.ReportContext, Area: "news", Help: "help of news.three_day"})
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30),
		tot(0, "auth.refuse", "news", "no_access", 9, 3),
		tot(0, "search.result", "", "empty", 30, 30), tot(0, "search.result", "", "found", 170, 30),
		tot(0, "ratelimit.reject", "", "vote", 100, 9), tot(1, "ratelimit.reject", "", "vote", 20, 9),
		tot(0, "news.three_day", "", "on", 60, 12),
	}
	pages := []PageDepth{{Page: "arbit", Views: 200, MobileViews: 50, Visitors: 20}}
	for _, s := range Invest(names, totals, pages, w30) {
		want := "help of " + s.Name
		if strings.HasPrefix(s.Name, "ui.") {
			want = "" // not registered
		}
		if s.Help != want {
			t.Errorf("%s %s: help %q, want %q", s.Section, s.Label, s.Help, want)
		}
	}
}

// expectedLater are the names the rules read that a later stage registers, with the shape
// each rule assumes; once registered, the shape is checked.
var expectedLater = []struct {
	name, stage string
	shape       func(observability.Name) bool
}{
	{uiLoad, "2a", func(n observability.Name) bool {
		return n.Family == observability.FamilyUI && n.Scope == observability.ScopePage // scope read as the page
	}},
	{"ui.search.sort_locked", "2b", func(n observability.Name) bool { return n.Family == observability.FamilyUI }},
	{"ui.row.locked", "2b", func(n observability.Name) bool {
		return n.Family == observability.FamilyUI && n.Values != observability.ValueNone
	}},
	{"ui.upload.upsell", "2d", func(n observability.Name) bool { return n.Family == observability.FamilyUI }},
	{"ui.offline.sync", "2d", func(n observability.Name) bool {
		return n.Family == observability.FamilyUI && n.Scope != observability.ScopeNone && slices.Contains(n.Enum, "fail")
	}},
}

// Every name the rules read is pinned: registered now with the shape read, or listed as expected later.
func TestEveryNameReadIsPinned(t *testing.T) {
	flush, ok := observability.Lookup(flushName)
	if !ok || flush.Report != observability.ReportInternal || flush.Scope != observability.ScopeNone || flush.Values != observability.ValueNone {
		t.Errorf("%s = %+v: growing, new and Coverage read its days with no scope or value", flushName, flush)
	}
	pv, ok := observability.Lookup(pageView)
	if !ok || pv.Values != observability.ValuePage || pv.Family != observability.FamilyServer {
		t.Errorf("%s = %+v: Silent and the remove denominators read its value as the page", pageView, pv)
	}
	job, ok := observability.Lookup("job.run")
	if !ok || !slices.Equal(job.Scopes, []string{"fold", "stock", "events_rollup"}) || !slices.Contains(job.Enum, "ok") || !slices.Contains(job.Enum, "fail") {
		t.Errorf("job.run = %+v: Problems judges ok and fail, JobNote names stock", job)
	}
	reader, ok := observability.Lookup(stateReader)
	if !ok || reader.Family != observability.FamilyState || reader.Scope != observability.ScopeEnum || reader.Values != observability.ValueNone || !slices.Equal(reader.Scopes, observability.SettingPaths) {
		t.Errorf("%s = %+v: Coverage reads its days by path scope; Remove reads its rows as readers", stateReader, reader)
	}
	later := map[string]bool{}
	for _, e := range expectedLater {
		later[e.name] = true
		if n, ok := observability.Lookup(e.name); ok && !e.shape(n) {
			t.Errorf("%s, expected from stage %s, is registered with a shape the rules do not read: %+v", e.name, e.stage, n)
		}
	}
	for _, p := range append(slices.Clone(walls), failures...) {
		for _, pt := range append([]part{p.num}, p.denom...) {
			if _, ok := observability.Lookup(pt.name); !ok && !later[pt.name] {
				t.Errorf("%s: %s is neither registered nor expected later", p.label, pt.name)
			}
		}
	}
	for _, name := range []string{uiLoad, stateReader} {
		if _, ok := observability.Lookup(name); !ok && !later[name] {
			t.Errorf("%s is neither registered nor expected later", name)
		}
	}
}
