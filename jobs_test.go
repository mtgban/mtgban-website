package main

import (
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/jobs"
)

// setTestJobs swaps in an empty job tracker and a site started an hour ago,
// and puts both back after.
func setTestJobs(t *testing.T) {
	t.Helper()
	prevJobs, prevStart := backgroundJobs, StartTime
	t.Cleanup(func() { backgroundJobs, StartTime = prevJobs, prevStart })
	StartTime = time.Now().Add(-time.Hour)
	backgroundJobs = jobs.New(StartTime)
}

func jobRow(t *testing.T, name string) jobs.Row {
	t.Helper()
	for _, row := range backgroundJobs.Rows() {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("no row for %s", name)
	return jobs.Row{}
}

// TestTrackedRecordsRunsAndPanics records a job's run, and recovers and
// records its panic without ending the test.
func TestTrackedRecordsRunsAndPanics(t *testing.T) {
	setTestJobs(t)

	tracked("ZZ job", func() {})()
	if row := jobRow(t, "ZZ job"); row.Started.IsZero() || row.Running || row.Problem != "" {
		t.Errorf("after a clean run: got %+v", row)
	}
	tracked("ZZ job", func() { panic("boom") })()
	if row := jobRow(t, "ZZ job"); row.Running || row.Problem != "panicked: boom" {
		t.Errorf("after a panic: got %+v", row)
	}
}

// setTestVendors serves vendors for the test.
func setTestVendors(t *testing.T, vendors ...mtgban.Vendor) {
	t.Helper()
	prev := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prev) })
	vendorsPtr.Store(&vendors)
}

// TestSetAnalysisReport flags an analysis on the empty datastore, and on a
// site serving CK's buylist one without a P90.
func TestSetAnalysisReport(t *testing.T) {
	setTestVendors(t, buylistOf("CK", 1, time.Now()))

	card := mtgban.InventoryRecord{"a": {{Price: 1}}}
	loaded := time.Now()
	for _, tc := range []struct {
		name          string
		loadedAt      time.Time
		infos         map[string]mtgban.InventoryRecord
		result, probl string
	}{
		{"found its P90s", loaded, map[string]mtgban.InventoryRecord{"goodP90": card, "hotlist": card}, "1 P90s, 1 90d highs, 0 new highs", ""},
		{"no P90s", loaded, map[string]mtgban.InventoryRecord{}, "0 P90s, 0 90d highs, 0 new highs", "found no P90s"},
		{"before the datastore", time.Time{}, map[string]mtgban.InventoryRecord{}, "0 P90s, 0 90d highs, 0 new highs", "ran before the datastore loaded"},
	} {
		result, problem := setAnalysisReport(tc.loadedAt, tc.infos)
		if result != tc.result || problem != tc.probl {
			t.Errorf("%s: got %q, %q, want %q, %q", tc.name, result, problem, tc.result, tc.probl)
		}
	}

	setTestVendors(t, buylistOf("SCG", 1, time.Now()))
	if result, problem := setAnalysisReport(loaded, nil); result != "" || problem != "" {
		t.Errorf("no CK buylist, no P90s: got %q, %q, want nothing", result, problem)
	}
}

// TestCKSignalsReport flags each input CK's signals go wrong without, and
// signals that never say sell now or wait.
func TestCKSignalsReport(t *testing.T) {
	now := time.Now()
	fresh := &ckHistorySnapshot{Today: ckToday(now)}
	odds := &ckOdds{Generated: now.Add(-10 * time.Hour)}
	signals := map[string]ckSignal{"a": {Rule: "sell"}, "b": {Rule: "cut"}, "c": {Pause: ckPause{Paused: true}}}

	result, problem := ckSignalsReport(signals, fresh, odds, now)
	if result != "1 sell now, 1 wait, 1 paused, of 3 cards" || problem != "" {
		t.Errorf("healthy: got %q, %q", result, problem)
	}
	for _, tc := range []struct {
		name    string
		history *ckHistorySnapshot
		odds    *ckOdds
		signals map[string]ckSignal
		want    string
	}{
		{"no history", nil, odds, signals, "have no stock history"},
		{"history two days behind", &ckHistorySnapshot{Today: ckToday(now).AddDate(0, 0, -2)}, odds, signals,
			"read a stock history from " + ckToday(now).AddDate(0, 0, -2).Format(time.DateOnly)},
		{"no odds", fresh, nil, signals, "have no odds"},
		{"odds a missed run old", fresh, &ckOdds{Generated: now.Add(-40 * time.Hour)}, signals, "quote odds 40h old"},
		{"no sell now or wait", fresh, odds, map[string]ckSignal{"c": {Pause: ckPause{Paused: true}}}, "have no sell now or wait"},
	} {
		_, problem := ckSignalsReport(tc.signals, tc.history, tc.odds, now)
		if problem != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, problem, tc.want)
		}
	}
}

// TestCheckJobHealthAnnouncesTransitions posts a job turning bad once, stays
// quiet while it stays bad and while the site is starting, and posts its
// recovery once.
func TestCheckJobHealthAnnouncesTransitions(t *testing.T) {
	setTestJobs(t)
	prevState, prevNotify, prevGame := staleAlarmState.stale, notifyStale, Config().Game
	t.Cleanup(func() {
		staleAlarmState.stale, notifyStale, Config().Game = prevState, prevNotify, prevGame
	})
	staleAlarmState.stale = map[string]bool{}
	Config().Game = DefaultGame
	var notices []string
	notifyStale = func(kind, message string) error {
		notices = append(notices, message)
		return nil
	}

	backgroundJobs.Report(jobSetAnalysis, "0 P90s", "found no P90s")
	checkJobHealth()
	checkJobHealth()
	if len(notices) != 1 || notices[0] != "magic: Set analysis found no P90s" {
		t.Fatalf("after two checks with no P90s: got %q, want the one alarm", notices)
	}

	backgroundJobs.Report(jobSetAnalysis, "74730 P90s", "")
	checkJobHealth()
	if len(notices) != 2 || !strings.HasSuffix(notices[1], "Set analysis is fine again") {
		t.Fatalf("after the P90s came back: got %q, want the recovery", notices)
	}

	StartTime = time.Now()
	backgroundJobs.Report(jobSetAnalysis, "0 P90s", "found no P90s")
	checkJobHealth()
	if len(notices) != 2 {
		t.Errorf("just started: got %q, want nothing new", notices[2:])
	}
}
