package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestInstanceProblem(t *testing.T) {
	for name, wantProblem := range map[string]bool{"": true, "shared": true, "magic": false, "magic-beta": false} {
		if got := instanceProblem(name) != ""; got != wantProblem {
			t.Errorf("instanceProblem(%q) reported a problem: %v, want %v", name, got, wantProblem)
		}
	}
}

func TestMetricsJobsEnabled(t *testing.T) {
	withConfigCopy(t)
	savedDB := ObservabilityDB
	t.Cleanup(func() { ObservabilityDB = savedDB })

	withFeatureCounter(t)
	ObservabilityDB = &observability.Client{}
	Config().MetricsJobs = false
	if metricsJobsEnabled() {
		t.Error("enabled without the flag")
	}
	Config().MetricsJobs = true
	if !metricsJobsEnabled() {
		t.Error("disabled with the flag, a database and a counter")
	}
	ObservabilityDB = nil
	if metricsJobsEnabled() {
		t.Error("enabled without a database")
	}
	ObservabilityDB = &observability.Client{}
	FeatureCounter = nil
	if metricsJobsEnabled() {
		t.Error("enabled without the feature tables")
	}
}

// A flagged instance that schedules nothing says why.
func TestMetricsJobsProblem(t *testing.T) {
	withConfigCopy(t)
	savedDB := ObservabilityDB
	t.Cleanup(func() { ObservabilityDB = savedDB })
	withFeatureCounter(t)
	counter := FeatureCounter

	for _, c := range []struct {
		name, instance string
		flag, db, ctr  bool
		want           string // a fragment of the problem, "" for none
	}{
		{"not flagged", "", false, false, false, ""},
		{"scheduled", "magic", true, true, true, ""},
		{"no instance name", "", true, false, false, "instance_name"},
		{"shared instance name", "shared", true, false, false, "reserved"},
		{"no database", "magic", true, false, false, "no observability database"},
		{"no feature tables", "magic", true, true, false, "feature tables"},
	} {
		Config().MetricsJobs, Config().InstanceName = c.flag, c.instance
		ObservabilityDB, FeatureCounter = nil, nil
		if c.db {
			ObservabilityDB = &observability.Client{}
		}
		if c.ctr {
			FeatureCounter = counter
		}
		got := metricsJobsProblem()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: problem %q, want %q", c.name, got, c.want)
		}
		if got != "" && metricsJobsEnabled() {
			t.Errorf("%s: a problem on an instance that schedules the jobs", c.name)
		}
	}
}

func TestConfigReadsMetricsJobs(t *testing.T) {
	var c ConfigType
	if err := json.Unmarshal([]byte(`{"metrics_jobs": true}`), &c); err != nil || !c.MetricsJobs {
		t.Fatalf("metrics_jobs not read: %v, %v", c.MetricsJobs, err)
	}
}

// fakeFoldStore holds the UTC days that have minute rows.
type fakeFoldStore struct {
	minutes     []time.Time
	failOn      time.Time // FoldDay of this day fails
	calls       []string  // "fold 2026-11-10", "prune 2026-10-28"
	cancel      func()    // called after the prune numbered cancelAfter
	cancelAfter int
	prunes      int
	failErrors  bool // PruneErrors fails
}

func (f *fakeFoldStore) MinuteDaysBefore(_ context.Context, before time.Time) ([]time.Time, error) {
	f.calls = append(f.calls, "days "+before.Format(time.DateOnly))
	var out []time.Time
	for _, d := range f.minutes {
		if d.Before(before) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (f *fakeFoldStore) FoldDay(_ context.Context, day time.Time) (int64, error) {
	f.calls = append(f.calls, "fold "+day.Format(time.DateOnly))
	if day.Equal(f.failOn) {
		return 0, errors.New("fold failed")
	}
	return 10, nil
}

func (f *fakeFoldStore) PruneMinutes(_ context.Context, before time.Time) (int64, error) {
	f.calls = append(f.calls, "prune "+before.Format(time.DateOnly))
	kept := slices.DeleteFunc(slices.Clone(f.minutes), func(d time.Time) bool { return d.Before(before) })
	n := int64(len(f.minutes) - len(kept))
	f.minutes = kept
	if f.prunes++; f.cancel != nil && f.prunes == f.cancelAfter {
		f.cancel()
	}
	return n, nil
}

func (f *fakeFoldStore) PruneErrors(_ context.Context, before time.Time) (int64, error) {
	f.calls = append(f.calls, "prune errors "+before.Format(time.DateOnly))
	if f.failErrors {
		return 0, errors.New("prune failed")
	}
	return 7, nil
}

// dateOf is the UTC midnight of a YYYY-MM-DD date.
func dateOf(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// Phase 2f extends this test when it adds its foldPrunes entry: each want list
// that reaches the prunes gains its prune, and each result its count.
func TestFoldFeatureDays(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 40, 0, 0, time.UTC)

	store := &fakeFoldStore{minutes: []time.Time{dateOf("2026-11-10"), dateOf("2026-11-11")}}
	result, err := foldFeatureDays(context.Background(), store, now, false)
	want := []string{"days 2026-11-11", "fold 2026-11-08", "fold 2026-11-09", "fold 2026-11-10", "prune 2026-10-28", "prune errors 2026-08-13"}
	if err != nil || !slices.Equal(store.calls, want) {
		t.Fatalf("calls %v, err %v, want %v", store.calls, err, want)
	}
	if result != "folded 3 of 3 days, 30 rows; pruned 0 days, 0 minutes; swept 0 minutes; swept 7 errors" {
		t.Errorf("result = %q", result)
	}

	// After an outage days fold oldest first, and an expired day is pruned straight after its own fold.
	store = &fakeFoldStore{minutes: []time.Time{dateOf("2026-10-20"), dateOf("2026-10-22"), dateOf("2026-11-01"), dateOf("2026-11-09"), dateOf("2026-11-11")}}
	result, err = foldFeatureDays(context.Background(), store, now, false)
	want = []string{"days 2026-11-11", "fold 2026-10-20", "prune 2026-10-21", "fold 2026-10-22", "prune 2026-10-23",
		"fold 2026-11-01", "fold 2026-11-08", "fold 2026-11-09", "fold 2026-11-10", "prune 2026-10-28", "prune errors 2026-08-13"}
	if err != nil || !slices.Equal(store.calls, want) {
		t.Fatalf("outage: calls %v, err %v, want %v", store.calls, err, want)
	}
	if left := []time.Time{dateOf("2026-11-01"), dateOf("2026-11-09"), dateOf("2026-11-11")}; !slices.Equal(store.minutes, left) {
		t.Errorf("minutes left on %v, want %v", store.minutes, left)
	}
	if result != "folded 6 of 6 days, 60 rows; pruned 2 days, 2 minutes; swept 0 minutes; swept 7 errors" {
		t.Errorf("outage: result = %q", result)
	}

	// A fold that fails on day k keeps the days before it folded and pruned, and leaves k on untouched.
	store = &fakeFoldStore{minutes: []time.Time{dateOf("2026-10-20"), dateOf("2026-10-22"), dateOf("2026-10-25"), dateOf("2026-11-01")}, failOn: dateOf("2026-10-25")}
	result, err = foldFeatureDays(context.Background(), store, now, false)
	want = []string{"days 2026-11-11", "fold 2026-10-20", "prune 2026-10-21", "fold 2026-10-22", "prune 2026-10-23", "fold 2026-10-25"}
	if err == nil || !slices.Equal(store.calls, want) {
		t.Fatalf("failed fold: calls %v, err %v, want an error after %v", store.calls, err, want)
	}
	if left := []time.Time{dateOf("2026-10-25"), dateOf("2026-11-01")}; !slices.Equal(store.minutes, left) {
		t.Errorf("failed fold: minutes left on %v, want %v", store.minutes, left)
	}
	if result != "folded 2 of 7 days, 20 rows; pruned 2 days, 2 minutes" {
		t.Errorf("failed fold: result = %q", result)
	}

	// A context ended after two days stops there, keeps them, and reports progress rather than a failure.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store = &fakeFoldStore{minutes: []time.Time{dateOf("2026-10-20"), dateOf("2026-10-22"), dateOf("2026-10-25")}, cancel: cancel, cancelAfter: 2}
	result, err = foldFeatureDays(ctx, store, now, false)
	want = []string{"days 2026-11-11", "fold 2026-10-20", "prune 2026-10-21", "fold 2026-10-22", "prune 2026-10-23"}
	if err != nil || !slices.Equal(store.calls, want) {
		t.Fatalf("cancelled: calls %v, err %v, want %v", store.calls, err, want)
	}
	if left := []time.Time{dateOf("2026-10-25")}; !slices.Equal(store.minutes, left) {
		t.Errorf("cancelled: minutes left on %v, want %v", store.minutes, left)
	}
	if !strings.HasPrefix(result, "folded 2 of 6 days, 20 rows; pruned 2 days, 2 minutes") || !strings.Contains(result, "next night") {
		t.Errorf("cancelled: result = %q", result)
	}

	// A run with no time for one day is a failure and touches nothing.
	near, cancelNear := context.WithDeadline(context.Background(), time.Now().Add(jobStopMargin/2))
	defer cancelNear()
	store = &fakeFoldStore{minutes: []time.Time{dateOf("2026-10-20")}}
	_, err = foldFeatureDays(near, store, now, false)
	if !errors.Is(err, errNoDayDone) || !slices.Equal(store.calls, []string{"days 2026-11-11"}) {
		t.Fatalf("no time: calls %v, err %v, want errNoDayDone and no fold", store.calls, err)
	}

	// A run by hand folds the day in progress too, and prunes no differently.
	store = &fakeFoldStore{minutes: []time.Time{dateOf("2026-11-11")}}
	_, err = foldFeatureDays(context.Background(), store, now, true)
	want = []string{"days 2026-11-11", "fold 2026-11-08", "fold 2026-11-09", "fold 2026-11-10", "fold 2026-11-11", "prune 2026-10-28", "prune errors 2026-08-13"}
	if err != nil || !slices.Equal(store.calls, want) {
		t.Fatalf("by hand: calls %v, err %v, want %v", store.calls, err, want)
	}
}

// Every prune the fold job runs is named and bounded; minutes come first.
func TestFoldPrunes(t *testing.T) {
	if len(foldPrunes) == 0 || foldPrunes[0].what != "minutes" || foldPrunes[0].days != minuteRetentionDays {
		t.Fatalf("foldPrunes = %+v, want minutes at %d days first", foldPrunes, minuteRetentionDays)
	}
	for _, p := range foldPrunes {
		if p.what == "" || p.days <= 0 || p.run == nil {
			t.Errorf("prune %+v is incomplete", p)
		}
	}
}

// Error rows go at 90 days, after the minutes.
func TestFoldPrunesErrorRows(t *testing.T) {
	i := slices.IndexFunc(foldPrunes, func(p foldPrune) bool { return p.what == "errors" })
	if i < 1 || foldPrunes[i].days != errorRetentionDays || errorRetentionDays != 90 {
		t.Fatalf("foldPrunes = %+v, want errors at 90 days after minutes", foldPrunes)
	}
	store := &fakeFoldStore{}
	before := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	if n, err := foldPrunes[i].run(context.Background(), store, before); err != nil || n != 7 {
		t.Fatalf("run = %d, %v", n, err)
	}
	if !slices.Equal(store.calls, []string{"prune errors 2026-08-13"}) {
		t.Errorf("calls = %v", store.calls)
	}
}

// The cutoff is today's UTC midnight less 90 days, at any hour of the run.
func TestFoldCutsErrorRowsFromToday(t *testing.T) {
	now := time.Date(2026, 11, 11, 23, 59, 0, 0, time.UTC)
	for _, byHand := range []bool{false, true} {
		store := &fakeFoldStore{}
		if _, err := foldFeatureDays(context.Background(), store, now, byHand); err != nil {
			t.Fatalf("by hand %v: %v", byHand, err)
		}
		minutes := slices.Index(store.calls, "prune 2026-10-28")
		errs := slices.Index(store.calls, "prune errors 2026-08-13")
		if minutes < 0 || errs <= minutes {
			t.Errorf("by hand %v: calls %v, want the error prune at 2026-08-13 after the minutes", byHand, store.calls)
		}
	}
}

// A failed error prune fails the run, after the folds and the minutes.
func TestFailedErrorPruneFailsTheFoldRun(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 40, 0, 0, time.UTC)
	store := &fakeFoldStore{failErrors: true}
	result, err := foldFeatureDays(context.Background(), store, now, false)
	if err == nil || !slices.Contains(store.calls, "fold 2026-11-10") || !slices.Contains(store.calls, "prune 2026-10-28") {
		t.Fatalf("calls %v, err %v, want an error after the folds and the minute prune", store.calls, err)
	}
	if !strings.HasSuffix(result, "; swept 0 minutes") {
		t.Errorf("result = %q", result)
	}

	setTestJobs(t)
	rows := withFeatureCounter(t)
	free := func(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
		return true, fn(ctx)
	}
	metricsFoldJob(free, &fakeFoldStore{failErrors: true}, func() time.Time { return now }, false)()
	if got := find(rows.rows(), "job.run"); len(got) != 1 || got[0].Scope != "fold" || got[0].Value != "fail" {
		t.Errorf("job.run rows = %+v, want one fold fail", got)
	}
}

// The job body the cron and the admin tool share: one lock, one job.run row.
func TestMetricsFoldJob(t *testing.T) {
	setTestJobs(t)
	rows := withFeatureCounter(t)
	free := func(ctx context.Context, key string, fn func(context.Context) error) (bool, error) {
		if key != "metrics.fold" {
			t.Errorf("lock key %q", key)
		}
		return true, fn(ctx)
	}
	store := &fakeFoldStore{}
	now := func() time.Time { return time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC) }
	metricsFoldJob(free, store, now, true)()
	if !slices.Contains(store.calls, "fold 2026-11-11") {
		t.Errorf("calls %v, want today folded", store.calls)
	}
	if got := find(rows.rows(), "job.run"); len(got) != 1 || got[0].Scope != "fold" || got[0].Value != "ok" {
		t.Errorf("job.run rows = %+v", got)
	}
}

func TestFoldMetricsNowNeedsTheFlag(t *testing.T) {
	withConfigCopy(t)
	Config().MetricsJobs = false
	if msg := foldMetricsNow(); !strings.Contains(msg, "not enabled") {
		t.Errorf("message %q, want a refusal on an unflagged instance", msg)
	}
}

// job.run lists the metrics jobs in its scopes, where the Health view reads them.
func TestJobRunIsScopedByJob(t *testing.T) {
	n, ok := observability.Lookup("job.run")
	if !ok || n.Scope != observability.ScopeEnum || n.Values != observability.ValueEnum {
		t.Fatalf("job.run = %+v, want an enum scope and an enum value", n)
	}
	if !slices.Equal(n.Scopes, []string{"fold", "stock", "events_rollup"}) || !slices.Equal(n.Enum, []string{"ok", "fail"}) {
		t.Errorf("scopes %v, values %v", n.Scopes, n.Enum)
	}
	if _, _, ok := n.Check("", "ok", observability.Validators{}); ok {
		t.Error("a job.run row with no job is stored")
	}
}

// fakeRollUp holds the UTC days that have page hits.
type fakeRollUp struct {
	days        []time.Time
	before      time.Time
	labels      []string
	calls       []string // "roll 2025-01-02"
	failOn      time.Time
	cancel      func() // called after the roll numbered cancelAfter
	cancelAfter int
}

func (f *fakeRollUp) OldestEventDay(_ context.Context, before time.Time) (time.Time, bool, error) {
	f.before = before
	for _, d := range f.days {
		if d.Before(before) {
			return d, true, nil
		}
	}
	return time.Time{}, false, nil
}

func (f *fakeRollUp) RollUpEventDay(_ context.Context, day time.Time, labels []string) (int64, int64, error) {
	f.calls = append(f.calls, "roll "+day.Format(time.DateOnly))
	f.labels = labels
	if day.Equal(f.failOn) {
		return 0, 0, errors.New("roll failed")
	}
	f.days = slices.DeleteFunc(f.days, func(d time.Time) bool { return d.Equal(day) })
	if f.cancel != nil && len(f.calls) == f.cancelAfter {
		f.cancel()
	}
	return 2, 30, nil
}

func TestRollUpOldEventsKeepsFourHundredDays(t *testing.T) {
	store := &fakeRollUp{days: []time.Time{dateOf("2025-10-06"), dateOf("2025-10-07")}}
	result, err := rollUpOldEvents(context.Background(), store, time.Date(2026, 11, 11, 4, 30, 0, 0, time.UTC))
	if err != nil || !store.before.Equal(dateOf("2025-10-07")) {
		t.Fatalf("cutoff %v, err %v, want 2025-10-07", store.before, err)
	}
	if !slices.Equal(store.labels, pageLabels()) {
		t.Errorf("labels %v, want the page labels", store.labels)
	}
	if !slices.Equal(store.calls, []string{"roll 2025-10-06"}) {
		t.Errorf("calls %v, want the day before the cutoff alone", store.calls)
	}
	if result != "rolled 1 days, 2 day rows from 30 events; none remain" {
		t.Errorf("result = %q", result)
	}
}

func TestRollUpOldEventsGoesADayAtATime(t *testing.T) {
	now := time.Date(2026, 11, 11, 4, 30, 0, 0, time.UTC)
	backlog := func() []time.Time {
		return []time.Time{dateOf("2025-01-01"), dateOf("2025-01-02"), dateOf("2025-01-05")}
	}
	all := []string{"roll 2025-01-01", "roll 2025-01-02", "roll 2025-01-05"}

	// A backlog rolls oldest first, a statement per day.
	store := &fakeRollUp{days: backlog()}
	result, err := rollUpOldEvents(context.Background(), store, now)
	if err != nil || !slices.Equal(store.calls, all) || len(store.days) != 0 {
		t.Fatalf("calls %v, days left %v, err %v, want %v", store.calls, store.days, err, all)
	}
	if result != "rolled 3 days, 6 day rows from 90 events; none remain" {
		t.Errorf("result = %q", result)
	}

	// A context ended after the first day keeps it and leaves the other two for the next run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store = &fakeRollUp{days: backlog(), cancel: cancel, cancelAfter: 1}
	result, err = rollUpOldEvents(ctx, store, now)
	if err != nil || !slices.Equal(store.calls, all[:1]) || len(store.days) != 2 {
		t.Fatalf("cancelled: calls %v, days left %v, err %v", store.calls, store.days, err)
	}
	if result != "rolled 1 days, 2 day rows from 30 events; stopped, the rest rolls next night" {
		t.Errorf("cancelled: result = %q", result)
	}
	store.cancel = nil
	if _, err := rollUpOldEvents(context.Background(), store, now); err != nil || !slices.Equal(store.calls, all) {
		t.Errorf("next run: calls %v, err %v, want the other two rolled", store.calls, err)
	}

	// A failure on day k reports the days before it.
	store = &fakeRollUp{days: backlog(), failOn: dateOf("2025-01-02")}
	result, err = rollUpOldEvents(context.Background(), store, now)
	if err == nil || !slices.Equal(store.calls, all[:2]) || len(store.days) != 2 {
		t.Fatalf("failed: calls %v, days left %v, err %v", store.calls, store.days, err)
	}
	if !strings.HasPrefix(result, "rolled 1 days, 2 day rows from 30 events") {
		t.Errorf("failed: result = %q", result)
	}

	// Near the deadline nothing starts, and with no day done that is a failure that says more remain.
	near, cancelNear := context.WithDeadline(context.Background(), time.Now().Add(jobStopMargin/2))
	defer cancelNear()
	store = &fakeRollUp{days: backlog()}
	result, err = rollUpOldEvents(near, store, now)
	if !errors.Is(err, errNoDayDone) || len(store.calls) != 0 || !strings.HasSuffix(result, "more remain") {
		t.Fatalf("no time: calls %v, result %q, err %v", store.calls, result, err)
	}
}

func TestRunMetricsJob(t *testing.T) {
	held := func(context.Context, string, func(context.Context) error) (bool, error) { return false, nil }
	free := func(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
		return true, fn(ctx)
	}

	for _, c := range []struct {
		name        string
		lock        jobLocker
		err         error
		wantValue   string // "" for no job.run row
		wantProblem bool
	}{
		{"ran", free, nil, "ok", false},
		{"failed", free, errors.New("boom"), "fail", true},
		{"lock held elsewhere", held, nil, "", true}, // the prior failure stands
		{"lock unreachable", func(context.Context, string, func(context.Context) error) (bool, error) {
			return false, errors.New("no database")
		}, nil, "fail", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			setTestJobs(t)
			rows := withFeatureCounter(t)
			// Every case follows a failed run; only a run that stood aside leaves its problem.
			backgroundJobs.Report(jobMetricsFold, "folded 1 of 4 days", "fold 2026-11-09: boom")
			called := false
			runMetricsJob(c.lock, jobMetricsFold, "fold", func(context.Context) (string, error) {
				called = true
				return "did it", c.err
			})
			row := jobRow(t, jobMetricsFold)
			if (row.Problem != "") != c.wantProblem {
				t.Errorf("dashboard problem %q, want one: %v", row.Problem, c.wantProblem)
			}
			got := find(rows.rows(), "job.run")
			switch {
			case c.wantValue == "" && (len(got) != 0 || called || row.Result != "the lock is held elsewhere"):
				t.Errorf("rows %v, called %v, result %q, want no run", got, called, row.Result)
			case c.wantValue != "" && (len(got) != 1 || got[0].Scope != "fold" || got[0].Value != c.wantValue || got[0].Device != "job"):
				t.Errorf("job.run rows = %+v, want one, scope fold, value %s", got, c.wantValue)
			}
		})
	}
}

// A job that panics counts as a failed run, and tracked still reports the panic.
func TestRunMetricsJobCountsAPanicAsAFailure(t *testing.T) {
	setTestJobs(t)
	rows := withFeatureCounter(t)
	free := func(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
		return true, fn(ctx)
	}
	tracked(jobMetricsFold, func() {
		runMetricsJob(free, jobMetricsFold, "fold", func(context.Context) (string, error) { panic("boom") })
	})()
	if row := jobRow(t, jobMetricsFold); row.Problem == "" {
		t.Error("the panic left no problem on the dashboard")
	}
	if got := find(rows.rows(), "job.run"); len(got) != 1 || got[0].Value != "fail" {
		t.Errorf("job.run rows = %+v, want one fail", got)
	}
}
