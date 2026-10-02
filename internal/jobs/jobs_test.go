package jobs

import (
	"slices"
	"testing"
	"time"
)

// hourly is a schedule on the hour.
func hourly(t time.Time) time.Time {
	return t.Truncate(time.Hour).Add(time.Hour)
}

// newTestTracker is a tracker started at start whose clock reads *now.
func newTestTracker(start time.Time, now *time.Time) *Tracker {
	tracker := New(start)
	tracker.clock = func() time.Time { return *now }
	return tracker
}

func rowOf(t *testing.T, tracker *Tracker, name string) Row {
	t.Helper()
	for _, row := range tracker.Rows() {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("no row for %s", name)
	return Row{}
}

// TestRuns records a run's start, length and panic, and a panic clears at
// the next run.
func TestRuns(t *testing.T) {
	start := time.Date(2026, 9, 29, 15, 40, 0, 0, time.UTC)
	now := start
	tracker := newTestTracker(start, &now)

	finish := tracker.Start("stash")
	now = now.Add(90 * time.Second)
	if row := rowOf(t, tracker, "stash"); !row.Running || row.TookText() != "" {
		t.Errorf("mid-run: got %+v, want running with no length yet", row)
	}
	finish(nil)
	row := rowOf(t, tracker, "stash")
	if row.Running || !row.Started.Equal(start) || row.TookText() != "1m30s" || row.Problem != "" {
		t.Errorf("after a clean run: got %+v", row)
	}

	tracker.Start("stash")("runtime error: index out of range")
	if row := rowOf(t, tracker, "stash"); row.Problem != "panicked: runtime error: index out of range" {
		t.Errorf("after a panic: got %q", row.Problem)
	}
	tracker.Start("stash")(nil)
	if row := rowOf(t, tracker, "stash"); row.Problem != "" {
		t.Errorf("after the next clean run: got %q", row.Problem)
	}
}

// TestSchedule tells a scheduled job missing its time, before it ever ran
// and after, and running on past its next one; within Slack it is on time.
func TestSchedule(t *testing.T) {
	start := time.Date(2026, 9, 29, 15, 40, 0, 0, time.UTC)
	now := start
	tracker := newTestTracker(start, &now)
	tracker.Schedule("signals", hourly)

	for _, tc := range []struct {
		name string
		at   time.Time
		want string
	}{
		{"before its first time", start.Add(10 * time.Minute), ""},
		{"within the slack", time.Date(2026, 9, 29, 16, 9, 0, 0, time.UTC), ""},
		{"never ran past it", time.Date(2026, 9, 29, 17, 45, 0, 0, time.UTC), "has not run in the 2h since startup"},
	} {
		now = tc.at
		if got := rowOf(t, tracker, "signals").Problem; got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	now = time.Date(2026, 9, 29, 18, 0, 0, 0, time.UTC)
	finish := tracker.Start("signals")
	now = now.Add(80 * time.Minute)
	if got := rowOf(t, tracker, "signals").Problem; got != "has been running for 1h" {
		t.Errorf("running past its next time: got %q", got)
	}
	finish(nil)
	now = time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	if got := rowOf(t, tracker, "signals").Problem; got != "last ran 14h ago" {
		t.Errorf("missed since: got %q", got)
	}
}

// TestReport shows what a job reported, behind a panic or a missed time.
func TestReport(t *testing.T) {
	start := time.Date(2026, 9, 29, 15, 40, 0, 0, time.UTC)
	now := start
	tracker := newTestTracker(start, &now)
	tracker.Schedule("analysis", hourly)

	tracker.Start("analysis")(nil)
	tracker.Report("analysis", "0 P90s", "found no P90s")
	if row := rowOf(t, tracker, "analysis"); row.Result != "0 P90s" || row.Problem != "found no P90s" {
		t.Errorf("reported: got %+v", row)
	}
	now = time.Date(2026, 9, 29, 20, 0, 0, 0, time.UTC)
	if got := rowOf(t, tracker, "analysis").Problem; got != "last ran 4h ago" {
		t.Errorf("missed after reporting: got %q", got)
	}
	tracker.Start("analysis")(nil)
	tracker.Report("analysis", "74730 P90s", "")
	if got := rowOf(t, tracker, "analysis").Problem; got != "" {
		t.Errorf("a fine report: got %q", got)
	}

	if names := tracker.Rows(); len(names) != 1 {
		t.Errorf("got %d rows, want the one job", len(names))
	}
}

func TestAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		59 * time.Minute: "59m",
		2 * time.Hour:    "2h",
		47 * time.Hour:   "47h",
		50 * time.Hour:   "2d",
	} {
		if got := Age(d); got != want {
			t.Errorf("Age(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestRowsByName(t *testing.T) {
	now := time.Now()
	tracker := newTestTracker(now, &now)
	tracker.Start("b")
	tracker.Report("a", "", "")

	var names []string
	for _, row := range tracker.Rows() {
		names = append(names, row.Name)
	}
	if !slices.Equal(names, []string{"a", "b"}) {
		t.Errorf("rows %v, want them by name", names)
	}
}
