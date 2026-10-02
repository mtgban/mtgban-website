// Package jobs records what the site's background jobs did: when each last
// ran and for how long, whether that run panicked, what the job reported
// finding and what is wrong with it, and whether a scheduled one has missed
// its time. The admin dashboard lists it; the staleness alarm announces a job
// turning bad.
package jobs

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// Slack is how late a scheduled job may start, or run on past its next time,
// before it is late.
const Slack = 10 * time.Minute

// Tracker holds every job's record.
type Tracker struct {
	mu    sync.Mutex
	start time.Time
	clock func() time.Time
	jobs  map[string]*record
}

type record struct {
	next     func(time.Time) time.Time
	started  time.Time
	took     time.Duration
	active   int
	panicked string
	result   string
	problem  string
}

// New returns a tracker for a process started at start.
func New(start time.Time) *Tracker {
	return &Tracker{start: start, clock: time.Now, jobs: map[string]*record{}}
}

// get is name's record, made on first sight. Callers hold mu.
func (t *Tracker) get(name string) *record {
	r, found := t.jobs[name]
	if !found {
		r = &record{}
		t.jobs[name] = r
	}
	return r
}

// Schedule records that name runs at the times next gives after any time,
// so a run it misses shows.
func (t *Tracker) Schedule(name string, next func(time.Time) time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.get(name).next = next
}

// Start records a run of name beginning now, and returns the func that
// records it ending, given the value it panicked with, nil for none.
func (t *Tracker) Start(name string) func(panicked any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.get(name)
	began := t.clock()
	r.started = began
	r.active++
	r.panicked = ""
	return func(panicked any) {
		t.mu.Lock()
		defer t.mu.Unlock()
		r.active--
		r.took = t.clock().Sub(began)
		if panicked != nil {
			r.panicked = fmt.Sprint(panicked)
		}
	}
}

// Report records what name's latest run found, and what is wrong with that,
// "" when nothing is. Both stand until its next report.
func (t *Tracker) Report(name, result, problem string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.get(name)
	r.result, r.problem = result, problem
}

// Row is one job as of a moment.
type Row struct {
	Name    string
	Started time.Time     // its latest run's start, zero if it never ran
	Took    time.Duration // its latest finished run's length
	Running bool
	Result  string
	Problem string // "" when nothing is wrong
}

// TookText is Took to the second, "" before a run has finished.
func (r Row) TookText() string {
	if r.Took == 0 && (r.Started.IsZero() || r.Running) {
		return ""
	}
	return r.Took.Round(time.Second).String()
}

// Rows lists the jobs as of now, by name: the order they are first seen in
// depends on which goroutine runs first.
func (t *Tracker) Rows() []Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	rows := make([]Row, 0, len(t.jobs))
	for _, name := range slices.Sorted(maps.Keys(t.jobs)) {
		r := t.jobs[name]
		rows = append(rows, Row{
			Name:    name,
			Started: r.started,
			Took:    r.took,
			Running: r.active > 0,
			Result:  r.result,
			Problem: r.problemAt(now, t.start),
		})
	}
	return rows
}

// problemAt is what is wrong with the job as of now: a panic in its latest
// run, then a scheduled time it missed or ran on past, then what it
// reported.
func (r *record) problemAt(now, start time.Time) string {
	if r.panicked != "" {
		return "panicked: " + r.panicked
	}
	if r.next != nil {
		since := r.started
		if since.IsZero() {
			since = start
		}
		late := now.After(r.next(since).Add(Slack))
		switch {
		case late && r.active > 0:
			return "has been running for " + Age(now.Sub(r.started))
		case late && r.started.IsZero():
			return "has not run in the " + Age(now.Sub(start)) + " since startup"
		case late:
			return "last ran " + Age(now.Sub(r.started)) + " ago"
		}
	}
	return r.problem
}

// Age is d in the largest whole unit that fits: minutes, hours, or days past
// two of them.
func Age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
