package metricsreport

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// MinuteDays is how many days the minute rows of feature_events keep.
const MinuteDays = 14

// How old a counter flush or a job's last ok run may be before Health calls it stale.
const (
	StaleFlush = 10 * time.Minute // a flush older than this is stale
	StaleJob   = 36 * time.Hour   // an ok run older than this is overdue
)

// FlushStale reports whether a counter whose newest flush is last is stale at now:
// no flush at all, or one more than StaleFlush old. At exactly StaleFlush it is not.
func FlushStale(now, last time.Time) bool {
	return last.IsZero() || now.Sub(last) > StaleFlush
}

// The states JobStateOf gives a job.
const (
	JobOK      = "ok"
	JobNoRun   = "no_run"  // no ok or fail run in the MinuteDays the minute rows keep
	JobFailed  = "failed"  // the newest run failed
	JobOverdue = "overdue" // the newest run is ok but older than StaleJob
)

// JobState is what a job's runs say at one moment.
type JobState struct {
	Job       string
	Newest    observability.JobRun // the newest ok or fail run on any instance, an ok winning a tie; zero when none
	LastOK    observability.JobRun // the newest ok run on any instance; zero when none
	Status    string               // JobOK, JobNoRun, JobFailed or JobOverdue
	Threshold time.Duration        // StaleJob, the age an ok run becomes overdue past
}

// JobStateOf judges one job from runs on every instance; only results ok and fail count.
// A missing ok row is a failure, so an ok older than StaleJob is overdue even with no
// fail row; several ok rows a night are normal; at exactly StaleJob an ok is not overdue.
func JobStateOf(job string, runs []observability.JobRun, now time.Time) JobState {
	st := JobState{Job: job, Threshold: StaleJob}
	for _, r := range runs {
		if r.Job != job || (r.Result != "ok" && r.Result != "fail") {
			continue
		}
		// on a tie the ok wins: the job did finish
		if st.Newest.At.IsZero() || r.At.After(st.Newest.At) || (r.At.Equal(st.Newest.At) && r.Result == "ok") {
			st.Newest = r
		}
		if r.Result == "ok" && r.At.After(st.LastOK.At) {
			st.LastOK = r
		}
	}
	switch {
	case st.Newest.At.IsZero():
		st.Status = JobNoRun
	case st.Newest.Result == "fail":
		st.Status = JobFailed
	case now.Sub(st.LastOK.At) > StaleJob:
		st.Status = JobOverdue
	default:
		st.Status = JobOK
	}
	return st
}

// Problem is the state's Health line, or "" when the job is fine.
func (st JobState) Problem() string {
	switch st.Status {
	case JobNoRun:
		return fmt.Sprintf("Job %s: no run in %d days", st.Job, MinuteDays)
	case JobFailed:
		return fmt.Sprintf("Job %s: last run failed, %s", st.Job, healthTime(st.Newest.At))
	case JobOverdue:
		return fmt.Sprintf("Job %s: last ran %s", st.Job, healthTime(st.LastOK.At))
	}
	return ""
}

// everyView is one count the root emits on every page view of pages, so a page view
// there with no row of it can only mean broken instrumentation.
type everyView struct {
	name  string
	pages []string // page.view labels whose every view emits it; a subset of the name's Page list
}

// everyViewCounts are the only names Silent judges, each checked at its emit site; every one
// is emitted under isPageView, the same population page.view counts.
var everyViewCounts = []everyView{
	// arbitFacts via scraperCompare, both the landing and a store view; only an unknown source skips it
	{name: "arbit.view", pages: []string{"arbit", "reverse", "global"}},
	// News, page "": observe(news.report, index) before the render
	{name: "news.report", pages: []string{"newspaper/index"}},
	// sleepersFacts from Sleepers' default branch, the index
	{name: "sleepers.page", pages: []string{"sleepers/index"}},
	// APIPlans, on every view of the pricing page
	{name: "apiplans.view", pages: []string{"api-plans"}},
	// UploadHandoff, beside its own recordHit, shown or locked
	{name: "upload.handoff_page", pages: []string{"upload/handoff"}},
}

// Silent judges only the everyViewCounts present in names: one with no row in the last
// 30 days is broken when its pages had page views, quiet when they had none. Every other
// name is in neither list: a rare event, a POST-only fact or an unused feature having no
// rows says nothing about the instrumentation. allReaders are DayTotals over the last 30
// finished days with Step 30 and both toggles off (every reader, bots included), whatever
// the view says; only period 0 is read.
func Silent(names []observability.Name, allReaders []observability.DayTotal) (broken, quiet []string) {
	idx := newIndex(allReaders, 1)
	for _, e := range everyViewCounts {
		i := slices.IndexFunc(names, func(n observability.Name) bool { return n.Name == e.name })
		if i < 0 || idx.hasRows(e.name) {
			continue
		}
		onPages := names[i]
		onPages.Page, onPages.Denom = strings.Join(e.pages, ","), "" // the pages' own views
		if total, days := denominatorOf(onPages).measure(idx, 1); total > 0 || days > 0 {
			broken = append(broken, e.name)
		} else {
			quiet = append(quiet, e.name)
		}
	}
	slices.Sort(broken)
	slices.Sort(quiet)
	return broken, quiet
}

// HealthInput is what Problems judges, all of it read from minute rows.
type HealthInput struct {
	Now      time.Time
	Instance string                         // the instance the counter lines are about
	Counters []observability.InstanceHealth // CounterHealth from the start of yesterday
	Jobs     []observability.JobRun         // JobRuns, every instance
	JobNames []string                       // the scopes job.run is registered with
	Broken   []string                       // Silent's broken: counts missing although their pages were used
}

// healthTime prints a time for a Health line: "15:04 UTC on Jan 2".
func healthTime(t time.Time) string {
	return t.UTC().Format("15:04 UTC on Jan 2")
}

// Problems lists what makes the numbers untrustworthy, one short line each: the
// instance's counter, then at most one line a job in JobNames order, then one line for Silent's broken counts.
// A job's newest row on any instance decides; a missing ok row is a failure, so an ok
// older than a day and a half is reported even with no fail row.
func Problems(in HealthInput) []string {
	var out []string
	i := slices.IndexFunc(in.Counters, func(h observability.InstanceHealth) bool { return h.Instance == in.Instance })
	if i < 0 {
		out = append(out, fmt.Sprintf("Counters: nothing written by %s since yesterday", in.Instance))
	} else {
		h := in.Counters[i]
		switch {
		case h.LastFlush.IsZero():
			out = append(out, "Counters: nothing saved since yesterday")
		case FlushStale(in.Now, h.LastFlush):
			out = append(out, "Counters: last saved "+healthTime(h.LastFlush))
		}
		if h.Dropped > 0 {
			out = append(out, fmt.Sprintf("Counters: %d events dropped since yesterday", h.Dropped))
		}
		if h.FlushFailed > 0 {
			out = append(out, fmt.Sprintf("Counters: %d saves failed since yesterday", h.FlushFailed))
		}
	}
	for _, job := range in.JobNames {
		if line := JobStateOf(job, in.Jobs, in.Now).Problem(); line != "" {
			out = append(out, line)
		}
	}
	switch n := len(in.Broken); {
	case n == 1:
		out = append(out, "1 count missing for 30 days although its pages were used")
	case n > 1:
		out = append(out, fmt.Sprintf("%d counts missing for 30 days although their pages were used", n))
	}
	return out
}

// stockJobNote is the Health copy for the stock job, which runs only with the user-state database.
const stockJobNote = "Scheduled only where the user-state database is configured."

// JobNote is the Health copy that explains a job's row, or "".
func JobNote(job string) string {
	if job == "stock" {
		return stockJobNote
	}
	return ""
}
