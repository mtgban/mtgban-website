package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// instanceProblem says why name cannot label this instance's counts, or "" if it can.
func instanceProblem(name string) string {
	switch name {
	case "":
		return "instance_name not set in config"
	case observability.SharedInstance:
		return "instance_name \"shared\" is reserved for stored-state counts"
	}
	return ""
}

// metricsJobsEnabled reports whether this instance runs the nightly metrics jobs.
func metricsJobsEnabled() bool {
	return Config().MetricsJobs && ObservabilityDB != nil && FeatureCounter != nil
}

// metricsJobsProblem says why a flagged instance schedules no metrics job, "" when it does or is not flagged.
func metricsJobsProblem() string {
	switch {
	case !Config().MetricsJobs:
		return ""
	case instanceProblem(Config().InstanceName) != "":
		return instanceProblem(Config().InstanceName)
	case ObservabilityDB == nil:
		return "no observability database"
	case FeatureCounter == nil:
		return "the feature tables are not ready"
	}
	return ""
}

// utcDay is t's UTC midnight.
func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// How long each table keeps its rows, and how many finished days every fold redoes.
const (
	minuteRetentionDays = 14
	eventsRetentionDays = 400
	foldCatchUpDays     = 3
)

// metricsJobTimeout bounds a run, so a stuck database cannot hold its lock all night.
const metricsJobTimeout = 10 * time.Minute

// jobStopMargin is how near its deadline a job stops starting another day.
const jobStopMargin = time.Minute

// timeLeft says ctx is live and more than jobStopMargin from its deadline.
func timeLeft(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) > jobStopMargin
}

// errNoDayDone is a job stopping for its deadline before it finished a day.
var errNoDayDone = errors.New("stopped at the deadline before a day was done")

// jobLocker runs fn under key's lock, or reports false when another holder has it.
type jobLocker func(ctx context.Context, key string, fn func(context.Context) error) (bool, error)

// runMetricsJob runs fn under scope's lock, reports it as job and counts how it ended.
func runMetricsJob(lock jobLocker, job, scope string, fn func(context.Context) (string, error)) {
	ctx, cancel := context.WithTimeout(ServerContext, metricsJobTimeout)
	defer cancel()
	settled := false
	// A panic still counts as a failed run; tracked reports the panic itself.
	defer func() {
		if !settled {
			observeJob("job", scope, "job.run", "fail")
		}
	}()
	var result string
	ran, err := lock(ctx, "metrics."+scope, func(ctx context.Context) error {
		var err error
		result, err = fn(ctx)
		return err
	})
	settled = true
	switch {
	case err != nil:
		log.Println(job+":", err)
		backgroundJobs.Report(job, result, err.Error())
		observeJob("job", scope, "job.run", "fail")
	case !ran:
		// A run that stood aside did nothing, so a previous run's problem stands.
		backgroundJobs.Note(job, "the lock is held elsewhere")
	default:
		backgroundJobs.Report(job, result, "")
		observeJob("job", scope, "job.run", "ok")
	}
}

// foldStore is what the fold job reads and trims.
type foldStore interface {
	MinuteDaysBefore(ctx context.Context, before time.Time) ([]time.Time, error)
	FoldDay(ctx context.Context, day time.Time) (int64, error)
	PruneMinutes(ctx context.Context, before time.Time) (int64, error)
}

// foldPrune is one table the fold job trims once the days are folded.
type foldPrune struct {
	what string // the noun in the job's result: "minutes"
	days int    // rows older than this many days before today go
	run  func(ctx context.Context, store foldStore, before time.Time) (int64, error)
}

// pruneMinutes deletes the minute rows before the cutoff.
func pruneMinutes(ctx context.Context, store foldStore, before time.Time) (int64, error) {
	return store.PruneMinutes(ctx, before)
}

// foldPrunes run in order after every fold; written once here, only read after.
var foldPrunes = []foldPrune{{what: "minutes", days: minuteRetentionDays, run: pruneMinutes}}

// foldDays is every finished day with minutes, the catch-up days and, by hand, today, ascending and each once.
func foldDays(withMinutes []time.Time, today time.Time, throughToday bool) []time.Time {
	var days []time.Time
	for _, d := range withMinutes {
		days = append(days, utcDay(d))
	}
	for i := foldCatchUpDays; i >= 1; i-- {
		days = append(days, today.AddDate(0, 0, -i))
	}
	if throughToday {
		days = append(days, today)
	}
	slices.SortFunc(days, time.Time.Compare)
	return slices.CompactFunc(days, time.Time.Equal)
}

// foldFeatureDays folds days oldest first and prunes each expired day after its own fold.
func foldFeatureDays(ctx context.Context, store foldStore, now time.Time, throughToday bool) (string, error) {
	today := utcDay(now)
	withMinutes, err := store.MinuteDaysBefore(ctx, today)
	if err != nil {
		return "", err
	}
	days := foldDays(withMinutes, today, throughToday)
	expiry := today.AddDate(0, 0, -minuteRetentionDays)
	var folded, pruned int
	var rows, minutes int64
	progress := func() string {
		return fmt.Sprintf("folded %d of %d days, %d rows; pruned %d days, %d minutes", folded, len(days), rows, pruned, minutes)
	}
	for _, day := range days {
		if !timeLeft(ctx) {
			if folded == 0 {
				return progress(), errors.Join(errNoDayDone, ctx.Err())
			}
			return progress() + "; stopped at the deadline, the rest folds next night", nil
		}
		n, err := store.FoldDay(ctx, day)
		if err != nil {
			return progress(), fmt.Errorf("fold %s: %w", day.Format(time.DateOnly), err)
		}
		folded++
		rows += n
		// Every older day with minutes was folded and pruned above, so this cutoff takes this day alone.
		if day.Before(expiry) {
			n, err := store.PruneMinutes(ctx, day.AddDate(0, 0, 1))
			if err != nil {
				return progress(), fmt.Errorf("prune %s: %w", day.Format(time.DateOnly), err)
			}
			pruned++
			minutes += n
		}
	}
	result := progress()
	for _, p := range foldPrunes {
		n, err := p.run(ctx, store, today.AddDate(0, 0, -p.days))
		if err != nil {
			return result, fmt.Errorf("prune %s: %w", p.what, err)
		}
		result += fmt.Sprintf("; swept %d %s", n, p.what)
	}
	return result, nil
}

// metricsFoldJob is the fold's job body, which the cron and the admin tool share.
func metricsFoldJob(lock jobLocker, store foldStore, now func() time.Time, throughToday bool) func() {
	return func() {
		runMetricsJob(lock, jobMetricsFold, "fold", func(ctx context.Context) (string, error) {
			return foldFeatureDays(ctx, store, now(), throughToday)
		})
	}
}

// foldMetricsNow is the admin tool: it starts a fold through today, or says why not.
func foldMetricsNow() string {
	if !metricsJobsEnabled() {
		return "Metrics jobs are not enabled on this instance"
	}
	go tracked(jobMetricsFold, metricsFoldJob(ObservabilityDB.WithJobLock, ObservabilityDB, time.Now, true))()
	return "Folding metrics in the background..."
}

// rollUpStore is what the page-hit roll-up writes through.
type rollUpStore interface {
	OldestEventDay(ctx context.Context, before time.Time) (time.Time, bool, error)
	RollUpEventDay(ctx context.Context, day time.Time, labels []string) (rolled, deleted int64, err error)
}

// rollUpOldEvents rolls page hits older than the retention up into days, a day per statement, oldest first.
func rollUpOldEvents(ctx context.Context, store rollUpStore, now time.Time) (string, error) {
	cutoff := utcDay(now).AddDate(0, 0, -eventsRetentionDays)
	labels := pageLabels()
	var days int
	var rolled, deleted int64
	var last time.Time
	progress := func(rest string) string {
		return fmt.Sprintf("rolled %d days, %d day rows from %d events; %s", days, rolled, deleted, rest)
	}
	for {
		if ctx.Err() != nil {
			if days == 0 {
				return progress("none done"), errors.Join(errNoDayDone, ctx.Err())
			}
			return progress("stopped, the rest rolls next night"), nil
		}
		day, ok, err := store.OldestEventDay(ctx, cutoff)
		if err != nil {
			return progress("stopped"), err
		}
		if !ok {
			return progress("none remain"), nil
		}
		if !timeLeft(ctx) {
			if days == 0 {
				return progress("more remain"), errors.Join(errNoDayDone, ctx.Err())
			}
			return progress("more remain, rolled next night"), nil
		}
		// A day that comes back after its roll-up would loop until the deadline.
		if !last.IsZero() && !day.After(last) {
			return progress("stopped"), fmt.Errorf("roll up %s: it has rows after its roll-up", day.Format(time.DateOnly))
		}
		last = day
		r, d, err := store.RollUpEventDay(ctx, day, labels)
		if err != nil {
			return progress("stopped"), fmt.Errorf("roll up %s: %w", day.Format(time.DateOnly), err)
		}
		days++
		rolled += r
		deleted += d
	}
}
