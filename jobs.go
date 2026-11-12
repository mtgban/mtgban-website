package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/internal/jobs"
	"gopkg.in/robfig/cron.v2"
)

// The site's background jobs, as the admin dashboard and the staleness alarm
// name them.
const (
	jobStash           = "Price stash"
	jobSetAnalysis     = "Set analysis"
	jobNewspaper       = "Newspaper cache"
	jobCKSignals       = "CK signals"
	jobTCGListings     = "TCG listings"
	jobSalesVelocity   = "Sales velocity"
	jobNewspaperSales  = "Newspaper sales"
	jobOffline         = "Offline refresh"
	jobTCGCSVPrices    = "TCGCSV prices"
	jobTCGCSVProducts  = "TCGCSV products"
	jobCheckpoints     = "Checkpoints"
	jobStaleness       = "Staleness check"
	jobAlerts          = "Alert evaluation"
	jobPopular         = "Popular searches"
	jobUploadShares    = "Upload shares"
	jobPatreonSessions = "Patreon sessions"
	jobFeatureCounter  = "Feature counter"
	jobMetricsFold     = "Metrics fold"
	jobMetricsStock    = "Stored state counts"
	jobEventsRollUp    = "Events roll-up"
)

// backgroundJobs records every run of the jobs above.
var backgroundJobs = jobs.New(StartTime)

// jobHealthGrace is how long after startup the alarm leaves the jobs alone:
// the first runs report before the datastore, the prices and each other are
// all in.
const jobHealthGrace = 15 * time.Minute

// checkJobHealth announces the jobs whose health changed since the last
// check, through the staleness alarm and its memory of what it announced.
func checkJobHealth() {
	if time.Since(StartTime) < jobHealthGrace {
		return
	}
	rows := backgroundJobs.Rows()

	staleAlarmState.mu.Lock()
	defer staleAlarmState.mu.Unlock()

	var changes []staleChange
	for _, row := range rows {
		key := "job/" + row.Name
		switch classifyStaleTransition(staleAlarmState.stale[key], row.Problem != "") {
		case becameStale:
			changes = append(changes, staleChange{key: key, stale: true,
				line: fmt.Sprintf("%s: %s %s", Config().Game, row.Name, row.Problem)})
		case staleRecovered:
			changes = append(changes, staleChange{key: key, stale: false,
				line: fmt.Sprintf("%s: %s is fine again", Config().Game, row.Name)})
		}
	}
	announceStaleChanges(changes)
}

// startCrons schedules the background refreshes and starts them.
func (s *site) startCrons() {
	s.scheduleCrons().Start()
}

// scheduleCrons registers the background refreshes on a scheduler it leaves
// stopped. The library runs each job on a bare goroutine, where a panic
// would end the process: tracked reports it instead, and the job runs again
// at its next time.
func (s *site) scheduleCrons() *cron.Cron {
	c := cron.New()
	// addJob schedules fn at spec as the background job name, whose runs
	// and schedule the admin dashboard and the staleness alarm read.
	addJob := func(spec, name string, fn func()) {
		schedule, err := cron.Parse(spec)
		if err != nil {
			log.Fatalln("cron", name, err)
		}
		backgroundJobs.Schedule(name, schedule.Next)
		c.Schedule(schedule, cron.FuncJob(tracked(name, fn)))
	}

	// Take a snapshot twice a day
	addJob("0 */12 * * *", jobStash, s.stashInTimeseries)

	// Update set values with new prices
	addJob("30 */12 * * *", jobSetAnalysis, s.runSealedAnalysis)

	// Reload DB Newspaper every 3 hours, TCGplayer's copies sold a day after it.
	// refreshNewspaper tracks each as its own job.
	newspaperSchedule, err := cron.Parse(newsCron)
	if err != nil {
		log.Fatalln("cron", jobNewspaper, err)
	}
	backgroundJobs.Schedule(jobNewspaper, newspaperSchedule.Next)
	backgroundJobs.Schedule(jobSalesVelocity, newspaperSchedule.Next)
	c.Schedule(newspaperSchedule, cron.FuncJob(s.refreshNewspaper))

	// Rebuild CK's buylist signals, reloading its stock history once the
	// newspaper has a new day; until then that is one indexed MAX(date).
	// Only where the site serves CK's buylist, which is known once the
	// prices load: its runs, schedule and row start with that.
	ckSchedule, err := cron.Parse("45 * * * *")
	if err != nil {
		log.Fatalln("cron", jobCKSignals, err)
	}
	ckJob := tracked(jobCKSignals, s.refreshCKSignals)
	c.Schedule(ckSchedule, cron.FuncJob(func() {
		if !ckAvailable(s.prices()) {
			return
		}
		backgroundJobs.Schedule(jobCKSignals, ckSchedule.Next)
		ckJob()
	}))

	// Reload TCGplayer's sellers and copies per grade once the newspaper
	// finishes a scrape; until then that is one MAX(calc_date).
	addJob("50 * * * *", jobTCGListings, s.loadTCGListings)

	// Alarm on the newspaper's sales pull signing out or stopping. Every site reads
	// the same table, so one of them watches it.
	if Config().Game == DefaultGame && NewNewspaperDB != nil && !SkipNewspaper {
		addJob("10 * * * *", jobNewspaperSales, checkNewspaperSales)
	}

	// Rank the month's typed searches for the landing strip; only where the
	// observability database holds the votes.
	if ObservabilityDB != nil {
		addJob("20 * * * *", jobPopular, s.refreshPopularSearches)
	}

	// Backstop refresh; reloads normally drive this via RequestRefresh.
	c.AddFunc("20 */12 * * *", recovered("cron RequestRefresh", s.offline.RequestRefresh))

	// Pull the latest tcgcsv snapshot daily (after its ~20:00 UTC refresh).
	// The job gates on tcgcsv's last-updated, so it no-ops until there's a
	// newer snapshot regardless of the exact fire time. Registered only when
	// the ingestion service came up: without a configured game or a price DB
	// every fire would fail, posting a recurring spurious failure to the
	// notification channel. Deployments that run cmd/tcgcsvd on its own can
	// leave tcgcsv_config out here and let the crons stay unregistered; the
	// standalone process takes the same cross-process crawl lock either way.
	if TCGCSVService != nil {
		addJob("0 21 * * *", jobTCGCSVPrices, stashTCGCSVPrices)
		// Product metadata changes rarely; refresh the catalog weekly.
		addJob("0 22 * * 1", jobTCGCSVProducts, stashTCGCSVProducts)
	}

	// Refresh the chart checkpoints. Magic reads its ban markers from a
	// document published outside this project, so a B&R announcement only
	// reaches the charts when something re-reads it -- and the boot-time
	// load is not that, on a process that stays up for weeks. It doubles as
	// the retry for a boot-time load that failed: a fetch that never
	// succeeded leaves the index empty and every chart without its markers.
	addJob("15 */6 * * *", jobCheckpoints, refreshCheckpoints)

	// Expired upload shares are already misses; this reclaims their rows.
	if UserStateDB != nil {
		addJob("10 5 * * *", jobUploadShares, pruneUploadShares)
		// Reclaim the rows of sessions past their cap.
		addJob("15 5 * * *", jobPatreonSessions, prunePatreonSessions)
	}

	// Metrics jobs touch tables every site shares; one flagged instance runs them.
	if metricsJobsEnabled() {
		lock := ObservabilityDB.WithJobLock
		addJob("40 0 * * *", jobMetricsFold, metricsFoldJob(lock, ObservabilityDB, time.Now, false))
		if UserStateDB != nil {
			addJob("50 0 * * *", jobMetricsStock, func() {
				runMetricsJob(lock, jobMetricsStock, "stock", func(ctx context.Context) (string, error) {
					return countStoredState(ctx, s.stockSources(), time.Now())
				})
			})
		} else {
			log.Println("metrics jobs: stored state counts not scheduled: no user-state database")
		}
		addJob("30 4 * * *", jobEventsRollUp, func() {
			runMetricsJob(lock, jobEventsRollUp, "events_rollup", func(ctx context.Context) (string, error) {
				return rollUpOldEvents(ctx, ObservabilityDB, time.Now())
			})
		})
	} else if problem := metricsJobsProblem(); problem != "" {
		// The flag is set but nothing folds or prunes: say so rather than stay silent.
		ServerNotify("init", "metrics jobs not scheduled: "+problem)
	}

	// Alarm on a store whose retail or buylist data has gone stale (see
	// staleness.go); notifies only on the transition, so this can run
	// often without repeating itself.
	addJob("0 * * * *", jobStaleness, s.checkStaleness)
	// And on a background job turning bad, the same way.
	c.AddFunc("0 * * * *", recovered("cron checkJobHealth", checkJobHealth))

	return c
}
