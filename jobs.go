package main

import (
	"fmt"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/internal/jobs"
	"gopkg.in/robfig/cron.v2"
)

// The site's background jobs, as the admin dashboard and the staleness alarm
// name them.
const (
	jobStash          = "Price stash"
	jobSetAnalysis    = "Set analysis"
	jobNewspaper      = "Newspaper cache"
	jobCKSignals      = "CK signals"
	jobTCGListings    = "TCG listings"
	jobOffline        = "Offline refresh"
	jobTCGCSVPrices   = "TCGCSV prices"
	jobTCGCSVProducts = "TCGCSV products"
	jobCheckpoints    = "Checkpoints"
	jobStaleness      = "Staleness check"
	jobAlerts         = "Alert evaluation"
	jobPopular        = "Popular searches"
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

// startCrons schedules the background refreshes. The library runs each job
// on a bare goroutine, where a panic would end the process: tracked reports
// it instead, and the job runs again at its next time.
func (s *site) startCrons() {
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

	// Reload DB Newspaper every 3 hours
	addJob("33 */3 * * *", jobNewspaper, s.cacheNewspaper)

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
		if !ckAvailable() {
			return
		}
		backgroundJobs.Schedule(jobCKSignals, ckSchedule.Next)
		ckJob()
	}))

	// Reload TCGplayer's sellers and copies per grade once the newspaper
	// finishes a scrape; until then that is one MAX(calc_date).
	addJob("50 * * * *", jobTCGListings, s.loadTCGListings)

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

	// Alarm on a store whose retail or buylist data has gone stale (see
	// staleness.go); notifies only on the transition, so this can run
	// often without repeating itself.
	addJob("0 * * * *", jobStaleness, checkStaleness)
	// And on a background job turning bad, the same way.
	c.AddFunc("0 * * * *", recovered("cron checkJobHealth", checkJobHealth))

	c.Start()
}
