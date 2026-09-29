package main

import (
	"fmt"
	"time"

	"github.com/mtgban/mtgban-website/internal/jobs"
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
				line: fmt.Sprintf("%s: %s %s", Config.Game, row.Name, row.Problem)})
		case staleRecovered:
			changes = append(changes, staleChange{key: key, stale: false,
				line: fmt.Sprintf("%s: %s is fine again", Config.Game, row.Name)})
		}
	}
	announceStaleChanges(changes)
}
