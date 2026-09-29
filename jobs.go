package main

import "github.com/mtgban/mtgban-website/internal/jobs"

// The site's background jobs, as the admin dashboard names them.
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
