package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/tcgcsvd"
	"github.com/mtgban/mtgban-website/timeseries"
)

// TCGCSVService ingests non-Magic prices and catalogs from tcgcsv.com. The jobs
// themselves live in the tcgcsvd package and also ship as a standalone binary
// (cmd/tcgcsvd); what stays here is the wiring that hands them this process's
// config, database and notification channel. Nil until initTCGCSVService runs,
// and nil for the lifetime of a deployment that configures no games or no price
// database.
var TCGCSVService *tcgcsvd.Service

// initTCGCSVService builds the ingestion service from the loaded config. Call
// it after openDBs. It errors when ingestion isn't configured, which is a normal
// state for a deployment that doesn't carry the non-Magic games — the caller
// decides whether that is worth logging.
func initTCGCSVService() error {
	if Config.TCGCSVConfig == nil {
		return errors.New("tcgcsv: no tcgcsv_config section")
	}
	if PricesArchiveDB == nil {
		return errors.New("tcgcsv: no price database configured")
	}
	svc, err := tcgcsvd.New(*Config.TCGCSVConfig, PricesArchiveDB,
		tcgcsvd.WithLongFormWrites(Config.TimeseriesConfig.LongFormWrites),
		tcgcsvd.WithNotifier(func(kind, message string) { ServerNotify(kind, message) }),
		tcgcsvd.WithProductReport(logTCGProductMatchReport))
	if err != nil {
		return err
	}
	TCGCSVService = svc
	return nil
}

// IsTCGCSVStashing reports whether a daily TCGCSV ingest is currently running.
func IsTCGCSVStashing() bool {
	return TCGCSVService != nil && TCGCSVService.IsStashingPrices()
}

// stashTCGCSVPrices and stashTCGCSVProducts are the cron and admin entry
// points. They are registered only when the service exists, and stay nil-safe
// so an admin button on an unconfigured deployment logs instead of panicking.
//
// Both run under ServerContext rather than a request's: the admin button starts
// the ingest in a goroutine that outlives the request that pressed it, and a
// cron fire has no request at all. What they must not outlive is the process,
// hence not context.Background().
func stashTCGCSVPrices() {
	if TCGCSVService == nil {
		log.Println("stashTCGCSVPrices: tcgcsv ingestion is not configured")
		return
	}
	TCGCSVService.StashPrices(ServerContext)
}

func stashTCGCSVProducts() {
	if TCGCSVService == nil {
		log.Println("stashTCGCSVProducts: tcgcsv ingestion is not configured")
		return
	}
	TCGCSVService.StashProducts(ServerContext)
}

// logTCGProductMatchReport reports how many synced products resolve to a loaded
// card identity via mtgmatcher's external-id map. It is meaningful only on a
// deployment whose datastore is the matching game (e.g. a Lorcana datastore for
// category 71); elsewhere it will resolve few or none, which is expected until
// the display work runs a per-game backend. It needs the loaded datastore, which
// is why it is wired in here rather than living in tcgcsvd — the standalone
// service has no datastore to match against.
func logTCGProductMatchReport(categoryID int, products []timeseries.TCGProduct) {
	var matched int
	var sampleUnmatched []string
	for _, p := range products {
		if mtgmatcher.ConvertID(mtgmatcher.IDSpaceTCGplayer, strconv.Itoa(p.ProductID)) != "" {
			matched++
		} else if len(sampleUnmatched) < 3 {
			sampleUnmatched = append(sampleUnmatched, fmt.Sprintf("%d %q", p.ProductID, p.Name))
		}
	}
	log.Printf("tcgcsv products: category %d, %d/%d resolve to a loaded card identity (unmatched sample: %v)",
		categoryID, matched, len(products), sampleUnmatched)
}
