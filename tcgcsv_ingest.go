package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// priceToRow maps a tcgcsv price into a tcg_prices row. The pointer price
// fields carry through unchanged so genuine nulls stay distinct from 0.
func priceToRow(date string, categoryID int, p tcgcsv.Price) timeseries.TCGPriceRow {
	return timeseries.TCGPriceRow{
		Date:           date,
		CategoryID:     categoryID,
		ProductID:      p.ProductID,
		SubTypeName:    p.SubTypeName,
		LowPrice:       p.LowPrice,
		MidPrice:       p.MidPrice,
		HighPrice:      p.HighPrice,
		MarketPrice:    p.MarketPrice,
		DirectLowPrice: p.DirectLowPrice,
	}
}

// ensureTCGPartitions makes sure tcg_prices has a dedicated partition for every
// configured game's category before any upsert. tcg_prices is LIST-partitioned
// by category_id (games never share rows), so each game needs its own partition;
// without one, that game's rows route to the catch-all default partition instead
// of a per-game partition. EnsureTCGSchema already pre-creates partitions for the
// known TCGplayer categories, so this is a no-op for them and mainly covers a
// configured category not yet listed in the schema. Call it after EnsureTCGSchema,
// before ingesting.
func ensureTCGPartitions(ctx context.Context) error {
	for _, g := range Config.TCGCSVConfig.Games {
		if err := PricesArchiveDB.EnsureTCGCategoryPartition(ctx, g.CategoryID); err != nil {
			return err
		}
	}
	return nil
}

// tcgcsvClient builds a client from the configured registry, or an error if
// ingestion isn't configured.
func tcgcsvClient() (*tcgcsv.Client, error) {
	if Config.TCGCSVConfig == nil || len(Config.TCGCSVConfig.Games) == 0 {
		return nil, errors.New("tcgcsv: no tcgcsv_config games configured")
	}
	if PricesArchiveDB == nil {
		return nil, errors.New("tcgcsv: no price database configured")
	}
	return tcgcsv.NewClient(*Config.TCGCSVConfig), nil
}

// runTCGCSVBackfill parses the optional from/to date strings (defaulting to the
// archive epoch through today) and runs the backfill. Invoked by the
// -tcgcsv-backfill maintenance flag.
func runTCGCSVBackfill(ctx context.Context, fromStr, toStr string, force bool) error {
	from := tcgcsv.ArchiveEpoch
	explicitFrom := fromStr != ""
	if explicitFrom {
		d, err := time.Parse("2006-01-02", fromStr)
		if err != nil {
			return fmt.Errorf("tcgcsv: bad -tcgcsv-from %q: %w", fromStr, err)
		}
		from = d
	}
	to := time.Now().UTC().Truncate(24 * time.Hour)
	if toStr != "" {
		d, err := time.Parse("2006-01-02", toStr)
		if err != nil {
			return fmt.Errorf("tcgcsv: bad -tcgcsv-to %q: %w", toStr, err)
		}
		to = d
	}
	if from.Before(tcgcsv.ArchiveEpoch) {
		from = tcgcsv.ArchiveEpoch
	}
	// The resume cursor (per-category MAX(date) high-water mark) auto-advances the
	// default, no-argument backfill so re-runs are cheap. An explicit start date
	// or -tcgcsv-force means "fetch this whole range", so bypass the cursor —
	// otherwise a range aimed below the high-water mark (e.g. to fill a gap left
	// by an earlier daily ingest) would be silently skipped. The upsert is
	// idempotent, so re-covering already-stored days just overwrites them in place.
	resume := !explicitFrom && !force
	return backfillTCGCSV(ctx, from, to, resume)
}

// backfillTCGCSV fills tcg_prices from tcgcsv's daily archives for every
// configured game, one day at a time. When resume is set it skips a day for a
// category once that category already has data on or after it (the default
// backfill's per-category high-water mark); when resume is false it fetches
// every day in [from, to]. Archives are downloaded only for days that at least
// one category still needs, so resumed re-runs are cheap.
func backfillTCGCSV(ctx context.Context, from, to time.Time, resume bool) error {
	client, err := tcgcsvClient()
	if err != nil {
		return err
	}
	if PricesArchiveDB.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := tcgcsv.CheckArchiveTooling(); err != nil {
		return err
	}
	if err := PricesArchiveDB.EnsureTCGSchema(ctx); err != nil {
		return err
	}
	if err := ensureTCGPartitions(ctx); err != nil {
		return err
	}

	// Resume cursor: the newest date already stored per category. Consulted only
	// when resuming; an explicit range or force fetches every day in [from, to].
	latest := make(map[int]time.Time)
	if resume {
		for _, g := range Config.TCGCSVConfig.Games {
			d, ok, err := PricesArchiveDB.GetTCGLatestDate(ctx, g.CategoryID)
			if err != nil {
				return fmt.Errorf("tcgcsv: latest date for category %d: %w", g.CategoryID, err)
			}
			if ok {
				latest[g.CategoryID] = d
			}
		}
	}

	log.Printf("tcgcsv backfill: %s..%s across %d game(s), resume=%v",
		from.Format("2006-01-02"), to.Format("2006-01-02"), len(Config.TCGCSVConfig.Games), resume)

	var totalRows, daysWithData, daysEmpty, daysFailed int
	for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
		// Which categories still need this day?
		need := make(map[int]bool)
		for _, g := range Config.TCGCSVConfig.Games {
			if !resume || day.After(latest[g.CategoryID]) {
				need[g.CategoryID] = true
			}
		}
		if len(need) == 0 {
			continue
		}

		byCat, ok, err := client.FetchPriceArchive(ctx, day, need)
		if err != nil {
			// A single bad or unreachable archive shouldn't halt a multi-year
			// backfill; log it, count it, and move on. The day can be retried
			// with -tcgcsv-force later.
			daysFailed++
			log.Printf("tcgcsv backfill %s: skipped: %v", day.Format("2006-01-02"), err)
			continue
		}
		if !ok {
			continue // no archive published for that day (HTTP 404)
		}

		dateStr := day.Format("2006-01-02")
		var rows []timeseries.TCGPriceRow
		for cat, prices := range byCat {
			for _, p := range prices {
				rows = append(rows, priceToRow(dateStr, cat, p))
			}
		}
		if len(rows) == 0 {
			// The archive existed and extracted cleanly but held no rows for the
			// wanted categories. Expected for days before a game launched, but
			// also the signature of a broken extraction (e.g. a 7z variant that
			// silently unpacks nothing). Track it so an all-empty run is caught
			// below instead of being reported as a clean success.
			daysEmpty++
			continue
		}

		n, err := PricesArchiveDB.UpsertTCGPrices(ctx, rows, 0)
		if err != nil {
			return fmt.Errorf("tcgcsv backfill upsert %s: %w", dateStr, err)
		}
		totalRows += n
		daysWithData++
		log.Printf("tcgcsv backfill %s: %d rows (%d categories)", dateStr, n, len(byCat))
	}

	log.Printf("tcgcsv backfill complete: %d rows over %d days (%d empty, %d failed)",
		totalRows, daysWithData, daysEmpty, daysFailed)
	if daysFailed > 0 {
		return fmt.Errorf("tcgcsv backfill: %d day(s) failed; re-run with -tcgcsv-force to retry them", daysFailed)
	}
	// Fetching archives but storing nothing anywhere is not a real "complete":
	// it is almost always broken extraction tooling or a category filter that
	// never matches, not a range that genuinely predates every configured game.
	// Fail loudly rather than exit 0 on silent data loss.
	if daysWithData == 0 && daysEmpty > 0 {
		return fmt.Errorf("tcgcsv backfill: fetched %d archive(s) but extracted 0 rows; check the 7z tooling and configured categories", daysEmpty)
	}
	return nil
}

// tcgcsvStashing gates concurrent runs of the daily ingest (cron + admin
// button), mirroring stashInTimeseries.
var tcgcsvStashing atomic.Bool

// IsTCGCSVStashing reports whether a daily TCGCSV ingest is currently running.
func IsTCGCSVStashing() bool { return tcgcsvStashing.Load() }

// tcgcsvCrawlLockKey coordinates tcgcsv crawls across server instances. The
// daily/weekly crons are registered in every process, and the per-process
// atomic guards above can't see other instances, so without this every instance
// would crawl tcgcsv.com at once, N times the request volume against a service
// whose etiquette is one full sync per 24h. Only the instance that holds this
// Postgres advisory lock crawls; the rest skip.
const tcgcsvCrawlLockKey = 0x7463675f_63726177 // "tcg_craw"

// withTCGCSVCrawlLock runs fn only if this instance can take the shared
// cross-instance crawl lock, so concurrent instances don't all hit tcgcsv.com.
// A read-only instance can't ingest, so it skips without taking the lock (else
// it could win the lock and starve the writable instance). With no price DB
// there is nothing to coordinate on, so fn runs and surfaces its own error.
func withTCGCSVCrawlLock(job string, fn func()) {
	if PricesArchiveDB == nil {
		fn()
		return
	}
	if PricesArchiveDB.ReadOnly() {
		log.Printf("%s: price database is read-only, skipping", job)
		return
	}
	acquired, release, err := PricesArchiveDB.TryAdvisoryLock(context.Background(), tcgcsvCrawlLockKey)
	if err != nil {
		log.Printf("%s: could not acquire crawl lock: %v", job, err)
		return
	}
	if !acquired {
		log.Printf("%s: another instance holds the tcgcsv crawl lock, skipping", job)
		return
	}
	defer release()
	fn()
}

// stashTCGCSVPrices pulls tcgcsv's current snapshot for every configured game
// into tcg_prices. It is the cron/admin entry point: only one run proceeds at a
// time, and it no-ops when the current snapshot is already stored.
func stashTCGCSVPrices() {
	if !tcgcsvStashing.CompareAndSwap(false, true) {
		log.Println("stashTCGCSVPrices: another ingest is already running, skipping")
		return
	}
	defer tcgcsvStashing.Store(false)

	withTCGCSVCrawlLock("stashTCGCSVPrices", func() {
		if err := ingestTCGCSVLatest(context.Background()); err != nil {
			log.Println("tcgcsv daily ingest:", err)
			ServerNotify("tcgcsv", fmt.Sprintf("daily ingest error: %s", err))
		}
	})
}

// ingestTCGCSVLatest fetches tcgcsv's current prices for every configured game
// and upserts them under the snapshot's date. It gates on tcgcsv's last-updated
// timestamp so the full catalog is pulled at most once per new snapshot (per
// the once-per-24h etiquette); a category already holding that date is skipped.
// The row date is taken from last-updated so a live pull and the eventual
// archive for the same snapshot land on the same date.
func ingestTCGCSVLatest(ctx context.Context) error {
	client, err := tcgcsvClient()
	if err != nil {
		return err
	}
	if PricesArchiveDB.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := PricesArchiveDB.EnsureTCGSchema(ctx); err != nil {
		return err
	}
	if err := ensureTCGPartitions(ctx); err != nil {
		return err
	}

	updated, err := client.LastUpdated(ctx)
	if err != nil {
		return fmt.Errorf("tcgcsv: last-updated: %w", err)
	}
	snapshot := updated.UTC().Truncate(24 * time.Hour)
	dateStr := snapshot.Format("2006-01-02")

	// Ingest each game independently: one game's failure (a flaky endpoint, a bad
	// group) is logged and collected, not fatal, so the remaining games still get
	// pulled. A game is all-or-nothing — its rows land in a single upsert only
	// after every group fetched cleanly — so a failed game writes nothing and its
	// freshness cursor doesn't advance, leaving it safe to retry next run.
	var totalRows int
	var errs []error
	games := Config.TCGCSVConfig.Games
	for _, g := range games {
		n, err := ingestTCGCSVGame(ctx, client, g.CategoryID, snapshot, dateStr)
		if err != nil {
			log.Printf("tcgcsv daily %s: category %d failed: %v", dateStr, g.CategoryID, err)
			errs = append(errs, fmt.Errorf("category %d: %w", g.CategoryID, err))
			continue
		}
		totalRows += n
	}

	if totalRows > 0 {
		ServerNotify("tcgcsv", fmt.Sprintf("daily ingest %s: %d rows", dateStr, totalRows))
	}
	if len(errs) > 0 {
		log.Printf("tcgcsv daily ingest %s: %d rows, %d of %d game(s) failed",
			dateStr, totalRows, len(errs), len(games))
		return fmt.Errorf("tcgcsv daily ingest: %d of %d game(s) failed: %w",
			len(errs), len(games), errors.Join(errs...))
	}
	log.Printf("tcgcsv daily ingest complete: %d rows for %s", totalRows, dateStr)
	return nil
}

// ingestTCGCSVGame pulls one game's current snapshot and upserts it under
// dateStr. It returns the number of rows written, which is 0 when the category
// already holds the snapshot date (the freshness gate) or the game reports no
// prices. All of a game's rows are written in one upsert, so a mid-fetch failure
// leaves the category untouched and safe to retry.
func ingestTCGCSVGame(ctx context.Context, client *tcgcsv.Client, categoryID int, snapshot time.Time, dateStr string) (int, error) {
	latest, ok, err := PricesArchiveDB.GetTCGLatestDate(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("latest date: %w", err)
	}
	if ok && !snapshot.After(latest) {
		log.Printf("tcgcsv daily %s: category %d already current", dateStr, categoryID)
		return 0, nil
	}

	groups, err := client.Groups(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("groups: %w", err)
	}
	var rows []timeseries.TCGPriceRow
	for _, grp := range groups {
		prices, err := client.Prices(ctx, categoryID, grp.GroupID)
		if err != nil {
			return 0, fmt.Errorf("prices for group %d: %w", grp.GroupID, err)
		}
		for _, p := range prices {
			rows = append(rows, priceToRow(dateStr, categoryID, p))
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}

	n, err := PricesArchiveDB.UpsertTCGPrices(ctx, rows, 0)
	if err != nil {
		return 0, fmt.Errorf("upsert: %w", err)
	}
	log.Printf("tcgcsv daily %s: category %d, %d rows (%d groups)", dateStr, categoryID, n, len(groups))
	return n, nil
}
