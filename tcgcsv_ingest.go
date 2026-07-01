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
	if fromStr != "" {
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
	return backfillTCGCSV(ctx, from, to, force)
}

// backfillTCGCSV fills tcg_prices from tcgcsv's daily archives for every
// configured game, one day at a time. It resumes from where each category left
// off: unless force is set, a day is skipped for a category once that category
// already has data on or after it. Archives are downloaded only for days that
// at least one category still needs, so re-runs are cheap.
func backfillTCGCSV(ctx context.Context, from, to time.Time, force bool) error {
	client, err := tcgcsvClient()
	if err != nil {
		return err
	}
	if err := PricesArchiveDB.EnsureTCGSchema(ctx); err != nil {
		return err
	}

	// Resume cursor: the newest date already stored per category.
	latest := make(map[int]time.Time)
	for _, g := range Config.TCGCSVConfig.Games {
		if force {
			continue
		}
		d, ok, err := PricesArchiveDB.GetTCGLatestDate(ctx, g.CategoryID)
		if err != nil {
			return fmt.Errorf("tcgcsv: latest date for category %d: %w", g.CategoryID, err)
		}
		if ok {
			latest[g.CategoryID] = d
		}
	}

	log.Printf("tcgcsv backfill: %s..%s across %d game(s), force=%v",
		from.Format("2006-01-02"), to.Format("2006-01-02"), len(Config.TCGCSVConfig.Games), force)

	var totalRows, daysWithData int
	for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
		// Which categories still need this day?
		need := make(map[int]bool)
		for _, g := range Config.TCGCSVConfig.Games {
			if force || day.After(latest[g.CategoryID]) {
				need[g.CategoryID] = true
			}
		}
		if len(need) == 0 {
			continue
		}

		byCat, ok, err := client.FetchPriceArchive(ctx, day, need)
		if err != nil {
			return fmt.Errorf("tcgcsv backfill %s: %w", day.Format("2006-01-02"), err)
		}
		if !ok {
			continue // no archive published for that day
		}

		dateStr := day.Format("2006-01-02")
		var rows []timeseries.TCGPriceRow
		for cat, prices := range byCat {
			for _, p := range prices {
				rows = append(rows, priceToRow(dateStr, cat, p))
			}
		}
		if len(rows) == 0 {
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

	log.Printf("tcgcsv backfill complete: %d rows over %d days", totalRows, daysWithData)
	return nil
}

// tcgcsvStashing gates concurrent runs of the daily ingest (cron + admin
// button), mirroring stashInTimeseries.
var tcgcsvStashing atomic.Bool

// IsTCGCSVStashing reports whether a daily TCGCSV ingest is currently running.
func IsTCGCSVStashing() bool { return tcgcsvStashing.Load() }

// stashTCGCSVPrices pulls tcgcsv's current snapshot for every configured game
// into tcg_prices. It is the cron/admin entry point: only one run proceeds at a
// time, and it no-ops when the current snapshot is already stored.
func stashTCGCSVPrices() {
	if !tcgcsvStashing.CompareAndSwap(false, true) {
		log.Println("stashTCGCSVPrices: another ingest is already running, skipping")
		return
	}
	defer tcgcsvStashing.Store(false)

	if err := ingestTCGCSVLatest(context.Background()); err != nil {
		log.Println("tcgcsv daily ingest:", err)
		ServerNotify("tcgcsv", fmt.Sprintf("daily ingest error: %s", err))
	}
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
	if err := PricesArchiveDB.EnsureTCGSchema(ctx); err != nil {
		return err
	}

	updated, err := client.LastUpdated(ctx)
	if err != nil {
		return fmt.Errorf("tcgcsv: last-updated: %w", err)
	}
	snapshot := updated.UTC().Truncate(24 * time.Hour)
	dateStr := snapshot.Format("2006-01-02")

	var totalRows int
	for _, g := range Config.TCGCSVConfig.Games {
		latest, ok, err := PricesArchiveDB.GetTCGLatestDate(ctx, g.CategoryID)
		if err != nil {
			return fmt.Errorf("tcgcsv: latest date for category %d: %w", g.CategoryID, err)
		}
		if ok && !snapshot.After(latest) {
			log.Printf("tcgcsv daily %s: category %d already current", dateStr, g.CategoryID)
			continue
		}

		groups, err := client.Groups(ctx, g.CategoryID)
		if err != nil {
			return fmt.Errorf("tcgcsv: groups for category %d: %w", g.CategoryID, err)
		}
		var rows []timeseries.TCGPriceRow
		for _, grp := range groups {
			prices, err := client.Prices(ctx, g.CategoryID, grp.GroupID)
			if err != nil {
				return fmt.Errorf("tcgcsv: prices for %d/%d: %w", g.CategoryID, grp.GroupID, err)
			}
			for _, p := range prices {
				rows = append(rows, priceToRow(dateStr, g.CategoryID, p))
			}
		}
		if len(rows) == 0 {
			continue
		}

		n, err := PricesArchiveDB.UpsertTCGPrices(ctx, rows, 0)
		if err != nil {
			return fmt.Errorf("tcgcsv: upsert category %d: %w", g.CategoryID, err)
		}
		totalRows += n
		log.Printf("tcgcsv daily %s: category %d, %d rows (%d groups)", dateStr, g.CategoryID, n, len(groups))
	}

	if totalRows > 0 {
		ServerNotify("tcgcsv", fmt.Sprintf("daily ingest %s: %d rows", dateStr, totalRows))
	}
	log.Printf("tcgcsv daily ingest complete: %d rows for %s", totalRows, dateStr)
	return nil
}
