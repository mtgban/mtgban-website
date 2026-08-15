package tcgcsvd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// longForm dual-writes non-Magic price rows into the long prices table,
// resolving each (category, product, sub-type) to a ban_id and emitting one
// LongPrice per set price column (> 0, zeros omitted like the backfill). The
// legacy tcgplayer_nonmagic_product_prices upsert stays the source of truth
// during the dual-write window; a long-form failure is logged, not fatal.
func (s *Service) writeLongForm(ctx context.Context, rows []timeseries.TCGPriceRow) (int, error) {
	longRows := make([]timeseries.LongPrice, 0, len(rows)*3)
	for _, r := range rows {
		banID, err := s.store.ResolveTCGBanID(ctx, timeseries.TCGVariant{
			CategoryID: r.CategoryID, ProductID: r.ProductID, SubType: r.SubTypeName,
		})
		if err != nil {
			log.Println("tcgcsv long-form: resolve ban_id:", err)
			continue
		}
		for _, pc := range []struct {
			p        *float64
			provider int16
		}{
			{r.LowPrice, timeseries.ProviderTCGLow},
			{r.MarketPrice, timeseries.ProviderTCGMarket},
			{r.MidPrice, timeseries.ProviderTCGMid},
			{r.HighPrice, timeseries.ProviderTCGHigh},
			{r.DirectLowPrice, timeseries.ProviderTCGDirectLow},
		} {
			if pc.p != nil && *pc.p > 0 {
				longRows = append(longRows, timeseries.LongPrice{
					BanID: banID, Date: r.Date, Provider: pc.provider, Price: *pc.p,
				})
			}
		}
	}
	return s.store.UpsertLongPrices(ctx, longRows, 0)
}

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

// BackfillOptions is the request form of the backfill flags: the dates are
// YYYY-MM-DD strings as typed on a command line, and the zero value means
// "every configured game, from the archive epoch through today, resuming from
// each category's high-water mark".
type BackfillOptions struct {
	// From and To bound the range, inclusive. Empty From starts at the archive
	// epoch; empty To ends today (UTC).
	From, To string
	// Categories restricts the run to these TCGplayer category ids,
	// comma-separated. Empty covers every configured game.
	Categories string
	// Force re-fetches days already stored, ignoring the resume cursor.
	Force bool
}

// Backfill fills tcg_prices from tcgcsv's daily archives over the requested
// range. Invoked by the -tcgcsv-backfill server flag and by cmd/tcgcsvd.
func (s *Service) Backfill(ctx context.Context, opts BackfillOptions) error {
	games, err := s.SelectGames(opts.Categories)
	if err != nil {
		return err
	}
	from := tcgcsv.ArchiveEpoch
	explicitFrom := opts.From != ""
	if explicitFrom {
		d, err := time.Parse("2006-01-02", opts.From)
		if err != nil {
			return fmt.Errorf("tcgcsv: bad backfill start date %q: %w", opts.From, err)
		}
		from = d
	}
	to := time.Now().UTC().Truncate(24 * time.Hour)
	if opts.To != "" {
		d, err := time.Parse("2006-01-02", opts.To)
		if err != nil {
			return fmt.Errorf("tcgcsv: bad backfill end date %q: %w", opts.To, err)
		}
		to = d
	}
	if from.Before(tcgcsv.ArchiveEpoch) {
		from = tcgcsv.ArchiveEpoch
	}
	// The resume cursor (per-category MAX(date) high-water mark) auto-advances the
	// default, no-argument backfill so re-runs are cheap. An explicit start date
	// or Force means "fetch this whole range", so bypass the cursor — otherwise a
	// range aimed below the high-water mark (e.g. to fill a gap left by an earlier
	// daily ingest) would be silently skipped. The upsert is idempotent, so
	// re-covering already-stored days just overwrites them in place.
	resume := !explicitFrom && !opts.Force
	return s.backfill(ctx, games, from, to, resume)
}

// backfill fills tcg_prices from tcgcsv's daily archives for each of the given
// games, one day at a time. When resume is set it skips a day for a category
// once that category already has data on or after it (the default backfill's
// per-category high-water mark); when resume is false it fetches every day in
// [from, to]. Archives are downloaded only for days that at least one category
// still needs, so resumed re-runs are cheap and a game added to the config today
// pulls its whole history while the games already current skip every day.
func (s *Service) backfill(ctx context.Context, games []tcgcsv.GameConfig, from, to time.Time, resume bool) error {
	if s.store.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := tcgcsv.CheckArchiveTooling(); err != nil {
		return err
	}
	if err := s.store.EnsureTCGSchema(ctx); err != nil {
		return err
	}
	if err := s.ensurePartitions(ctx, games); err != nil {
		return err
	}

	// Resume cursor: the newest date already stored per category. Consulted only
	// when resuming; an explicit range or force fetches every day in [from, to].
	latest := make(map[int]time.Time)
	if resume {
		for _, g := range games {
			d, ok, err := s.store.GetTCGLatestDate(ctx, g.CategoryID)
			if err != nil {
				return fmt.Errorf("tcgcsv: latest date for category %d: %w", g.CategoryID, err)
			}
			if ok {
				latest[g.CategoryID] = d
			}
		}
	}

	log.Printf("tcgcsv backfill: %s..%s across %d game(s), resume=%v",
		from.Format("2006-01-02"), to.Format("2006-01-02"), len(games), resume)

	var totalRows, daysWithData, daysEmpty, daysFailed int
	for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
		// Which categories still need this day?
		need := make(map[int]bool)
		for _, g := range games {
			if !resume || day.After(latest[g.CategoryID]) {
				need[g.CategoryID] = true
			}
		}
		if len(need) == 0 {
			continue
		}

		byCat, ok, err := s.client.FetchPriceArchive(ctx, day, need)
		if err != nil {
			// A single bad or unreachable archive shouldn't halt a multi-year
			// backfill; log it, count it, and move on. The day can be retried
			// with -force later.
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

		n, err := s.store.UpsertTCGPrices(ctx, rows, 0)
		if err != nil {
			return fmt.Errorf("tcgcsv backfill upsert %s: %w", dateStr, err)
		}
		if s.longForm {
			if _, lerr := s.writeLongForm(ctx, rows); lerr != nil {
				log.Printf("tcgcsv backfill long-form %s: %v", dateStr, lerr)
			}
		}
		totalRows += n
		daysWithData++
		log.Printf("tcgcsv backfill %s: %d rows (%d categories)", dateStr, n, len(byCat))
	}

	log.Printf("tcgcsv backfill complete: %d rows over %d days (%d empty, %d failed)",
		totalRows, daysWithData, daysEmpty, daysFailed)
	if daysFailed > 0 {
		return fmt.Errorf("tcgcsv backfill: %d day(s) failed; re-run with -force to retry them", daysFailed)
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

// IsStashingPrices reports whether a daily price ingest is currently running in
// this process.
func (s *Service) IsStashingPrices() bool { return s.pricesStashing.Load() }

// StashPrices pulls tcgcsv's current snapshot for every configured game into
// tcg_prices. It is the cron/admin entry point: only one run proceeds at a time
// per process, only the process holding the crawl lock crawls, and it no-ops
// when the current snapshot is already stored.
func (s *Service) StashPrices() {
	if !s.pricesStashing.CompareAndSwap(false, true) {
		log.Println("tcgcsv StashPrices: another ingest is already running, skipping")
		return
	}
	defer s.pricesStashing.Store(false)

	err := s.WithCrawlLock("tcgcsv StashPrices", func() error {
		return s.IngestLatest(context.Background())
	})
	if err != nil {
		log.Println("tcgcsv daily ingest:", err)
		s.notifyf("daily ingest error: %s", err)
	}
}

// IngestLatest fetches tcgcsv's current prices for every configured game and
// upserts them under the snapshot's date. It gates on tcgcsv's last-updated
// timestamp so the full catalog is pulled at most once per new snapshot (per
// the once-per-24h etiquette); a category already holding that date is skipped.
// The row date is taken from last-updated so a live pull and the eventual
// archive for the same snapshot land on the same date.
func (s *Service) IngestLatest(ctx context.Context) error {
	if s.store.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := s.store.EnsureTCGSchema(ctx); err != nil {
		return err
	}
	if err := s.ensurePartitions(ctx, s.games); err != nil {
		return err
	}

	updated, err := s.client.LastUpdated(ctx)
	if err != nil {
		return fmt.Errorf("tcgcsv: last-updated: %w", err)
	}
	// tcgcsv names each day's archive (prices-YYYY-MM-DD) for the UTC date of
	// this same last-updated stamp, verified against the live service:
	// last-updated 2026-07-05T20:05Z is served by prices-2026-07-05, and the
	// refresh runs at a steady ~20:05 UTC, well clear of midnight. Truncating to
	// the UTC day therefore yields the archive's filename date, so a live pull
	// and a later backfill of the same snapshot key the same row instead of
	// recording it under two adjacent dates.
	snapshot := updated.UTC().Truncate(24 * time.Hour)
	dateStr := snapshot.Format("2006-01-02")

	// Ingest each game independently: one game's failure (a flaky endpoint, a bad
	// group) is logged and collected, not fatal, so the remaining games still get
	// pulled. A game is all-or-nothing — its rows land in a single upsert only
	// after every group fetched cleanly — so a failed game writes nothing and its
	// freshness cursor doesn't advance, leaving it safe to retry next run.
	var totalRows int
	var errs []error
	for _, g := range s.games {
		n, err := s.ingestGame(ctx, g.CategoryID, snapshot, dateStr)
		if err != nil {
			log.Printf("tcgcsv daily %s: category %d failed: %v", dateStr, g.CategoryID, err)
			errs = append(errs, fmt.Errorf("category %d: %w", g.CategoryID, err))
			continue
		}
		totalRows += n
	}

	if totalRows > 0 {
		s.notifyf("daily ingest %s: %d rows", dateStr, totalRows)
	}
	if len(errs) > 0 {
		log.Printf("tcgcsv daily ingest %s: %d rows, %d of %d game(s) failed",
			dateStr, totalRows, len(errs), len(s.games))
		return fmt.Errorf("tcgcsv daily ingest: %d of %d game(s) failed: %w",
			len(errs), len(s.games), errors.Join(errs...))
	}
	log.Printf("tcgcsv daily ingest complete: %d rows for %s", totalRows, dateStr)
	return nil
}

// ingestGame pulls one game's current snapshot and upserts it under dateStr. It
// returns the number of rows written, which is 0 when the category already holds
// the snapshot date (the freshness gate) or the game reports no prices. All of a
// game's rows are written in one upsert, so a mid-fetch failure leaves the
// category untouched and safe to retry.
func (s *Service) ingestGame(ctx context.Context, categoryID int, snapshot time.Time, dateStr string) (int, error) {
	latest, ok, err := s.store.GetTCGLatestDate(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("latest date: %w", err)
	}
	if ok && !snapshot.After(latest) {
		log.Printf("tcgcsv daily %s: category %d already current", dateStr, categoryID)
		return 0, nil
	}

	groups, err := s.client.Groups(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("groups: %w", err)
	}
	var rows []timeseries.TCGPriceRow
	for _, grp := range groups {
		prices, err := s.client.Prices(ctx, categoryID, grp.GroupID)
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

	n, err := s.store.UpsertTCGPrices(ctx, rows, 0)
	if err != nil {
		return 0, fmt.Errorf("upsert: %w", err)
	}
	if s.longForm {
		if _, lerr := s.writeLongForm(ctx, rows); lerr != nil {
			log.Printf("tcgcsv daily long-form category %d: %v", categoryID, lerr)
		}
	}
	log.Printf("tcgcsv daily %s: category %d, %d rows (%d groups)", dateStr, categoryID, n, len(groups))
	return n, nil
}
