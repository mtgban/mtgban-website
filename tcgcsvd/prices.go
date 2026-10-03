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

// writeLongForm writes non-Magic price rows into the long prices table,
// resolving each (category, product, sub-type) to a ban_id, filing the new
// ones under timeseries.TCGBanID, and emitting one
// LongPrice per set price column (> 0, zeros omitted like the backfill). The
// charts read only this table, so callers write it before the legacy
// tcgplayer_nonmagic_product_prices upsert, whose dates gate the next run.
func (s *Service) writeLongForm(ctx context.Context, rows []timeseries.TCGPriceRow) (int, error) {
	variants := make([]timeseries.TCGVariant, len(rows))
	for i, r := range rows {
		variants[i] = timeseries.TCGVariant{CategoryID: r.CategoryID, ProductID: r.ProductID, SubType: r.SubTypeName}
	}
	// One batch files every new product the day brought, rather than a
	// round-trip per row the warm cache missed.
	banIDs, err := s.store.EnsureTCGVariants(ctx, variants)
	if err != nil {
		return 0, fmt.Errorf("resolve ban_ids: %w", err)
	}

	longRows := make([]timeseries.LongPrice, 0, len(rows)*3)
	for i, r := range rows {
		banID, ok := banIDs[variants[i]]
		if !ok {
			log.Printf("tcgcsv long-form: no ban_id for %+v", variants[i])
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
//
// Only the archive can reach a past day, and tcgcsv has not served it since
// September 2026, so a range wholly in the past currently fails whatever is
// asked for here. See docs/tcgcsv-archive-withdrawal.md.
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

// Backfill fills tcg_prices over the requested range, from tcgcsv's daily
// archives where they are served and from the current snapshot where they are
// not. Invoked by the -tcgcsv-backfill server flag and by cmd/tcgcsvd.
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
	// An inverted range walks zero days, which would otherwise be reported as a
	// clean backfill that stored nothing -- the same silent success the checks
	// below exist to prevent.
	if from.After(to) {
		return fmt.Errorf("tcgcsv: backfill range %s..%s is empty; the start date is after the end date",
			from.Format("2006-01-02"), to.Format("2006-01-02"))
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

// backfill fills tcg_prices for the given games over [from, to]. It prefers
// tcgcsv's daily archives, which are the only thing that can reach a past day,
// and falls back to the current snapshot when tcgcsv isn't serving them -- the
// live per-group price files it now asks callers to read instead.
func (s *Service) backfill(ctx context.Context, games []tcgcsv.GameConfig, from, to time.Time, resume bool) error {
	if s.store.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := s.store.EnsureTCGSchema(ctx); err != nil {
		return err
	}
	if err := s.ensurePartitions(ctx, games); err != nil {
		return err
	}

	err := s.backfillFromArchive(ctx, games, from, to, resume)
	if !errors.Is(err, tcgcsv.ErrArchiveUnavailable) {
		return err
	}
	log.Printf("tcgcsv backfill: %v", err)
	// !resume is the operator having named a range or passed -force, which is
	// what re-fetching a date already stored means now that the snapshot's own
	// date is the only one reachable.
	return s.backfillFromSnapshot(ctx, games, from, to, !resume)
}

// backfillFromSnapshot is what a backfill can still do once tcgcsv withdraws
// the archive: store the one day it does publish. That is only worth doing when
// the snapshot's own date falls inside the requested range -- writing today's
// prices because someone asked for last July would be a surprise, and the range
// they asked for is genuinely gone, so say so instead.
func (s *Service) backfillFromSnapshot(ctx context.Context, games []tcgcsv.GameConfig, from, to time.Time, force bool) error {
	snapshot, dateStr, err := s.snapshotDate(ctx)
	if err != nil {
		return err
	}
	fromStr, toStr := from.Format("2006-01-02"), to.Format("2006-01-02")
	if snapshot.Before(from) || snapshot.After(to) {
		return fmt.Errorf("tcgcsv backfill: the price archive is no longer served, and the only prices tcgcsv still publishes are the %s snapshot, outside the requested %s..%s; that range cannot be recovered",
			dateStr, fromStr, toStr)
	}

	// Under the crawl lock, unlike the archive walk this replaces. That walk is
	// exempt because it runs for hours and holding the lock across it would
	// starve the daily pull; this is one pass over every group of every game --
	// the same ~1,600 requests the daily job makes -- and letting it run beside
	// that job is exactly what the lock exists to prevent. Losing the lock means
	// another process is already pulling this snapshot, so the run is a no-op
	// that says so and exits 0.
	var rows int
	var crawled bool
	err = s.WithCrawlLock(ctx, "tcgcsv backfill snapshot", func() error {
		var ierr error
		crawled = true
		// force means the operator named a range or passed -force, so re-fetch the
		// snapshot even for a category already holding it: it is the one day still
		// reachable, and the freshness gate would otherwise turn that run into a
		// no-op. A plain resumed backfill keeps the gate, so a repeat run costs the
		// last-updated request instead of re-crawling every group of every game.
		rows, _, ierr = s.ingestSnapshot(ctx, games, snapshot, dateStr, force)
		return ierr
	})
	if err != nil {
		// Some games may have stored their rows before another failed; say so,
		// since the error alone reads as if nothing landed.
		if rows > 0 {
			log.Printf("tcgcsv backfill: stored %d row(s) for the %s snapshot before failing", rows, dateStr)
		}
		return fmt.Errorf("tcgcsv backfill from the %s snapshot: %w", dateStr, err)
	}
	if !crawled {
		// The lock went to another process, which is already pulling this same
		// snapshot. Nothing was even attempted here, so don't claim the games are
		// current -- WithCrawlLock has already logged who to blame.
		log.Printf("tcgcsv backfill: the price archive is no longer served and this run yielded the crawl lock; %s..%s stays missing",
			fromStr, toStr)
		return nil
	}
	if rows == 0 {
		// Nothing was written -- every game already holds the snapshot date -- so
		// there is no news here, and a range that is out of reach was already
		// reported by the run that did store it.
		log.Printf("tcgcsv backfill: the price archive is no longer served and every game already holds the %s snapshot; %s..%s stays missing",
			dateStr, fromStr, toStr)
		return nil
	}
	// Worth waking someone for: a backfill that was meant to close a hole has
	// stored one day and left the rest of the range permanently missing.
	s.notifyf("backfill: the price archive is no longer served; stored the %s snapshot (%d rows), but %s..%s cannot be recovered",
		dateStr, rows, fromStr, toStr)
	log.Printf("tcgcsv backfill: stored the %s snapshot, %d rows; %s..%s stays missing while the archive is withdrawn",
		dateStr, rows, fromStr, toStr)
	return nil
}

// backfillFromArchive fills tcg_prices from tcgcsv's daily archives for each of
// the given games, one day at a time. When resume is set it skips a day for a
// category once that category already has data on or after it (the default
// backfill's per-category high-water mark); when resume is false it fetches
// every day in [from, to]. Archives are downloaded only for days that at least
// one category still needs, so resumed re-runs are cheap and a game added to the
// config today pulls its whole history while the games already current skip
// every day.
func (s *Service) backfillFromArchive(ctx context.Context, games []tcgcsv.GameConfig, from, to time.Time, resume bool) error {
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

	// settledBefore is the first day whose archive tcgcsv has had time to publish:
	// the refresh runs at ~20:05 UTC, so the last two days of a range can be
	// legitimately unpublished. A day missing at or before this is not ordinary
	// lag, and the "the whole archive is gone" verdict below needs one.
	settledBefore := to.AddDate(0, 0, -1)
	var totalRows, daysNeeded, daysWithData, daysEmpty, daysMissing, daysMissingSettled, daysFailed int
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
		daysNeeded++

		byCat, ok, err := s.client.FetchPriceArchive(ctx, day, need)
		if errors.Is(err, tcgcsv.ErrArchiveUnavailable) || errors.Is(err, tcgcsv.ErrArchiveTooling) {
			// Neither says anything about this one day: the archive isn't being
			// served, or nothing on this box can unpack it. Every remaining day
			// would answer the same, so stop instead of asking hundreds more
			// times, and let the caller decide what to do about it. Report what
			// the run did get first -- the refusal currently lands on the first
			// day, but one arriving mid-range would otherwise bury it.
			if daysWithData > 0 {
				log.Printf("tcgcsv backfill stopped at %s: %d rows over %d days before that",
					day.Format("2006-01-02"), totalRows, daysWithData)
			}
			return err
		}
		if err != nil {
			// A single bad or unreachable archive shouldn't halt a multi-year
			// backfill; log it, count it, and move on. The day can be retried
			// with -force later.
			daysFailed++
			log.Printf("tcgcsv backfill %s: skipped: %v", day.Format("2006-01-02"), err)
			continue
		}
		if !ok {
			daysMissing++
			if day.Before(settledBefore) {
				daysMissingSettled++
			}
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

		if s.longForm {
			_, err := s.writeLongForm(ctx, rows)
			if err != nil {
				return fmt.Errorf("tcgcsv backfill long-form %s: %w", dateStr, err)
			}
		}
		n, err := s.store.UpsertTCGPrices(ctx, rows, 0)
		if err != nil {
			return fmt.Errorf("tcgcsv backfill upsert %s: %w", dateStr, err)
		}
		totalRows += n
		daysWithData++
		log.Printf("tcgcsv backfill %s: %d rows (%d categories)", dateStr, n, len(byCat))
	}

	log.Printf("tcgcsv backfill complete: %d rows over %d days (%d empty, %d missing, %d failed)",
		totalRows, daysWithData, daysEmpty, daysMissing, daysFailed)
	if daysFailed > 0 {
		return fmt.Errorf("tcgcsv backfill: %d day(s) failed; re-run with -force to retry them", daysFailed)
	}
	// Every day answering "no archive published" is how the archive disappearing
	// would look if it ever 404s rather than 403s, and the loop above would
	// otherwise report that as a clean run over zero days. Unpublished days at
	// the tail of a range are ordinary -- today's archive lands after tcgcsv's
	// evening refresh -- so the range must be entirely missing *and* include a
	// settled day, or asking for the last day or two before the refresh would
	// read as a withdrawn archive and trigger the snapshot fallback's full crawl.
	if daysWithData == 0 && daysMissing == daysNeeded && daysMissingSettled > 0 {
		return fmt.Errorf("%w: all %d requested day(s) answered 404", tcgcsv.ErrArchiveUnavailable, daysMissing)
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
//
// Pass a context that outlives a request but not the process — the caller's
// shutdown context — so a stop ends the ingest where it is instead of leaving
// it running into the exit.
func (s *Service) StashPrices(ctx context.Context) {
	if !s.pricesStashing.CompareAndSwap(false, true) {
		log.Println("tcgcsv StashPrices: another ingest is already running, skipping")
		return
	}
	defer s.pricesStashing.Store(false)

	err := s.WithCrawlLock(ctx, "tcgcsv StashPrices", func() error {
		return s.IngestLatest(ctx)
	})
	if errors.Is(err, context.Canceled) {
		// The process is going down and the run stopped with it. That is the
		// shutdown working, not something to wake anyone for.
		log.Println("tcgcsv daily ingest: stopped by shutdown")
		return
	}
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

	snapshot, dateStr, err := s.snapshotDate(ctx)
	if err != nil {
		return err
	}

	totalRows, failed, err := s.ingestSnapshot(ctx, s.games, snapshot, dateStr, false)
	if totalRows > 0 {
		s.notifyf("daily ingest %s: %d rows", dateStr, totalRows)
	}
	if err != nil {
		log.Printf("tcgcsv daily ingest %s: %d rows, %d of %d game(s) failed",
			dateStr, totalRows, failed, len(s.games))
		return fmt.Errorf("tcgcsv daily ingest: %w", err)
	}
	log.Printf("tcgcsv daily ingest complete: %d rows for %s", totalRows, dateStr)
	return nil
}

// snapshotDate asks tcgcsv when it last refreshed and returns the date its rows
// are keyed by, both as a time and as the string the table stores.
//
// tcgcsv names each day's archive (prices-YYYY-MM-DD) for the UTC date of this
// same last-updated stamp, verified against the live service: last-updated
// 2026-07-05T20:05Z is served by prices-2026-07-05, and the refresh runs at a
// steady ~20:05 UTC, well clear of midnight. Truncating to the UTC day therefore
// yields the archive's filename date, so a live pull and a later backfill of the
// same snapshot key the same row instead of recording it under two adjacent
// dates.
func (s *Service) snapshotDate(ctx context.Context) (time.Time, string, error) {
	updated, err := s.client.LastUpdated(ctx)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("tcgcsv: last-updated: %w", err)
	}
	snapshot := updated.UTC().Truncate(24 * time.Hour)
	return snapshot, snapshot.Format("2006-01-02"), nil
}

// ingestSnapshot pulls tcgcsv's current per-group prices for each game and
// upserts them under the snapshot's date, returning the rows written and how
// many games failed.
//
// Each game is ingested independently: one game's failure (a flaky endpoint, a
// bad group) is logged and collected, not fatal, so the remaining games still
// get pulled. A game is all-or-nothing — its rows land in a single upsert only
// after every group fetched cleanly — so a failed game writes nothing and its
// freshness cursor doesn't advance, leaving it safe to retry next run. force
// ignores that cursor, which is what a backfill onto the snapshot's own date
// needs.
func (s *Service) ingestSnapshot(ctx context.Context, games []tcgcsv.GameConfig, snapshot time.Time, dateStr string, force bool) (rows, failed int, err error) {
	var errs []error
	for _, g := range games {
		n, gerr := s.ingestGame(ctx, g.CategoryID, snapshot, dateStr, force)
		if gerr != nil {
			log.Printf("tcgcsv snapshot %s: category %d failed: %v", dateStr, g.CategoryID, gerr)
			errs = append(errs, fmt.Errorf("category %d: %w", g.CategoryID, gerr))
			continue
		}
		rows += n
	}
	if len(errs) > 0 {
		return rows, len(errs), fmt.Errorf("%d of %d game(s) failed: %w",
			len(errs), len(games), errors.Join(errs...))
	}
	return rows, 0, nil
}

// ingestGame pulls one game's current snapshot and upserts it under dateStr. It
// returns the number of rows written, which is 0 when the category already holds
// the snapshot date (the freshness gate, which force skips) or the game reports
// no prices. All of a game's rows are written in one upsert, so a mid-fetch
// failure leaves the category untouched and safe to retry.
func (s *Service) ingestGame(ctx context.Context, categoryID int, snapshot time.Time, dateStr string, force bool) (int, error) {
	if !force {
		latest, ok, err := s.store.GetTCGLatestDate(ctx, categoryID)
		if err != nil {
			return 0, fmt.Errorf("latest date: %w", err)
		}
		if ok && !snapshot.After(latest) {
			log.Printf("tcgcsv snapshot %s: category %d already current", dateStr, categoryID)
			return 0, nil
		}
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

	if s.longForm {
		_, err := s.writeLongForm(ctx, rows)
		if err != nil {
			return 0, fmt.Errorf("long-form: %w", err)
		}
	}
	n, err := s.store.UpsertTCGPrices(ctx, rows, 0)
	if err != nil {
		return 0, fmt.Errorf("upsert: %w", err)
	}
	log.Printf("tcgcsv snapshot %s: category %d, %d rows (%d groups)", dateStr, categoryID, n, len(groups))
	return n, nil
}
