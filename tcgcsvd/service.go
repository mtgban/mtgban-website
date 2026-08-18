package tcgcsvd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// Store is the slice of the price database the ingest jobs touch.
// *timeseries.Client implements it; the interface keeps the service testable
// and free of any dependency on how the caller built its connection pool.
type Store interface {
	ReadOnly() bool
	EnsureTCGSchema(ctx context.Context) error
	EnsureTCGProductsSchema(ctx context.Context) error
	EnsureTCGCategoryPartition(ctx context.Context, categoryID int) error
	GetTCGLatestDate(ctx context.Context, categoryID int) (time.Time, bool, error)
	UpsertTCGPrices(ctx context.Context, rows []timeseries.TCGPriceRow, batchSize int) (int, error)
	UpsertTCGProducts(ctx context.Context, products []timeseries.TCGProduct, batchSize int) (int, error)
	ResolveTCGBanID(ctx context.Context, v timeseries.TCGVariant) (int64, error)
	UpsertLongPrices(ctx context.Context, rows []timeseries.LongPrice, batchSize int) (int, error)
	TryAdvisoryLock(ctx context.Context, key int64) (acquired bool, release func(), err error)
}

// Service runs the tcgcsv ingestion jobs against one price database. Build it
// with New and share a single instance per process: the single-flight guards
// that keep two ingests from overlapping live on it.
type Service struct {
	client   *tcgcsv.Client
	store    Store
	games    []tcgcsv.GameConfig
	longForm bool
	notify   func(kind, message string)
	report   func(categoryID int, products []timeseries.TCGProduct)

	pricesStashing   atomic.Bool
	productsStashing atomic.Bool
}

// Option customizes a Service at construction.
type Option func(*Service)

// WithNotifier routes job-level successes and failures to an out-of-band
// channel (the server passes ServerNotify, which posts to Discord). Everything
// is logged either way; without a notifier the logs are the only record.
func WithNotifier(fn func(kind, message string)) Option {
	return func(s *Service) { s.notify = fn }
}

// WithLongFormWrites dual-writes each price row into the long prices table,
// resolving every (category, product, sub-type) to a ban_id. Mirrors the
// timeseries_config.long_form_writes flag; off by default.
func WithLongFormWrites(on bool) Option {
	return func(s *Service) { s.longForm = on }
}

// WithProductReport hands each synced game's catalog to fn after it is stored.
// The server uses it to report how many products resolve to a loaded card
// identity, which needs the mtgmatcher datastore the standalone binary doesn't
// have — hence a hook rather than a dependency.
func WithProductReport(fn func(categoryID int, products []timeseries.TCGProduct)) Option {
	return func(s *Service) { s.report = fn }
}

// New builds a Service for the configured games. It errors when ingestion isn't
// configured — no games, or no database — rather than standing up a service
// whose every job would fail at its first call.
func New(cfg tcgcsv.Config, store Store, opts ...Option) (*Service, error) {
	if len(cfg.Games) == 0 {
		return nil, errors.New("tcgcsv: no tcgcsv_config games configured")
	}
	if store == nil {
		return nil, errors.New("tcgcsv: no price database configured")
	}
	s := &Service{
		client: tcgcsv.NewClient(cfg),
		store:  store,
		games:  slices.Clone(cfg.Games),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Games returns the configured games, in config order.
func (s *Service) Games() []tcgcsv.GameConfig { return slices.Clone(s.games) }

// SelectGames resolves a comma-separated list of TCGplayer category ids against
// the configured registry. An empty spec means every configured game. An id
// that isn't configured is an error rather than a silent no-op run, since a typo
// would otherwise look like a clean backfill that wrote nothing.
func (s *Service) SelectGames(spec string) ([]tcgcsv.GameConfig, error) {
	if strings.TrimSpace(spec) == "" {
		return s.Games(), nil
	}
	var games []tcgcsv.GameConfig
	seen := make(map[int]bool)
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		cat, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("tcgcsv: bad category list %q: %q is not a category id", spec, field)
		}
		if seen[cat] {
			continue
		}
		idx := slices.IndexFunc(s.games, func(g tcgcsv.GameConfig) bool {
			return g.CategoryID == cat
		})
		if idx < 0 {
			var configured []string
			for _, g := range s.games {
				configured = append(configured, fmt.Sprintf("%d (%s)", g.CategoryID, g.Name))
			}
			return nil, fmt.Errorf("tcgcsv: category %d is not a configured game; configured: %s",
				cat, strings.Join(configured, ", "))
		}
		seen[cat] = true
		games = append(games, s.games[idx])
	}
	if len(games) == 0 {
		return nil, fmt.Errorf("tcgcsv: category list %q selected no games", spec)
	}
	return games, nil
}

// notifyf sends a formatted message to the configured notifier, if any.
func (s *Service) notifyf(format string, args ...any) {
	if s.notify == nil {
		return
	}
	s.notify("tcgcsv", fmt.Sprintf(format, args...))
}

// crawlLockKey coordinates tcgcsv crawls across processes. The daily/weekly
// crons are registered in every server instance, and the per-process atomics
// above can't see other processes, so without this every instance would crawl
// tcgcsv.com at once, N times the request volume against a service whose
// etiquette is one full sync per 24h. Only the process that holds this Postgres
// advisory lock crawls; the rest skip. A standalone tcgcsvd takes the same lock,
// so it and the servers stay coordinated with no extra configuration.
const crawlLockKey = 0x7463675f_63726177 // "tcg_craw"

// WithCrawlLock runs fn only if this process can take the shared crawl lock,
// and returns fn's error. A run that never happened is not a failure: when
// another process holds the lock the reason is logged and the return is nil.
// A read-only database can't ingest, so it skips without taking the lock (else
// it could win the lock and starve the writable process).
//
// Wrap the scheduled crawls in it — the daily ingest and the product sync do,
// and a standalone process should too, so it stays coordinated with a server
// whose crons are still armed. Backfill is the one exception: it is
// operator-driven and runs for hours, and holding the lock across that would
// starve the daily pull, which is the run that must not be missed.
//
// ctx covers taking the lock only; fn gets whatever context its caller closed
// over, which is normally the same one.
func (s *Service) WithCrawlLock(ctx context.Context, job string, fn func() error) error {
	if s.store.ReadOnly() {
		log.Printf("%s: price database is read-only, skipping", job)
		return nil
	}
	acquired, release, err := s.store.TryAdvisoryLock(ctx, crawlLockKey)
	if err != nil {
		log.Printf("%s: could not acquire crawl lock: %v", job, err)
		return nil
	}
	if !acquired {
		log.Printf("%s: another process holds the tcgcsv crawl lock, skipping", job)
		return nil
	}
	defer release()
	return fn()
}

// ensurePartitions makes sure tcg_prices has a dedicated partition for each
// game's category before any upsert. tcg_prices is LIST-partitioned by
// category_id (games never share rows), so each game needs its own partition;
// without one, that game's rows route to the catch-all default partition instead
// of a per-game partition. EnsureTCGSchema already pre-creates partitions for the
// known TCGplayer categories, so this is a no-op for them and mainly covers a
// configured category not yet listed in the schema. Call it after EnsureTCGSchema,
// before ingesting.
func (s *Service) ensurePartitions(ctx context.Context, games []tcgcsv.GameConfig) error {
	for _, g := range games {
		if err := s.store.EnsureTCGCategoryPartition(ctx, g.CategoryID); err != nil {
			return err
		}
	}
	return nil
}
