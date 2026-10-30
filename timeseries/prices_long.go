package timeseries

import (
	"cmp"
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"
)

// LongPrice is one row of the long prices table: a single provider's price for a
// variant (ban_id) on a day.
type LongPrice struct {
	BanID    int64
	Date     string
	Provider int16
	Price    float64
}

// ProviderPrices maps a provider id to its price on one day. It is the pivoted
// shape a single-card chart consumes: one map per date, indexed by provider.
type ProviderPrices map[int16]float64

const longColsPerRow = 4

// longMaxBatch keeps a bulk upsert under Postgres's bind-parameter cap.
const longMaxBatch = pgMaxParams / longColsPerRow

// hgetAllLongQuery is the hottest read the site makes. NewClient keeps it
// prepared, and the text stays here for the fallback path (see Client.query).
const hgetAllLongQuery = `
		WITH canon AS (
			SELECT ban_id FROM variants
			 WHERE mtgjson_uuid=$1 AND is_foil=$2 AND is_etched=$3 AND is_alt=$4
			 ORDER BY (language='') DESC, ban_id ASC
			 LIMIT 1
		)
		SELECT date, provider, price FROM prices
		 WHERE ban_id = (SELECT ban_id FROM canon) AND date >= $5`

// HGetAllLong returns a single card's price history over the lookback window,
// pivoted to date -> (provider -> price). The read identity (uuid, foil, etched,
// alt) is coarser than a ban_id, so a CTE resolves the canonical printing first:
// preferring language=”, falling back to the smallest matching ban_id (e.g. a
// Japanese-only promo). Deterministic, unlike the wide table's
// last-wins over an unordered scan (plan 17.2).
//
// Resolution and fetch are one statement (a scalar subquery over the CTE), so the
// common chart read stays a single round-trip; splitting it doubled latency
// against a remote DB. An unresolved card yields NULL, which matches no prices
// and returns an empty map.
func (c *Client) HGetAllLong(ctx context.Context, uuid string, isFoil, isEtched, isAlt bool, lb Lookback) (map[string]ProviderPrices, error) {
	uuid = NormalizeUUID(uuid)
	result := make(map[string]ProviderPrices)
	rows, err := c.query(ctx, c.stmtHGetAllLong, hgetAllLongQuery, uuid, isFoil, isEtched, isAlt, lb.Since())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d time.Time
		var provider int16
		var price float64
		if err := rows.Scan(&d, &provider, &price); err != nil {
			return nil, err
		}
		day := d.Format("2006-01-02")
		pp := result[day]
		if pp == nil {
			pp = ProviderPrices{}
			result[day] = pp
		}
		pp[provider] = price
	}
	return result, rows.Err()
}

const hgetAllByBanIDQuery = `
		SELECT date, provider, price FROM prices
		 WHERE ban_id=$1 AND date >= $2`

// HGetAllByBanID returns one exact variant's price history over the lookback
// window, pivoted to date -> (provider -> price). Unlike HGetAllLong it does no
// canonical resolution: the caller already holds the precise ban_id (a ban: id,
// or a resolved TCGplayer product), so it charts that printing exactly, including
// a specific language/finish/alt or a non-Magic sub-type.
func (c *Client) HGetAllByBanID(ctx context.Context, banID int64, lb Lookback) (map[string]ProviderPrices, error) {
	result := make(map[string]ProviderPrices)
	rows, err := c.query(ctx, c.stmtHGetAllByBanID, hgetAllByBanIDQuery, banID, lb.Since())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d time.Time
		var provider int16
		var price float64
		if err := rows.Scan(&d, &provider, &price); err != nil {
			return nil, err
		}
		day := d.Format("2006-01-02")
		pp := result[day]
		if pp == nil {
			pp = ProviderPrices{}
			result[day] = pp
		}
		pp[provider] = price
	}
	return result, rows.Err()
}

// GetEarliestDateLong returns the oldest on-record date for a card, bounded by
// the lookback window, across every ban_id that shares (uuid, foil, etched,
// alt) — language-agnostic, matching the wide table's MIN (plan 17.2).
func (c *Client) GetEarliestDateLong(ctx context.Context, uuid string, isFoil, isEtched, isAlt bool, lb Lookback) (time.Time, error) {
	uuid = NormalizeUUID(uuid)
	boundary := lb.Since()
	var earliest sql.NullTime
	err := c.db.QueryRowContext(ctx, `
		SELECT MIN(p.date)
		  FROM prices p
		  JOIN variants v ON v.ban_id = p.ban_id
		 WHERE v.mtgjson_uuid=$1 AND v.is_foil=$2 AND v.is_etched=$3 AND v.is_alt=$4 AND p.date >= $5`,
		uuid, isFoil, isEtched, isAlt, boundary).Scan(&earliest)
	if err != nil || !earliest.Valid || earliest.Time.IsZero() {
		return boundary, err
	}
	return earliest.Time, nil
}

// GetEarliestDateByBanID returns the oldest on-record date for one exact variant,
// bounded by the lookback window (the ban_id counterpart of GetEarliestDateLong).
func (c *Client) GetEarliestDateByBanID(ctx context.Context, banID int64, lb Lookback) (time.Time, error) {
	boundary := lb.Since()
	var earliest sql.NullTime
	err := c.db.QueryRowContext(ctx,
		`SELECT MIN(date) FROM prices WHERE ban_id=$1 AND date >= $2`, banID, boundary).Scan(&earliest)
	if err != nil || !earliest.Valid || earliest.Time.IsZero() {
		return boundary, err
	}
	return earliest.Time, nil
}

// AggregatePriceKey identifies a card variant in an aggregate result map.
// Language is intentionally omitted: we aggregate across it. IsAlt is kept,
// since the Alternate Fourth Edition copy shares its original's uuid.
type AggregatePriceKey struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool
	IsAlt       bool
}

// AggregatePriceStats holds per-card summary statistics of one price column
// over a date window: max, min, discrete 90th percentile, and the count of
// rows that contributed to them. Computed from rows where the column is
// strictly positive, so Count is the number of buying days. PriorMax is the
// max over the window's days before the caller's cutoff, 0 when there are
// none, so a price above everything before today tells apart from a tie.
type AggregatePriceStats struct {
	Max      float64
	Min      float64
	P90      float64
	Count    int64
	PriorMax float64
}

// GetAggregatePriceStatsLong returns per-card max/min/p90/count of one provider
// over rows with date >= since, and PriorMax over those before cutoff, keyed by
// (uuid, foil, etched, alt) so callers do O(1)
// lookups while iterating a buylist/inventory. Scoped to Magic variants
// (mtgjson_uuid IS NOT NULL) so a shared provider (3/4) doesn't pull other games'
// rows (plan 17.3). price > 0 is redundant with the zero-omitting backfill but
// kept defensive.
func (c *Client) GetAggregatePriceStatsLong(ctx context.Context, provider int16, since, cutoff time.Time) (map[AggregatePriceKey]AggregatePriceStats, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT v.mtgjson_uuid, v.is_foil, v.is_etched, v.is_alt,
		       MAX(p.price)                                          AS max_price,
		       MIN(p.price)                                          AS min_price,
		       percentile_disc(0.9) WITHIN GROUP (ORDER BY p.price)  AS p90_price,
		       COUNT(*)                                              AS sample_count,
		       COALESCE(MAX(p.price) FILTER (WHERE p.date < $3), 0)  AS prior_max
		  FROM prices p
		  JOIN variants v ON v.ban_id = p.ban_id
		 WHERE p.provider = $1 AND p.date >= $2 AND p.price > 0
		   AND v.mtgjson_uuid IS NOT NULL
		 GROUP BY v.mtgjson_uuid, v.is_foil, v.is_etched, v.is_alt`, provider, since, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[AggregatePriceKey]AggregatePriceStats)
	for rows.Next() {
		var key AggregatePriceKey
		var stats AggregatePriceStats
		err := rows.Scan(&key.MtgjsonUUID, &key.IsFoil, &key.IsEtched, &key.IsAlt,
			&stats.Max, &stats.Min, &stats.P90, &stats.Count, &stats.PriorMax)
		if err != nil {
			return nil, err
		}
		result[key] = stats
	}
	return result, rows.Err()
}

// CategoryMagic is TCGplayer's own category id for Magic. Magic rows are keyed
// by mtgjson uuid rather than by TCGplayer product, so this doubles as the
// discriminator between the two identities a mover row can carry.
const CategoryMagic = 1

// moverScope renders the game predicate over an aliased `v` of variants, and
// the arguments it needs, numbered from next. It is one statement per game
// rather than one statement carrying both: a predicate the planner can read as
// a constant is what lets the anchor queries below stop at the first row they
// find, and a `($1 AND ...) OR (NOT $1 AND ...)` cannot be read that way.
//
// CategoryMagic selects the Magic rows, keyed by mtgjson uuid and restricted to
// canonical English variants (empty language) that are not an Alternate Fourth
// Edition copy (is_alt, which shares its original's uuid), so each (uuid, foil,
// etched) is a single ban_id and cur vs prior compare the same printing (plan
// 17.2). Any other category selects that TCGplayer category's rows, which have
// no mtgjson uuid and are keyed by their product + sub-type - already one
// ban_id per identity.
func moverScope(tcgCategory, next int) (string, []any) {
	if tcgCategory == CategoryMagic {
		return "v.mtgjson_uuid IS NOT NULL AND v.language='' AND NOT v.is_alt", nil
	}
	return fmt.Sprintf("v.mtgjson_uuid IS NULL AND v.tcgp_category_id = $%d", next), []any{tcgCategory}
}

// priceDatesGame renders, over an aliased `v` of variants, the game price_dates
// files a row under and the rows it files at all: exactly the rows moverScope
// selects for some game. A Magic day holding only foreign-language or
// Alternate Fourth Edition rows would otherwise anchor the screener on a day
// its rows query finds nothing on, and a TCGplayer row under category 1 would
// share Magic's key.
func priceDatesGame() (game, scope string) {
	magic, _ := moverScope(CategoryMagic, 0)
	return fmt.Sprintf("coalesce(v.tcgp_category_id, %d)", CategoryMagic),
		fmt.Sprintf("(%s) OR (v.mtgjson_uuid IS NULL AND v.tcgp_category_id <> %d)", magic, CategoryMagic)
}

func recordPriceDatesQuery() string {
	game, scope := priceDatesGame()
	return `
		INSERT INTO price_dates (provider, category, date)
		SELECT DISTINCT $1::smallint, ` + game + `, $2::date
		  FROM variants v
		 WHERE v.ban_id = ANY($3::bigint[]) AND (` + scope + `)
		ON CONFLICT DO NOTHING`
}

// recordPriceDates files the days these rows give each game under each
// provider, in the transaction that writes them. A snapshot covers one or two
// days, so it is a handful of statements, each sending only its ban_ids. They
// run in a fixed order, so two writers filing the same days wait on each other
// instead of deadlocking.
func recordPriceDates(ctx context.Context, tx *sql.Tx, rows []LongPrice) error {
	type day struct {
		provider int16
		date     string
	}
	banIDs := map[day][]int64{}
	for _, r := range rows {
		d := day{r.Provider, r.Date}
		banIDs[d] = append(banIDs[d], r.BanID)
	}
	days := slices.SortedFunc(maps.Keys(banIDs), func(a, b day) int {
		return cmp.Or(cmp.Compare(a.provider, b.provider), strings.Compare(a.date, b.date))
	})
	query := recordPriceDatesQuery()
	for _, d := range days {
		if _, err := tx.ExecContext(ctx, query, d.provider, d.date, pq.Array(banIDs[d])); err != nil {
			return err
		}
	}
	return nil
}

// LatestIngestDate returns the day every tcgcsv provider has reached for a
// category, the least advanced provider's newest day; ok is false when it has
// none. A site's stash files today under providers 3 and 4 twice a day, which
// cannot advance 5 to 7. A provider that stops appearing for a category makes
// it re-ingest nightly until that day expires, which is idempotent.
func (c *Client) LatestIngestDate(ctx context.Context, categoryID int) (time.Time, bool, error) {
	ids := make([]int64, len(TCGCSVProviders))
	for i, p := range TCGCSVProviders {
		ids[i] = int64(p)
	}
	var newest sql.NullTime
	err := c.db.QueryRowContext(ctx, `
		SELECT min(m) FROM (
			SELECT max(date) AS m FROM price_dates
			 WHERE category = $1 AND provider = ANY($2)
			 GROUP BY provider) x`,
		categoryID, pq.Array(ids)).Scan(&newest)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("timeseries: latest ingest date: %w", err)
	}
	return newest.Time, newest.Valid, nil
}

// ExpirePriceDates drops the days in price_dates older than the screener can
// ask for: its longest window is a year, and a month more keeps that window for
// a game whose newest day lags. No-op on a read-only client.
func (c *Client) ExpirePriceDates(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	_, err := c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE date < current_date - interval '13 months'`)
	return err
}

// moverAnchor returns the newest date this game has under this provider, at or
// before the given bound, from price_dates.
//
// The anchor is per game, not per provider: one provider carries every game's
// prices, written by producers on unrelated schedules - the per-site snapshot
// stash for Magic, the TCGplayer archive ingest for the others - so a
// provider's newest date routinely belongs to a game other than the one being
// asked about. Finding the game's own newest date in prices means walking past
// every newer row of every other game, and through the provider's whole
// history when the game has none at or before the bound.
func (c *Client) moverAnchor(ctx context.Context, provider int16, tcgCategory int, before *time.Time) (sql.NullTime, error) {
	query := `SELECT max(date) FROM price_dates WHERE provider=$1 AND category=$2`
	args := []any{provider, tcgCategory}
	if before != nil {
		query += ` AND date <= $3`
		args = append(args, *before)
	}
	var date sql.NullTime
	err := c.db.QueryRowContext(ctx, query, args...).Scan(&date)
	return date, err
}

// buildMoverRowsQuery pairs each of this game's prices on the two anchor dates.
//
// Both arms are MATERIALIZED, and that is this query's performance: left
// inlined, the planner sees a self-join on prices, underestimates how many of
// one day's cards are still priced on the other, and picks a nested loop that
// descends into a 42GB index once per card. cur happens to materialize anyway
// under the multiple-reference rule - it is named again by the variants join -
// but old is referenced once, so PG12+ inlines it and that is all the nested
// loop needs. Saying it on both arms means neither depends on how many times
// the query below happens to name them.
func buildMoverRowsQuery(provider int16, tcgCategory int, latest, prior time.Time, minPrice, minPriorPrice float64) (string, []any) {
	args := []any{provider, latest, prior, minPrice, minPriorPrice}
	scope, scopeArgs := moverScope(tcgCategory, len(args)+1)
	args = append(args, scopeArgs...)

	return `
		WITH cur AS MATERIALIZED (
			SELECT ban_id, price FROM prices
			 WHERE provider=$1 AND date=$2 AND price >= $4
		),
		old AS MATERIALIZED (
			SELECT ban_id, price FROM prices
			 WHERE provider=$1 AND date=$3 AND price >= $5
		)
		SELECT v.mtgjson_uuid, v.is_foil, v.is_etched,
		       v.tcgp_product_id, v.tcgp_sub_type,
		       cur.price, old.price
		  FROM cur JOIN old USING (ban_id)
		  JOIN variants v ON v.ban_id = cur.ban_id
		 WHERE ` + scope, args
}

// GetMoversLong returns the largest per-card price moves for one provider over
// a window, for the game picked by tcgCategory. It is anchored to that game's
// own latest date for that provider: a lagging metric has no data on the global
// latest date, and a game has no data on another game's latest date. See
// moverScope for the scoping the three queries share.
func (c *Client) GetMoversLong(ctx context.Context, provider int16, windowDays int, minPrice, minPriorPrice float64, tcgCategory int) ([]MoverRow, error) {
	latest, err := c.moverAnchor(ctx, provider, tcgCategory, nil)
	if err != nil {
		return nil, err
	}
	if !latest.Valid {
		return nil, nil
	}
	target := latest.Time.AddDate(0, 0, -windowDays)

	prior, err := c.moverAnchor(ctx, provider, tcgCategory, &target)
	if err != nil {
		return nil, err
	}
	if !prior.Valid {
		return nil, nil
	}

	rowsQuery, rowsArgs := buildMoverRowsQuery(provider, tcgCategory, latest.Time, prior.Time, minPrice, minPriorPrice)
	rows, err := c.db.QueryContext(ctx, rowsQuery, rowsArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MoverRow
	for rows.Next() {
		var m MoverRow
		var uuid, subType sql.NullString
		var isFoil, isEtched sql.NullBool
		var productID sql.NullInt64
		err = rows.Scan(&uuid, &isFoil, &isEtched, &productID, &subType, &m.Current, &m.Prior)
		if err != nil {
			return nil, err
		}
		m.MtgjsonUUID = uuid.String
		m.IsFoil = isFoil.Bool
		m.IsEtched = isEtched.Bool
		m.TCGProductID = int(productID.Int64)
		m.TCGSubType = subType.String
		result = append(result, m)
	}
	return result, rows.Err()
}

// dedupeLongPrices collapses rows sharing (ban_id, date, provider) to their last
// occurrence; one INSERT ... ON CONFLICT DO UPDATE errors if a key appears twice
// at once.
func dedupeLongPrices(rows []LongPrice) []LongPrice {
	type key struct {
		banID    int64
		date     string
		provider int16
	}
	seen := make(map[key]int, len(rows))
	out := make([]LongPrice, 0, len(rows))
	for _, r := range rows {
		k := key{r.BanID, r.Date, r.Provider}
		if idx, ok := seen[k]; ok {
			out[idx] = r
			continue
		}
		seen[k] = len(out)
		out = append(out, r)
	}
	return out
}

// UpsertLongPrices inserts/overwrites long price rows in one transaction,
// batched under the parameter cap. Each provider is its own row, so this is a
// plain per-row overwrite — no COALESCE merge. No-op on a read-only client.
//
// A row already holding the same price is left alone, so the count returned is
// the rows inserted or changed. Every snapshot re-covers days it already wrote,
// and rewriting an unchanged price would still leave a dead row version and a
// new entry in each index.
//
// The days written are filed in price_dates in the same transaction, so the
// screener's anchors never name a day the prices do not hold.
func (c *Client) UpsertLongPrices(ctx context.Context, rows []LongPrice, batchSize int) (int, error) {
	if c.readOnly || len(rows) == 0 {
		return 0, nil
	}
	rows = dedupeLongPrices(rows)

	months := partitionMonths(rows)
	for i, m := range months {
		err := c.EnsurePricePartition(ctx, m)
		if err != nil && i == len(months)-1 {
			// No row in this batch lands in the month after, so its failure must not stop the write.
			log.Printf("timeseries: ensure next month's partition: %v", err)
		} else if err != nil {
			return 0, fmt.Errorf("partitions: %w", err)
		}
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() // no-op after Commit

	var total int
	for _, b := range batchBounds(len(rows), batchSize, longMaxBatch) {
		q, args := buildLongUpsertQuery(rows[b[0]:b[1]])
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return 0, fmt.Errorf("batch starting at row %d: %w", b[0], err)
		}
		n, _ := res.RowsAffected()
		total += int(n)
	}
	if err := recordPriceDates(ctx, tx, rows); err != nil {
		return 0, fmt.Errorf("price dates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// partitionMonths returns the sorted first-of-month (UTC) of every month a
// row falls in, plus the month after the latest. Unparseable dates are skipped.
func partitionMonths(rows []LongPrice) []time.Time {
	seen := map[time.Time]bool{}
	for _, r := range rows {
		d, err := time.Parse("2006-01-02", r.Date)
		if err != nil {
			continue
		}
		seen[time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC)] = true
	}
	if len(seen) == 0 {
		return nil
	}
	months := slices.SortedFunc(maps.Keys(seen), time.Time.Compare)
	return append(months, months[len(months)-1].AddDate(0, 1, 0))
}

// StrayPriceRows counts the rows that reached prices_default.
func (c *Client) StrayPriceRows(ctx context.Context) (int64, error) {
	var n int64
	err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM prices_default`).Scan(&n)
	return n, err
}

func buildLongUpsertQuery(batch []LongPrice) (string, []any) {
	valueClauses := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*longColsPerRow)
	for i := range batch {
		offset := i * longColsPerRow
		valueClauses = append(valueClauses, fmt.Sprintf("($%d,$%d,$%d,$%d)",
			offset+1, offset+2, offset+3, offset+4))
		r := batch[i]
		args = append(args, r.BanID, r.Date, r.Provider, r.Price)
	}
	q := `INSERT INTO prices (ban_id, date, provider, price) VALUES ` +
		strings.Join(valueClauses, ",") +
		` ON CONFLICT (ban_id, date, provider) DO UPDATE SET price = EXCLUDED.price` +
		` WHERE prices.price IS DISTINCT FROM EXCLUDED.price`
	return q, args
}

//go:embed schema_price_dates.sql
var priceDatesSchemaSQL string

// EnsurePriceDatesSchema creates price_dates if it does not exist. Every
// UpsertLongPrices writes to it, so call it at startup with the partitions.
// Idempotent; no-op on a read-only client.
func (c *Client) EnsurePriceDatesSchema(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	if err := c.execDDL(ctx, priceDatesSchemaSQL); err != nil {
		return fmt.Errorf("timeseries: ensure price_dates: %w", err)
	}
	return nil
}

// EnsurePricePartition creates the monthly range partition of prices covering
// the given day if it does not already exist, behind the DDL advisory lock so
// concurrent creators serialize. UpsertLongPrices runs it before every write;
// the startup calls stay as a courtesy. Idempotent; no-op on a read-only client.
func (c *Client) EnsurePricePartition(ctx context.Context, day time.Time) error {
	if c.readOnly {
		return nil
	}
	start := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	name := fmt.Sprintf("prices_%04d_%02d", start.Year(), start.Month())
	// name/bounds derive from a calendar month, safe to interpolate.
	q := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF prices FOR VALUES FROM ('%s') TO ('%s')`,
		name, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if err := c.execDDL(ctx, q); err != nil {
		return fmt.Errorf("timeseries: ensure price partition %s: %w", name, err)
	}
	return nil
}
