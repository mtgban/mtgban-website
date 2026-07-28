package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// LongPrice is one row of the long prices table: a single provider's price for a
// variant (ban_id) on a day. It replaces the wide, one-column-per-provider
// PriceRow — each provider is its own row, so there is no COALESCE merge.
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

// HGetAllLong returns a single card's price history over the lookback window,
// pivoted to date -> (provider -> price). The read identity (uuid, foil, etched)
// is coarser than a ban_id, so a CTE resolves the canonical printing first:
// preferring language='' AND is_alt=false, falling back to the smallest matching
// ban_id (e.g. a Japanese-only promo). Deterministic, unlike the wide table's
// last-wins over an unordered scan (plan 17.2).
//
// Resolution and fetch are one statement (a scalar subquery over the CTE), so the
// common chart read stays a single round-trip; splitting it doubled latency
// against a remote DB. An unresolved card yields NULL, which matches no prices
// and returns an empty map.
func (c *Client) HGetAllLong(ctx context.Context, uuid string, isFoil, isEtched bool, lb Lookback) (map[string]ProviderPrices, error) {
	uuid = NormalizeUUID(uuid)
	result := make(map[string]ProviderPrices)
	rows, err := c.db.QueryContext(ctx, `
		WITH canon AS (
			SELECT ban_id FROM variants
			 WHERE mtgjson_uuid=$1 AND is_foil=$2 AND is_etched=$3
			 ORDER BY (language='' AND is_alt=false) DESC, ban_id ASC
			 LIMIT 1
		)
		SELECT date, provider, price FROM prices
		 WHERE ban_id = (SELECT ban_id FROM canon) AND date >= $4`,
		uuid, isFoil, isEtched, lb.Since())
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
// the lookback window, across every ban_id that shares (uuid, foil, etched) —
// language/alt-agnostic, matching the wide table's MIN (plan 17.2).
func (c *Client) GetEarliestDateLong(ctx context.Context, uuid string, isFoil, isEtched bool, lb Lookback) (time.Time, error) {
	uuid = NormalizeUUID(uuid)
	boundary := lb.Since()
	var earliest sql.NullTime
	err := c.db.QueryRowContext(ctx, `
		SELECT MIN(p.date)
		  FROM prices p
		  JOIN variants v ON v.ban_id = p.ban_id
		 WHERE v.mtgjson_uuid=$1 AND v.is_foil=$2 AND v.is_etched=$3 AND p.date >= $4`,
		uuid, isFoil, isEtched, boundary).Scan(&earliest)
	if err != nil || !earliest.Valid || earliest.Time.IsZero() {
		return boundary, err
	}
	return earliest.Time, nil
}

// GetAggregatePriceStatsLong returns per-card max/min/p90/count of one provider
// over rows with date >= since, keyed by (uuid, foil, etched) so callers do O(1)
// lookups while iterating a buylist/inventory. Scoped to Magic variants
// (mtgjson_uuid IS NOT NULL) so a shared provider (3/4) doesn't pull other games'
// rows (plan 17.3). price > 0 is redundant with the zero-omitting backfill but
// kept defensive.
func (c *Client) GetAggregatePriceStatsLong(ctx context.Context, provider int16, since time.Time) (map[AggregatePriceKey]AggregatePriceStats, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT v.mtgjson_uuid, v.is_foil, v.is_etched,
		       MAX(p.price)                                          AS max_price,
		       MIN(p.price)                                          AS min_price,
		       percentile_disc(0.9) WITHIN GROUP (ORDER BY p.price)  AS p90_price,
		       COUNT(*)                                              AS sample_count
		  FROM prices p
		  JOIN variants v ON v.ban_id = p.ban_id
		 WHERE p.provider = $1 AND p.date >= $2 AND p.price > 0
		   AND v.mtgjson_uuid IS NOT NULL
		 GROUP BY v.mtgjson_uuid, v.is_foil, v.is_etched`, provider, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[AggregatePriceKey]AggregatePriceStats)
	for rows.Next() {
		var key AggregatePriceKey
		var stats AggregatePriceStats
		if err := rows.Scan(&key.MtgjsonUUID, &key.IsFoil, &key.IsEtched,
			&stats.Max, &stats.Min, &stats.P90, &stats.Count); err != nil {
			return nil, err
		}
		result[key] = stats
	}
	return result, rows.Err()
}

// GetMoversLong returns the largest per-card price moves for one provider over a
// window. Anchored to the provider's own latest date (a lagging metric has no
// data on the global latest). Restricted to canonical English variants
// (language=”), so each (uuid, foil, etched, is_alt) is a single ban_id and cur
// vs prior compare the same printing (plan 17.2).
func (c *Client) GetMoversLong(ctx context.Context, provider int16, windowDays int, minPrice, minPriorPrice float64) ([]MoverRow, error) {
	var latest sql.NullTime
	if err := c.db.QueryRowContext(ctx,
		`SELECT max(date) FROM prices WHERE provider=$1`, provider).Scan(&latest); err != nil {
		return nil, err
	}
	if !latest.Valid {
		return nil, nil
	}
	target := latest.Time.AddDate(0, 0, -windowDays)

	var prior sql.NullTime
	if err := c.db.QueryRowContext(ctx,
		`SELECT max(date) FROM prices WHERE provider=$1 AND date <= $2`, provider, target).Scan(&prior); err != nil {
		return nil, err
	}
	if !prior.Valid {
		return nil, nil
	}

	q := `
		WITH cur AS (
			SELECT ban_id, price FROM prices
			 WHERE provider=$1 AND date=$2 AND price >= $4
		),
		old AS (
			SELECT ban_id, price FROM prices
			 WHERE provider=$1 AND date=$3 AND price >= $5
		)
		SELECT v.mtgjson_uuid, v.is_foil, v.is_etched, cur.price, old.price
		  FROM cur JOIN old USING (ban_id)
		  JOIN variants v ON v.ban_id = cur.ban_id
		 WHERE v.mtgjson_uuid IS NOT NULL AND v.language=''`
	rows, err := c.db.QueryContext(ctx, q, provider, latest.Time, prior.Time, minPrice, minPriorPrice)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MoverRow
	for rows.Next() {
		var m MoverRow
		if err := rows.Scan(&m.MtgjsonUUID, &m.IsFoil, &m.IsEtched, &m.Current, &m.Prior); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// dedupeLongPrices collapses rows sharing (ban_id, date, provider) to their last
// occurrence — one INSERT ... ON CONFLICT DO UPDATE errors if a key appears twice
// (mirrors dedupeTCGPriceRows).
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
func (c *Client) UpsertLongPrices(ctx context.Context, rows []LongPrice, batchSize int) (int, error) {
	if c.readOnly || len(rows) == 0 {
		return 0, nil
	}
	rows = dedupeLongPrices(rows)

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
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
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
		` ON CONFLICT (ban_id, date, provider) DO UPDATE SET price = EXCLUDED.price`
	return q, args
}

// EnsurePricePartition creates the monthly range partition of prices covering
// the given day if it does not already exist, behind the DDL advisory lock so
// concurrent creators serialize. Call it at startup and from the daily cron so a
// write never races ahead of an existing partition (plan section 13). Idempotent;
// no-op on a read-only client.
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
	if err := c.execTCGDDL(ctx, q); err != nil {
		return fmt.Errorf("timeseries: ensure price partition %s: %w", name, err)
	}
	return nil
}
