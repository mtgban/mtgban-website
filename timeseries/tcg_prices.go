package timeseries

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"
)

//go:embed schema_tcg.sql
var tcgSchemaSQL string

// TCGPriceRow is a single row of the tcgplayer_nonmagic_product_prices table: one game's price for a
// TCGplayer product and printing sub-type on a given day. Unlike PriceRow,
// which is keyed by mtgjson uuid, this is keyed by TCGplayer product id so it
// can hold games (Lorcana, Pokemon, ...) whose cards have no mtgjson uuid.
//
// Price fields are *float64 so a missing value (TCGCSV reported null) stays
// distinct from a genuine 0.00.
type TCGPriceRow struct {
	Date        string `json:"date"`
	CategoryID  int    `json:"category_id"`
	ProductID   int    `json:"product_id"`
	SubTypeName string `json:"sub_type_name"`

	LowPrice       *float64 `json:"low_price"`
	MidPrice       *float64 `json:"mid_price"`
	HighPrice      *float64 `json:"high_price"`
	MarketPrice    *float64 `json:"market_price"`
	DirectLowPrice *float64 `json:"direct_low_price"`
}

// tcgColsPerRow is the number of bind parameters one row contributes to a
// bulk upsert; tcgMaxBatch keeps a batch under Postgres's 65535 parameter cap.
const (
	tcgColsPerRow = 9
	tcgMaxBatch   = 65535 / tcgColsPerRow // ~7281
)

const tcgSelectColumns = `
	date, category_id, product_id, sub_type_name,
	low_price, mid_price, high_price, market_price, direct_low_price`

// EnsureTCGSchema creates the tcgplayer_nonmagic_product_prices parent table, its default partition,
// and its indexes if they do not already exist. tcgplayer_nonmagic_product_prices is LIST-partitioned
// by category_id; this creates only the parent and the catch-all default
// partition. Call EnsureTCGCategoryPartition for each configured game to give it
// a dedicated partition. It is idempotent and a no-op on a read-only client.
// Callers that ingest into tcgplayer_nonmagic_product_prices should invoke this once at startup.
func (c *Client) EnsureTCGSchema(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	if _, err := c.db.ExecContext(ctx, tcgSchemaSQL); err != nil {
		return fmt.Errorf("timeseries: ensure tcg schema: %w", err)
	}
	return nil
}

// EnsureTCGCategoryPartition creates the LIST partition of tcgplayer_nonmagic_product_prices that holds
// a single TCGplayer category, if it does not already exist. Games never share
// rows and every query is category-scoped, so each configured game gets its own
// partition, keeping vacuum, analyze, and planner statistics per-game. It is
// idempotent and a no-op on a read-only client. Call it for a category before
// upserting that category's rows; otherwise the rows route to the default
// partition. Requires EnsureTCGSchema to have created the parent first.
func (c *Client) EnsureTCGCategoryPartition(ctx context.Context, categoryID int) error {
	if c.readOnly {
		return nil
	}
	// categoryID is a positive TCGplayer id from the trusted game config, so it
	// is safe to interpolate into the partition name and bound.
	q := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS tcgplayer_nonmagic_product_prices_cat_%d PARTITION OF tcgplayer_nonmagic_product_prices FOR VALUES IN (%d)`,
		categoryID, categoryID,
	)
	if _, err := c.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("timeseries: ensure tcg partition for category %d: %w", categoryID, err)
	}
	return nil
}

func scanTCGRow(scanner interface{ Scan(...any) error }) (TCGPriceRow, error) {
	var row TCGPriceRow
	var date time.Time
	err := scanner.Scan(
		&date, &row.CategoryID, &row.ProductID, &row.SubTypeName,
		&row.LowPrice, &row.MidPrice, &row.HighPrice, &row.MarketPrice, &row.DirectLowPrice,
	)
	if err != nil {
		return TCGPriceRow{}, err
	}
	row.Date = date.Format("2006-01-02")
	return row, nil
}

// GetTCGPriceHistory returns every stored price for a product and sub-type,
// newest first.
func (c *Client) GetTCGPriceHistory(ctx context.Context, categoryID, productID int, subTypeName string) ([]TCGPriceRow, error) {
	q := `SELECT` + tcgSelectColumns + `
		FROM tcgplayer_nonmagic_product_prices
		WHERE category_id = $1 AND product_id = $2 AND sub_type_name = $3
		ORDER BY date DESC`
	rows, err := c.db.QueryContext(ctx, q, categoryID, productID, subTypeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TCGPriceRow
	for rows.Next() {
		row, err := scanTCGRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// GetLatestTCGPrice returns the most recent stored price for a product and
// sub-type. It returns sql.ErrNoRows when the product has no history.
func (c *Client) GetLatestTCGPrice(ctx context.Context, categoryID, productID int, subTypeName string) (TCGPriceRow, error) {
	q := `SELECT` + tcgSelectColumns + `
		FROM tcgplayer_nonmagic_product_prices
		WHERE category_id = $1 AND product_id = $2 AND sub_type_name = $3
		ORDER BY date DESC LIMIT 1`
	return scanTCGRow(c.db.QueryRowContext(ctx, q, categoryID, productID, subTypeName))
}

// GetTCGEarliestDate returns the oldest date stored for a category. The bool is
// false (with a zero time) when the category has no rows yet.
func (c *Client) GetTCGEarliestDate(ctx context.Context, categoryID int) (time.Time, bool, error) {
	return c.tcgBoundaryDate(ctx, "MIN", categoryID)
}

// GetTCGLatestDate returns the newest date stored for a category. The bool is
// false (with a zero time) when the category has no rows yet. Backfill uses this
// as a resume cursor and the daily job uses it as a freshness gate.
func (c *Client) GetTCGLatestDate(ctx context.Context, categoryID int) (time.Time, bool, error) {
	return c.tcgBoundaryDate(ctx, "MAX", categoryID)
}

func (c *Client) tcgBoundaryDate(ctx context.Context, agg string, categoryID int) (time.Time, bool, error) {
	// agg is a hard-coded "MIN"/"MAX" from the two callers above; safe to interpolate.
	q := fmt.Sprintf(`SELECT %s(date) FROM tcgplayer_nonmagic_product_prices WHERE category_id = $1`, agg)
	var d sql.NullTime
	if err := c.db.QueryRowContext(ctx, q, categoryID).Scan(&d); err != nil {
		return time.Time{}, false, err
	}
	if !d.Valid {
		return time.Time{}, false, nil
	}
	return d.Time, true, nil
}

// UpsertTCGPrice inserts or overwrites a single price row.
func (c *Client) UpsertTCGPrice(ctx context.Context, row TCGPriceRow) error {
	_, err := c.UpsertTCGPrices(ctx, []TCGPriceRow{row}, 0)
	return err
}

// UpsertTCGPrices inserts or overwrites price rows, splitting them into batches
// kept under Postgres's parameter limit but committing every batch in a single
// transaction. Returns the number of rows affected. It is a no-op on a
// read-only client. Re-running the same rows overwrites in place (no
// duplicates), so backfilling a date range is idempotent.
//
// The write is all-or-nothing: a partial multi-batch commit would advance the
// per-category MAX(date) cursor that the daily ingest gates on, silently
// stranding an incomplete day that the freshness gate would then never revisit.
// Wrapping the batches in one transaction keeps a failed run safe to retry in
// full.
func (c *Client) UpsertTCGPrices(ctx context.Context, rows []TCGPriceRow, batchSize int) (int, error) {
	if c.readOnly {
		return 0, nil
	}
	if len(rows) == 0 {
		return 0, nil
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() // no-op once Commit succeeds

	var total int
	for _, b := range tcgBatchBounds(len(rows), batchSize) {
		q, args := buildTCGUpsertQuery(rows[b[0]:b[1]])
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

// clampTCGBatchSize resolves a requested batch size to a safe one: a
// non-positive or oversized request falls back to the parameter-limited max.
func clampTCGBatchSize(batchSize int) int {
	if batchSize <= 0 || batchSize > tcgMaxBatch {
		return tcgMaxBatch
	}
	return batchSize
}

// tcgBatchBounds splits total rows into contiguous [start, end) ranges, each no
// larger than the resolved batch size. Returns nil for zero rows.
func tcgBatchBounds(total, batchSize int) [][2]int {
	if total <= 0 {
		return nil
	}
	batchSize = clampTCGBatchSize(batchSize)
	var bounds [][2]int
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		bounds = append(bounds, [2]int{start, end})
	}
	return bounds
}

// buildTCGUpsertQuery builds a multi-VALUES upsert for one batch. Price columns
// are overwritten from the incoming row (not COALESCE-merged like
// product_prices): TCGCSV is the single authoritative source per
// (date, product, sub-type), so re-ingesting a day should reflect exactly what
// the archive reports.
func buildTCGUpsertQuery(batch []TCGPriceRow) (string, []any) {
	valueClauses := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*tcgColsPerRow)

	for i := range batch {
		offset := i * tcgColsPerRow
		valueClauses = append(valueClauses, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			offset+1, offset+2, offset+3, offset+4, offset+5,
			offset+6, offset+7, offset+8, offset+9,
		))
		r := batch[i]
		args = append(args,
			r.Date, r.CategoryID, r.ProductID, r.SubTypeName,
			r.LowPrice, r.MidPrice, r.HighPrice, r.MarketPrice, r.DirectLowPrice,
		)
	}

	q := `INSERT INTO tcgplayer_nonmagic_product_prices (
			date, category_id, product_id, sub_type_name,
			low_price, mid_price, high_price, market_price, direct_low_price
		) VALUES ` + strings.Join(valueClauses, ",") + `
		ON CONFLICT (date, category_id, product_id, sub_type_name) DO UPDATE SET
			low_price        = EXCLUDED.low_price,
			mid_price        = EXCLUDED.mid_price,
			high_price       = EXCLUDED.high_price,
			market_price     = EXCLUDED.market_price,
			direct_low_price = EXCLUDED.direct_low_price`
	return q, args
}
