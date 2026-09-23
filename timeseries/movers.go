package timeseries

import (
	"context"
	"database/sql"
	"fmt"
)

// MoverRow is one card's price movement over the requested window.
type MoverRow struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool

	// Non-Magic rows have no mtgjson uuid; they are keyed by their
	// TCGplayer product instead (see GetMoversLong)
	TCGProductID int
	TCGSubType   string

	Current float64
	Prior   float64
}

// buildWideMoverRowsQuery pairs each card's price on the two anchor dates, in
// the legacy wide table.
//
// Both arms are MATERIALIZED, and that is the whole performance of this query.
// Referenced once each they would otherwise be inlined, leaving the planner a
// plain self-join on product_prices - where it badly underestimates how many of
// one day's cards are still priced on the other (1,578 against 25,259 measured
// on the live archive) and so picks a nested loop: one idx_uuid_date descent
// per card of the current day, 25,891 descents into a 167M-row table, 152,571
// buffers and 14.6 seconds. Materialized, each day is one idx_date range scan
// and the two meet in a hash join - 6,003 buffers and 0.33s for the same 25,259
// rows.
//
// column is hard-coded via columnForDataset, safe to interpolate.
func buildWideMoverRowsQuery(column string) string {
	return fmt.Sprintf(`
		WITH cur AS MATERIALIZED (
			SELECT mtgjson_uuid, is_foil, is_etched, is_alt, %[1]s AS p
			  FROM product_prices
			 WHERE date = $1::date AND language = '' AND %[1]s > 0 AND %[1]s >= $3
		),
		old AS MATERIALIZED (
			SELECT mtgjson_uuid, is_foil, is_etched, is_alt, %[1]s AS p
			  FROM product_prices
			 WHERE date = $2::date AND language = '' AND %[1]s > 0 AND %[1]s >= $4
		)
		SELECT cur.mtgjson_uuid, cur.is_foil, cur.is_etched, cur.p, old.p
		  FROM cur JOIN old USING (mtgjson_uuid, is_foil, is_etched, is_alt)`, column)
}

// GetMovers returns the cards that moved the most over a window, filtered
// by the floor prices given.
func (c *Client) GetMovers(ctx context.Context, datasetIndex int, windowDays int, minPrice, minPriorPrice float64) ([]MoverRow, error) {
	column := columnForDataset(datasetIndex)
	if column == "" {
		return nil, fmt.Errorf("timeseries: unknown dataset index %d", datasetIndex)
	}

	// Resolve both dates first so the join can use literal-date index equality;
	// folding the date lookups into the join degrades to a ~40x slower plan.
	// Anchor to the selected column: a lagging metric (e.g. sealed EV, filled a
	// day after singles) has no data on the global latest date.
	var latest sql.NullTime
	if err := c.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT max(date) FROM product_prices WHERE %s > 0`, column)).Scan(&latest); err != nil {
		return nil, err
	}
	if !latest.Valid {
		return nil, nil
	}
	latestStr := latest.Time.Format("2006-01-02")
	targetStr := latest.Time.AddDate(0, 0, -windowDays).Format("2006-01-02")

	var prior sql.NullTime
	if err := c.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT max(date) FROM product_prices WHERE date <= $1::date AND %s > 0`, column), targetStr).Scan(&prior); err != nil {
		return nil, err
	}
	if !prior.Valid {
		return nil, nil
	}
	priorStr := prior.Time.Format("2006-01-02")

	rows, err := c.db.QueryContext(ctx, buildWideMoverRowsQuery(column), latestStr, priorStr, minPrice, minPriorPrice)
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
