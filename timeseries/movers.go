package timeseries

import (
	"context"
	"database/sql"
	"fmt"
)

// MoverRow is one card's price now versus N days ago, for a single metric.
type MoverRow struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool
	Current     float64
	Prior       float64
}

// GetMovers returns, for the price column matching datasetIndex, every card
// present both in the latest daily snapshot and in the nearest snapshot on or
// before windowDays ago, with both prices > 0 and the current price >= minPrice.
// Dates are resolved first and passed as literals so Postgres uses the fast
// index-equality plan; the minPrice floor cuts the rows transferred and cached.
func (c *Client) GetMovers(ctx context.Context, datasetIndex int, windowDays int, minPrice float64) ([]MoverRow, error) {
	column := columnForDataset(datasetIndex)
	if column == "" {
		return nil, fmt.Errorf("timeseries: unknown dataset index %d", datasetIndex)
	}

	// Latest snapshot date.
	var latest sql.NullTime
	if err := c.db.QueryRowContext(ctx, `SELECT max(date) FROM product_prices`).Scan(&latest); err != nil {
		return nil, err
	}
	if !latest.Valid {
		return nil, nil
	}
	latestStr := latest.Time.Format("2006-01-02")
	targetStr := latest.Time.AddDate(0, 0, -windowDays).Format("2006-01-02")

	// Nearest snapshot on or before the target date.
	var prior sql.NullTime
	if err := c.db.QueryRowContext(ctx,
		`SELECT max(date) FROM product_prices WHERE date <= $1::date`, targetStr).Scan(&prior); err != nil {
		return nil, err
	}
	if !prior.Valid {
		return nil, nil
	}
	priorStr := prior.Time.Format("2006-01-02")

	// column comes from columnForDataset (hard-coded), safe to interpolate.
	q := fmt.Sprintf(`
		WITH cur AS (
			SELECT mtgjson_uuid, is_foil, is_etched, is_alt, %[1]s AS p
			  FROM product_prices
			 WHERE date = $1::date AND language = '' AND %[1]s > 0 AND %[1]s >= $3
		),
		old AS (
			SELECT mtgjson_uuid, is_foil, is_etched, is_alt, %[1]s AS p
			  FROM product_prices
			 WHERE date = $2::date AND language = '' AND %[1]s > 0
		)
		SELECT cur.mtgjson_uuid, cur.is_foil, cur.is_etched, cur.p, old.p
		  FROM cur JOIN old USING (mtgjson_uuid, is_foil, is_etched, is_alt)`, column)

	rows, err := c.db.QueryContext(ctx, q, latestStr, priorStr, minPrice)
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
