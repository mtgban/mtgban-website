package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const selectColumns = `
	date, mtgjson_uuid, is_foil, is_etched, language, is_alt,
	cardkingdom_buylist_price, tcgplayer_market_price,
	tcgplayer_low_price, cardkingdom_retail_price,
	cardmarket_low_price, cardmarket_trend_price,
	starcitygames_buylist_price, abu_buylist_price,
	coolstuffinc_buylist_price, tcgplayer_low_sealed_expected_value`

func scanRow(scanner interface{ Scan(...any) error }) (PriceRow, error) {
	var row PriceRow
	var date time.Time
	err := scanner.Scan(
		&date, &row.MtgjsonUUID, &row.IsFoil, &row.IsEtched, &row.Language, &row.IsAlt,
		&row.CardkingdomBuylistPrice, &row.TcgplayerMarketPrice,
		&row.TcgplayerLowPrice, &row.CardkingdomRetailPrice,
		&row.CardmarketLowPrice, &row.CardmarketTrendPrice,
		&row.StarcitygamesBuylistPrice, &row.AbuBuylistPrice,
		&row.CoolstuffincBuylistPrice, &row.TcgplayerLowSealedExpectedValue,
	)
	if err != nil {
		return PriceRow{}, err
	}
	row.Date = date.Format("2006-01-02")
	return row, nil
}

func scanRows(rows interface {
	Next() bool
	Err() error
	Scan(...any) error
}, scanner func(interface{ Scan(...any) error }) (PriceRow, error)) ([]PriceRow, error) {
	var result []PriceRow
	for rows.Next() {
		row, err := scanner(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// GetPriceHistory returns all price rows for a given UUID, foil status, and language,
// ordered by date descending.
func (c *Client) GetPriceHistory(ctx context.Context, uuid string, isFoil bool, isEtched bool, language string) ([]PriceRow, error) {
	uuid = NormalizeUUID(uuid)
	language = *NormalizeLanguage(&language)
	q := `SELECT` + selectColumns + `
		FROM product_prices
		WHERE mtgjson_uuid = $1 AND is_foil = $2 AND is_etched = $3 AND language = $4
		ORDER BY date DESC`
	rows, err := c.db.QueryContext(ctx, q, uuid, isFoil, isEtched, language)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanRow)
}

// GetPriceHistorySince returns price rows for a UUID, foil status, and language
// on or after the given date.
func (c *Client) GetPriceHistorySince(ctx context.Context, uuid string, isFoil bool, isEtched bool, language *string, since time.Time) ([]PriceRow, error) {
	uuid = NormalizeUUID(uuid)
	language = NormalizeLanguage(language)
	var q string
	var args []any
	if language != nil {
		q = `SELECT` + selectColumns + `
			FROM product_prices
			WHERE mtgjson_uuid = $1 AND is_foil = $2 AND is_etched = $3 AND language = $4 AND date >= $5
			ORDER BY date DESC`
		args = []any{uuid, isFoil, isEtched, *language, since}
	} else {
		q = `SELECT` + selectColumns + `
			FROM product_prices
			WHERE mtgjson_uuid = $1 AND is_foil = $2 AND is_etched = $3 AND date >= $4
			ORDER BY date DESC`
		args = []any{uuid, isFoil, isEtched, since}
	}
	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanRow)
}

// GetPriceHistoryFor is a convenience wrapper around GetPriceHistorySince
// using a Lookback period instead of an explicit time.
func (c *Client) GetPriceHistoryFor(ctx context.Context, uuid string, isFoil bool, isEtched bool, language *string, lb Lookback) ([]PriceRow, error) {
	return c.GetPriceHistorySince(ctx, uuid, isFoil, isEtched, language, lb.Since())
}

// HGetAll returns all price rows for a card keyed by date, scoped by the
// given Lookback window. Language may be nil to match any language.
func (c *Client) HGetAll(ctx context.Context, cardID string, isFoil bool, isEtched bool, language *string, lb Lookback) (map[string]PriceRow, error) {
	priceRows, err := c.GetPriceHistoryFor(ctx, cardID, isFoil, isEtched, language, lb)
	if err != nil {
		return nil, err
	}
	result := make(map[string]PriceRow, len(priceRows))
	for _, row := range priceRows {
		result[row.Date] = row
	}
	return result, nil
}

// UpsertRow inserts or updates a full price row. On conflict it merges
// non-nil price columns with COALESCE so that a single UUID's prices can
// be built up across multiple scrapers without overwriting earlier values.
func (c *Client) UpsertRow(ctx context.Context, row PriceRow) error {
	if c.readOnly {
		return nil
	}
	row.MtgjsonUUID = NormalizeUUID(row.MtgjsonUUID)
	row.Language = NormalizeLanguage(row.Language)
	const q = `
		INSERT INTO product_prices (
			date, mtgjson_uuid, is_foil, is_etched, language, is_alt,
			cardkingdom_buylist_price, tcgplayer_market_price,
			tcgplayer_low_price, cardkingdom_retail_price,
			cardmarket_low_price, cardmarket_trend_price,
			starcitygames_buylist_price, abu_buylist_price,
			coolstuffinc_buylist_price, tcgplayer_low_sealed_expected_value
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (date, mtgjson_uuid, is_foil, is_etched, language, is_alt) DO UPDATE SET
			cardkingdom_buylist_price         = COALESCE(EXCLUDED.cardkingdom_buylist_price,         product_prices.cardkingdom_buylist_price),
			tcgplayer_market_price            = COALESCE(EXCLUDED.tcgplayer_market_price,            product_prices.tcgplayer_market_price),
			tcgplayer_low_price               = COALESCE(EXCLUDED.tcgplayer_low_price,               product_prices.tcgplayer_low_price),
			cardkingdom_retail_price          = COALESCE(EXCLUDED.cardkingdom_retail_price,          product_prices.cardkingdom_retail_price),
			cardmarket_low_price              = COALESCE(EXCLUDED.cardmarket_low_price,              product_prices.cardmarket_low_price),
			cardmarket_trend_price            = COALESCE(EXCLUDED.cardmarket_trend_price,            product_prices.cardmarket_trend_price),
			starcitygames_buylist_price       = COALESCE(EXCLUDED.starcitygames_buylist_price,       product_prices.starcitygames_buylist_price),
			abu_buylist_price                 = COALESCE(EXCLUDED.abu_buylist_price,                 product_prices.abu_buylist_price),
			coolstuffinc_buylist_price        = COALESCE(EXCLUDED.coolstuffinc_buylist_price,        product_prices.coolstuffinc_buylist_price),
			tcgplayer_low_sealed_expected_value = COALESCE(EXCLUDED.tcgplayer_low_sealed_expected_value, product_prices.tcgplayer_low_sealed_expected_value)`
	_, err := c.db.ExecContext(ctx, q,
		row.Date, row.MtgjsonUUID, row.IsFoil, row.IsEtched, row.Language, row.IsAlt,
		row.CardkingdomBuylistPrice, row.TcgplayerMarketPrice,
		row.TcgplayerLowPrice, row.CardkingdomRetailPrice,
		row.CardmarketLowPrice, row.CardmarketTrendPrice,
		row.StarcitygamesBuylistPrice, row.AbuBuylistPrice,
		row.CoolstuffincBuylistPrice, row.TcgplayerLowSealedExpectedValue,
	)
	return err
}

const colsPerRow = 16

// UpsertRows inserts or updates multiple price rows in a single statement.
// This is significantly faster than calling UpsertRow in a loop because it
// reduces the number of database round-trips. Rows are sent in batches of
// the given batchSize (capped to stay under Postgres's 65535 parameter limit).
func (c *Client) UpsertRows(ctx context.Context, rows []PriceRow, batchSize int) (int, error) {
	if c.readOnly {
		return 0, nil
	}
	if len(rows) == 0 {
		return 0, nil
	}

	maxBatch := 65535 / colsPerRow // ~4096
	if batchSize <= 0 || batchSize > maxBatch {
		batchSize = maxBatch
	}

	var totalUpserted int
	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]

		n, err := c.upsertBatch(ctx, batch)
		totalUpserted += n
		if err != nil {
			return totalUpserted, fmt.Errorf("batch starting at row %d: %w", start, err)
		}
	}
	return totalUpserted, nil
}

func (c *Client) upsertBatch(ctx context.Context, batch []PriceRow) (int, error) {
	var valueClauses []string
	args := make([]any, 0, len(batch)*colsPerRow)

	for i := range batch {
		batch[i].MtgjsonUUID = NormalizeUUID(batch[i].MtgjsonUUID)
		batch[i].Language = NormalizeLanguage(batch[i].Language)
		offset := i * colsPerRow
		valueClauses = append(valueClauses, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			offset+1, offset+2, offset+3, offset+4, offset+5, offset+6,
			offset+7, offset+8, offset+9, offset+10, offset+11, offset+12,
			offset+13, offset+14, offset+15, offset+16,
		))
		r := batch[i]
		args = append(args,
			r.Date, r.MtgjsonUUID, r.IsFoil, r.IsEtched, r.Language, r.IsAlt,
			r.CardkingdomBuylistPrice, r.TcgplayerMarketPrice,
			r.TcgplayerLowPrice, r.CardkingdomRetailPrice,
			r.CardmarketLowPrice, r.CardmarketTrendPrice,
			r.StarcitygamesBuylistPrice, r.AbuBuylistPrice,
			r.CoolstuffincBuylistPrice, r.TcgplayerLowSealedExpectedValue,
		)
	}

	q := `INSERT INTO product_prices (
			date, mtgjson_uuid, is_foil, is_etched, language, is_alt,
			cardkingdom_buylist_price, tcgplayer_market_price,
			tcgplayer_low_price, cardkingdom_retail_price,
			cardmarket_low_price, cardmarket_trend_price,
			starcitygames_buylist_price, abu_buylist_price,
			coolstuffinc_buylist_price, tcgplayer_low_sealed_expected_value
		) VALUES ` + strings.Join(valueClauses, ",") + `
		ON CONFLICT (date, mtgjson_uuid, is_foil, is_etched, language, is_alt) DO UPDATE SET
			cardkingdom_buylist_price         = COALESCE(EXCLUDED.cardkingdom_buylist_price,         product_prices.cardkingdom_buylist_price),
			tcgplayer_market_price            = COALESCE(EXCLUDED.tcgplayer_market_price,            product_prices.tcgplayer_market_price),
			tcgplayer_low_price               = COALESCE(EXCLUDED.tcgplayer_low_price,               product_prices.tcgplayer_low_price),
			cardkingdom_retail_price          = COALESCE(EXCLUDED.cardkingdom_retail_price,          product_prices.cardkingdom_retail_price),
			cardmarket_low_price              = COALESCE(EXCLUDED.cardmarket_low_price,              product_prices.cardmarket_low_price),
			cardmarket_trend_price            = COALESCE(EXCLUDED.cardmarket_trend_price,            product_prices.cardmarket_trend_price),
			starcitygames_buylist_price       = COALESCE(EXCLUDED.starcitygames_buylist_price,       product_prices.starcitygames_buylist_price),
			abu_buylist_price                 = COALESCE(EXCLUDED.abu_buylist_price,                 product_prices.abu_buylist_price),
			coolstuffinc_buylist_price        = COALESCE(EXCLUDED.coolstuffinc_buylist_price,        product_prices.coolstuffinc_buylist_price),
			tcgplayer_low_sealed_expected_value = COALESCE(EXCLUDED.tcgplayer_low_sealed_expected_value, product_prices.tcgplayer_low_sealed_expected_value)`

	res, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetEarliestDate returns the oldest date on record for a UUID and foil status,
// bounded by the given Lookback window. Returns the lookback boundary if no
// rows exist or if the earliest row is newer than the boundary.
func (c *Client) GetEarliestDate(ctx context.Context, uuid string, isFoil bool, isEtched bool, lb Lookback) (time.Time, error) {
	uuid = NormalizeUUID(uuid)
	boundary := lb.Since()
	var earliest sql.NullTime
	err := c.db.QueryRowContext(ctx,
		`SELECT MIN(date) FROM product_prices
		 WHERE mtgjson_uuid = $1 AND is_foil = $2 AND is_etched = $3 AND date >= $4`,
		uuid, isFoil, isEtched, boundary,
	).Scan(&earliest)
	if err != nil || !earliest.Valid || earliest.Time.IsZero() {
		return boundary, err
	}
	return earliest.Time, nil
}

// GetLatestPrice returns the most recent price row for a UUID, foil status, and language.
func (c *Client) GetLatestPrice(ctx context.Context, uuid string, isFoil bool, isEtched bool, language string) (PriceRow, error) {
	uuid = NormalizeUUID(uuid)
	language = *NormalizeLanguage(&language)
	q := `SELECT` + selectColumns + `
		FROM product_prices
		WHERE mtgjson_uuid = $1 AND is_foil = $2 AND is_etched = $3 AND language = $4
		ORDER BY date DESC LIMIT 1`
	return scanRow(c.db.QueryRowContext(ctx, q, uuid, isFoil, isEtched, language))
}
