package timeseries

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

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

	var totalUpserted int
	var errs []error
	for _, b := range batchBounds(len(rows), batchSize, pgMaxParams/colsPerRow) {
		n, err := c.upsertBatch(ctx, rows[b[0]:b[1]])
		totalUpserted += n
		if err != nil {
			errs = append(errs, fmt.Errorf("batch starting at row %d: %w", b[0], err))
		}
	}
	return totalUpserted, errors.Join(errs...)
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

// AggregatePriceKey identifies a card variant in an aggregate result map.
// Language and is_alt are intentionally omitted: we aggregate across them.
type AggregatePriceKey struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool
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
