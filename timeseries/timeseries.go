// Package timeseries keeps price history in Postgres and answers the
// chart and mover queries the site draws from it.
package timeseries

import (
	"fmt"
	"time"
)

// NormalizeUUID strips the _f, _e, and language suffixes that mtgmatcher
// appends for foil/etched/language variants, returning a clean UUID
// suitable for Postgres. A standard UUID is 36 characters; anything
// appended after that (e.g. _jpn, _ita, _alt, _f, _e) is stripped.
func NormalizeUUID(uuid string) string {
	if len(uuid) > 36 {
		uuid = uuid[:36]
	}
	return uuid
}

// NormalizeLanguage treats "English" and "" as equivalent, storing both as "".
func NormalizeLanguage(lang *string) *string {
	if lang != nil && *lang == "English" {
		empty := ""
		return &empty
	}
	return lang
}

// PriceRow represents a single row from the product_prices table.
// Each nullable price column uses *float64 so we can distinguish "no data" from zero.
type PriceRow struct {
	Date        string  `json:"date"`
	MtgjsonUUID string  `json:"mtgjson_uuid"`
	IsFoil      bool    `json:"is_foil"`
	IsEtched    bool    `json:"is_etched"`
	Language    *string `json:"language"`
	IsAlt       bool    `json:"is_alt"`

	CardkingdomBuylistPrice         *float64 `json:"cardkingdom_buylist_price"`
	TcgplayerMarketPrice            *float64 `json:"tcgplayer_market_price"`
	TcgplayerLowPrice               *float64 `json:"tcgplayer_low_price"`
	CardkingdomRetailPrice          *float64 `json:"cardkingdom_retail_price"`
	CardmarketLowPrice              *float64 `json:"cardmarket_low_price"`
	CardmarketTrendPrice            *float64 `json:"cardmarket_trend_price"`
	StarcitygamesBuylistPrice       *float64 `json:"starcitygames_buylist_price"`
	AbuBuylistPrice                 *float64 `json:"abu_buylist_price"`
	CoolstuffincBuylistPrice        *float64 `json:"coolstuffinc_buylist_price"`
	TcgplayerLowSealedExpectedValue *float64 `json:"tcgplayer_low_sealed_expected_value"`

	// Extra holds prices for datasets that have no wide column, keyed by
	// provider; the long form carries them, the wide upsert ignores them.
	Extra map[int16]float64 `json:"-"`
}

// Lookback is a number of days of history to consider.
type Lookback int

// Days returns the lookback as a day count.
func (l Lookback) Days() int {
	return int(l)
}

// Since returns the moment the lookback starts from.
func (l Lookback) Since() time.Time {
	return time.Now().AddDate(0, 0, -l.Days())
}

// column maps a dataset config index to its wide column, nil when it has none.
// PriceForDataset, SetPriceForDataset and HasWideColumn all read this one table.
func (r *PriceRow) column(index int) **float64 {
	switch index {
	case 0:
		return &r.CardkingdomRetailPrice
	case 1:
		return &r.CardkingdomBuylistPrice
	case 2:
		return &r.TcgplayerLowPrice
	case 3:
		return &r.TcgplayerMarketPrice
	case 4:
		return &r.CardmarketLowPrice
	case 5:
		return &r.CardmarketTrendPrice
	case 6:
		return &r.StarcitygamesBuylistPrice
	case 7:
		return &r.AbuBuylistPrice
	case 8:
		return &r.TcgplayerLowSealedExpectedValue
	case 9:
		return &r.CoolstuffincBuylistPrice
	default:
		return nil
	}
}

// HasWideColumn reports whether a dataset config index has a product_prices column.
func HasWideColumn(index int) bool {
	return (&PriceRow{}).column(index) != nil
}

// PriceForDataset returns the price column matching a dataset config index.
func (r PriceRow) PriceForDataset(index int) *float64 {
	if c := r.column(index); c != nil {
		return *c
	}
	return nil
}

// SetPriceForDataset sets the price column matching a dataset config index.
func (r *PriceRow) SetPriceForDataset(index int, price float64) {
	if c := r.column(index); c != nil {
		*c = &price
	}
}

// SetExtra records a price for a dataset with no wide column, keyed by provider.
func (r *PriceRow) SetExtra(provider int16, price float64) {
	if r.Extra == nil {
		r.Extra = map[int16]float64{}
	}
	r.Extra[provider] = price
}

func fmtPrice(p *float64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprintf("%.2f", *p)
}

func (r PriceRow) String() string {
	lang := "<nil>"
	if r.Language != nil {
		lang = *r.Language
	}
	return fmt.Sprintf("%s uuid=%s foil=%t etched=%t lang=%s alt=%t ck_buy=%s tcg_mkt=%s tcg_low=%s ck_ret=%s mkm_low=%s mkm_trend=%s scg_buy=%s abu_buy=%s csi_buy=%s tcg_ev=%s",
		r.Date, r.MtgjsonUUID, r.IsFoil, r.IsEtched, lang, r.IsAlt,
		fmtPrice(r.CardkingdomBuylistPrice),
		fmtPrice(r.TcgplayerMarketPrice),
		fmtPrice(r.TcgplayerLowPrice),
		fmtPrice(r.CardkingdomRetailPrice),
		fmtPrice(r.CardmarketLowPrice),
		fmtPrice(r.CardmarketTrendPrice),
		fmtPrice(r.StarcitygamesBuylistPrice),
		fmtPrice(r.AbuBuylistPrice),
		fmtPrice(r.CoolstuffincBuylistPrice),
		fmtPrice(r.TcgplayerLowSealedExpectedValue),
	)
}
