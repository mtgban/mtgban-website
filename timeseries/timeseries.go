package timeseries

import (
	"fmt"
	"time"
)

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
}

type Lookback int

const (
	LookbackStandard Lookback = iota
	LookbackModern
	LookbackLegacy
	LookbackVintage
)

func (l Lookback) Days() int {
	switch l {
	case LookbackStandard:
		return 730 // 2 years
	case LookbackModern, LookbackLegacy, LookbackVintage:
		return 3650 // 10 years
	default:
		return 30 // 30 days
	}
}

func (l Lookback) Since() time.Time {
	return time.Now().AddDate(0, 0, -l.Days())
}

// PriceForDataset returns the price column matching a dataset config index.
func (r PriceRow) PriceForDataset(index int) *float64 {
	switch index {
	case 0:
		return r.CardkingdomRetailPrice
	case 1:
		return r.CardkingdomBuylistPrice
	case 2:
		return r.TcgplayerLowPrice
	case 3:
		return r.TcgplayerMarketPrice
	case 4:
		return r.CardmarketLowPrice
	case 5:
		return r.CardmarketTrendPrice
	case 6:
		return r.StarcitygamesBuylistPrice
	case 7:
		return r.AbuBuylistPrice
	case 8:
		return r.TcgplayerLowSealedExpectedValue
	case 9:
		return r.CoolstuffincBuylistPrice
	default:
		return nil
	}
}

// SetPriceForDataset sets the price column matching a dataset config index.
func (r *PriceRow) SetPriceForDataset(index int, price float64) {
	switch index {
	case 0:
		r.CardkingdomRetailPrice = &price
	case 1:
		r.CardkingdomBuylistPrice = &price
	case 2:
		r.TcgplayerLowPrice = &price
	case 3:
		r.TcgplayerMarketPrice = &price
	case 4:
		r.CardmarketLowPrice = &price
	case 5:
		r.CardmarketTrendPrice = &price
	case 6:
		r.StarcitygamesBuylistPrice = &price
	case 7:
		r.AbuBuylistPrice = &price
	case 8:
		r.TcgplayerLowSealedExpectedValue = &price
	case 9:
		r.CoolstuffincBuylistPrice = &price
	}
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
