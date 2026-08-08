package timeseries

import (
	"context"
	"testing"
	"time"
)

// TestCompareReadPaths benchmarks the legacy wide-table reads against the new
// long-table reads on the SAME real cards, against a live DB, and checks the
// results agree. It is a diagnostic, not a pass/fail unit test: run it with -v to
// read the timing/parity report.
//
//	TCGLIVE_HOST=... TCGLIVE_USER=... TCGLIVE_PASSWORD=... TCGLIVE_DBNAME=card_prices \
//	TCGLIVE_SSLMODE=require go test ./timeseries/ -run TestCompareReadPaths -v
//
// TCGLow is legacy dataset index 2 / long provider id 3; both sides read that
// metric so the comparison is apples-to-apples.
const (
	cmpDatasetIndex = 2              // TCGLow, legacy columnForDataset index
	cmpProvider     = ProviderTCGLow // = 3
	cmpLookback     = Lookback(90)
)

func TestCompareReadPaths(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	// Sample recent canonical (English, non-alt) Magic cards that have TCGLow data.
	type card struct {
		uuid             string
		isFoil, isEtched bool
	}
	rows, err := c.db.QueryContext(ctx, `
		SELECT DISTINCT v.mtgjson_uuid, v.is_foil, v.is_etched
		FROM prices p JOIN variants v ON v.ban_id = p.ban_id
		WHERE p.provider = $1 AND p.date >= CURRENT_DATE - 7
		  AND v.mtgjson_uuid IS NOT NULL AND v.language = '' AND v.is_alt = false
		LIMIT 25`, cmpProvider)
	if err != nil {
		t.Fatalf("sample query: %v", err)
	}
	var cards []card
	for rows.Next() {
		var cd card
		if err := rows.Scan(&cd.uuid, &cd.isFoil, &cd.isEtched); err != nil {
			t.Fatal(err)
		}
		cards = append(cards, cd)
	}
	rows.Close()
	if len(cards) == 0 {
		t.Skip("no sample cards found")
	}
	t.Logf("sampled %d canonical cards for the single-card comparison", len(cards))

	// --- single-card chart read: HGetAll (wide) vs HGetAllLong (long) ---
	var oldDur, newDur time.Duration
	var matches, compared int
	for _, cd := range cards {
		t0 := time.Now()
		wide, err := c.HGetAll(ctx, cd.uuid, cd.isFoil, cd.isEtched, nil, cmpLookback)
		oldDur += time.Since(t0)
		if err != nil {
			t.Fatalf("HGetAll: %v", err)
		}
		t1 := time.Now()
		long, err := c.HGetAllLong(ctx, cd.uuid, cd.isFoil, cd.isEtched, cmpLookback)
		newDur += time.Since(t1)
		if err != nil {
			t.Fatalf("HGetAllLong: %v", err)
		}
		// Parity on the TCGLow series: for each date the wide row has a TCGLow
		// price, the long map should carry the same value under provider 3.
		for date, wrow := range wide {
			wp := wrow.PriceForDataset(cmpDatasetIndex)
			if wp == nil {
				continue
			}
			compared++
			if lp, ok := long[date][cmpProvider]; ok && lp == *wp {
				matches++
			}
		}
	}
	t.Logf("HGetAll   (wide, %d cards): total %v, avg %v/card",
		len(cards), oldDur.Round(time.Millisecond), (oldDur / time.Duration(len(cards))).Round(time.Microsecond))
	t.Logf("HGetAllLong (long, %d cards): total %v, avg %v/card",
		len(cards), newDur.Round(time.Millisecond), (newDur / time.Duration(len(cards))).Round(time.Microsecond))
	t.Logf("TCGLow series parity: %d/%d date-points match (differences are expected where the wide last-wins picked a non-canonical language/alt row)", matches, compared)

	// --- earliest date ---
	oldDur, newDur = 0, 0
	for _, cd := range cards {
		t0 := time.Now()
		_, _ = c.GetEarliestDate(ctx, cd.uuid, cd.isFoil, cd.isEtched, cmpLookback)
		oldDur += time.Since(t0)
		t1 := time.Now()
		_, _ = c.GetEarliestDateLong(ctx, cd.uuid, cd.isFoil, cd.isEtched, cmpLookback)
		newDur += time.Since(t1)
	}
	t.Logf("GetEarliestDate     avg %v/card | GetEarliestDateLong avg %v/card",
		(oldDur / time.Duration(len(cards))).Round(time.Microsecond),
		(newDur / time.Duration(len(cards))).Round(time.Microsecond))

	// --- aggregate buylist metrics over ~90 days (whole-provider scan) ---
	since := time.Now().AddDate(0, 0, -90)
	t0 := time.Now()
	wideStats, err := c.GetAggregatePriceStats(ctx, cmpDatasetIndex, since)
	oldAgg := time.Since(t0)
	if err != nil {
		t.Fatalf("GetAggregatePriceStats: %v", err)
	}
	t1 := time.Now()
	longStats, err := c.GetAggregatePriceStatsLong(ctx, cmpProvider, since)
	newAgg := time.Since(t1)
	if err != nil {
		t.Fatalf("GetAggregatePriceStatsLong: %v", err)
	}
	t.Logf("GetAggregatePriceStats     (wide): %v, %d cards", oldAgg.Round(time.Millisecond), len(wideStats))
	t.Logf("GetAggregatePriceStatsLong (long): %v, %d cards", newAgg.Round(time.Millisecond), len(longStats))
	// Spot-check parity on a few shared keys.
	var aggChecked, aggMatch int
	for k, ws := range wideStats {
		ls, ok := longStats[k]
		if !ok {
			continue
		}
		aggChecked++
		if ws.Max == ls.Max && ws.Min == ls.Min && ws.Count == ls.Count {
			aggMatch++
		}
		if aggChecked >= 500 {
			break
		}
	}
	t.Logf("aggregate parity (first %d shared keys): %d match on max/min/count", aggChecked, aggMatch)

	// --- movers over a 30-day window (two-date compare) ---
	t0 = time.Now()
	wideMovers, err := c.GetMovers(ctx, cmpDatasetIndex, 30, 1.0, 1.0)
	oldMov := time.Since(t0)
	if err != nil {
		t.Fatalf("GetMovers: %v", err)
	}
	t1 = time.Now()
	longMovers, err := c.GetMoversLong(ctx, cmpProvider, 30, 1.0, 1.0, CategoryMagic)
	newMov := time.Since(t1)
	if err != nil {
		t.Fatalf("GetMoversLong: %v", err)
	}
	t.Logf("GetMovers     (wide): %v, %d rows", oldMov.Round(time.Millisecond), len(wideMovers))
	t.Logf("GetMoversLong (long): %v, %d rows", newMov.Round(time.Millisecond), len(longMovers))
}
