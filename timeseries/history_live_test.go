package timeseries

import (
	"context"
	"testing"
	"time"
)

// historyPageCards is the handler's set page at a range: 120 card-months, at least one card.
func historyPageCards(days int) int {
	return max(1, 120/max(1, (days+15)/30))
}

// TestHistoryReadCostLive times the history API's read, HGetAllByBanIDs, for
// a batch of ids over a window: a fresh id set first ("cold"), then the same
// set again ("warm"). docs/api-v2-history.md quotes its tables. Strictly
// read-only, so it is safe to point at production.
//
//	CHARTLIVE_CONFIG=config.json go test ./timeseries/ -run TestHistoryReadCostLive -v
func TestHistoryReadCostLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(chartLiveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// The tables' sizes; need is every id they read, so none is read warm as cold.
	batches, batchDays := []int{10, 50, 100, 300}, []int{30, 180, 365}
	shapeDays := []int{30, 90, 180, 365, 730, 1825, 3650}
	need := 0
	for _, n := range batches {
		need += n * len(batchDays)
	}
	for _, days := range shapeDays {
		need += historyPageCards(days) + 300 + 1
	}

	// Magic printings with a TCG Market price on the newest day, so every id
	// has data; in id order, so the slices below are disjoint.
	var latest time.Time
	err = c.db.QueryRowContext(ctx, `SELECT max(date) FROM prices WHERE provider=$1 AND date > now() - interval '7 days'`, ProviderTCGMarket).Scan(&latest)
	if err != nil {
		t.Fatalf("latest day: %v", err)
	}
	rows, err := c.db.QueryContext(ctx, `
		SELECT p.ban_id FROM prices p JOIN variants v ON v.ban_id = p.ban_id
		 WHERE p.provider=$1 AND p.date=$2 AND v.mtgjson_uuid IS NOT NULL AND v.language='' AND v.is_alt=false
		 ORDER BY p.ban_id LIMIT $3`, ProviderTCGMarket, latest, need)
	if err != nil {
		t.Fatalf("ids: %v", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("ids: %v", err)
	}
	rows.Close()
	if len(ids) < need {
		t.Fatalf("only %d candidate ids, the tables read %d", len(ids), need)
	}
	t.Logf("latest %s day %s, %d candidate ids", "TCGMarket", latest.Format("2006-01-02"), len(ids))
	// read times a set over days, cold then warm, and counts the points.
	read := func(set []int64, days int) (ms [2]int64, points int) {
		for run := range 2 {
			start := time.Now()
			res, err := c.HGetAllByBanIDs(ctx, set, Lookback(days).Since())
			ms[run] = time.Since(start).Milliseconds()
			if err != nil {
				t.Fatalf("read %d ids over %d days: %v", len(set), days, err)
			}
			points = 0
			for _, daysOf := range res {
				for _, pp := range daysOf {
					points += len(pp)
				}
			}
		}
		return ms, points
	}
	next := 0
	take := func(n int) []int64 {
		if next+n > len(ids)-len(shapeDays) {
			t.Fatalf("take %d at %d runs into the printings' ids", n, next)
		}
		set := ids[next : next+n]
		next += n
		return set
	}
	t.Log("| ids | days | cold ms | warm ms | rows |")
	t.Log("|---|---|---|---|---|")
	for _, n := range batches {
		for _, days := range batchDays {
			ms, points := read(take(n), days)
			t.Logf("| %d | %d | %d | %d | %d |", n, days, ms[0], ms[1], points)
		}
	}

	// The handler's shapes: one printing's variants, a set page at the allowance, a 300-id set.
	t.Log("| shape | ids | days | cold ms | warm ms | rows |")
	t.Log("|---|---|---|---|---|---|")
	tail := len(ids) - 1
	for _, days := range shapeDays {
		// a printing from the far end of the list, clear of the slices taken above
		var printing []int64
		prows, err := c.db.QueryContext(ctx, `
			SELECT ban_id FROM variants
			 WHERE mtgjson_uuid = (SELECT mtgjson_uuid FROM variants WHERE ban_id=$1)
			   AND language='' AND is_alt=false
			 ORDER BY ban_id`, ids[tail])
		if err != nil {
			t.Fatalf("printing of %d: %v", ids[tail], err)
		}
		for prows.Next() {
			var id int64
			if err := prows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			printing = append(printing, id)
		}
		if err := prows.Err(); err != nil {
			t.Fatalf("printing of %d: %v", ids[tail], err)
		}
		prows.Close()
		tail--
		page := historyPageCards(days)
		for _, shape := range []struct {
			name string
			set  []int64
		}{
			{"single printing", printing},
			{"set page", take(page)},
			{"whole set (300)", take(300)},
		} {
			ms, points := read(shape.set, days)
			t.Logf("| %s | %d | %d | %d | %d | %d |", shape.name, len(shape.set), days, ms[0], ms[1], points)
		}
	}
}
