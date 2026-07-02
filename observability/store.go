// observability/store.go
package observability

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// InsertBatch writes events in one multi-row INSERT. ts uses the column default.
// An empty Visitor is stored as NULL so count(DISTINCT visitor) ignores anon hits.
// Each event binds 5 params; callers must keep len(evs)*5 below Postgres's 65535 param limit (256 events = 1280 params).
func (c *Client) InsertBatch(ctx context.Context, evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO events (path, tier, device, visitor, is_bot) VALUES ")
	args := make([]any, 0, len(evs)*5)
	for i, ev := range evs {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 5
		fmt.Fprintf(&b, "($%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5)
		var visitor any
		if ev.Visitor != "" {
			visitor = ev.Visitor
		}
		args = append(args, ev.Path, ev.Tier, ev.Device, visitor, ev.IsBot)
	}
	_, err := c.db.ExecContext(ctx, b.String(), args...)
	return err
}

// RefreshRollup recomputes usage_daily. Non-concurrent: it takes a brief
// ACCESS EXCLUSIVE lock, acceptable for a tiny hourly rollup on an admin-only
// dashboard, and avoids needing the TEMPORARY database privilege that a
// CONCURRENTLY refresh requires.
func (c *Client) RefreshRollup(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, "REFRESH MATERIALIZED VIEW usage_daily")
	return err
}

// PathAgg is a per-path aggregate. Uniques is summed daily uniques (a
// visitor-days approximation of range uniques), acceptable for the dashboard.
type PathAgg struct {
	Path    string
	Hits    int64
	Uniques int64
}

type TierAgg struct {
	Tier    string
	Hits    int64
	Uniques int64
}

type DeviceAgg struct {
	Path    string
	Device  string
	Hits    int64
	Uniques int64
}

// TopPages returns paths ordered by hits since the given day.
func (c *Client) TopPages(ctx context.Context, since time.Time, includeBots bool) ([]PathAgg, error) {
	const q = `SELECT path, sum(hits), sum(uniques)
FROM usage_daily
WHERE day >= $1::date AND ($2 OR NOT is_bot)
GROUP BY path ORDER BY sum(hits) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, includeBots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PathAgg
	for rows.Next() {
		var a PathAgg
		if err := rows.Scan(&a.Path, &a.Hits, &a.Uniques); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UsageByTier returns hits/uniques grouped by membership tier.
func (c *Client) UsageByTier(ctx context.Context, since time.Time, includeBots bool) ([]TierAgg, error) {
	const q = `SELECT tier, sum(hits), sum(uniques)
FROM usage_daily
WHERE day >= $1::date AND ($2 OR NOT is_bot)
GROUP BY tier ORDER BY sum(hits) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, includeBots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TierAgg
	for rows.Next() {
		var a TierAgg
		if err := rows.Scan(&a.Tier, &a.Hits, &a.Uniques); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeviceSplit returns hits/uniques grouped by path and device.
func (c *Client) DeviceSplit(ctx context.Context, since time.Time, includeBots bool) ([]DeviceAgg, error) {
	const q = `SELECT path, device, sum(hits), sum(uniques)
FROM usage_daily
WHERE day >= $1::date AND ($2 OR NOT is_bot)
GROUP BY path, device ORDER BY path, device`
	rows, err := c.db.QueryContext(ctx, q, since, includeBots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceAgg
	for rows.Next() {
		var a DeviceAgg
		if err := rows.Scan(&a.Path, &a.Device, &a.Hits, &a.Uniques); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SubViewBreakdown returns only newspaper/ and sleepers/ sub-view rows.
func (c *Client) SubViewBreakdown(ctx context.Context, since time.Time, includeBots bool) ([]PathAgg, error) {
	const q = `SELECT path, sum(hits), sum(uniques)
FROM usage_daily
WHERE day >= $1::date AND ($2 OR NOT is_bot)
  AND (path LIKE 'newspaper/%' OR path LIKE 'sleepers/%')
GROUP BY path ORDER BY sum(hits) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, includeBots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PathAgg
	for rows.Next() {
		var a PathAgg
		if err := rows.Scan(&a.Path, &a.Hits, &a.Uniques); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
