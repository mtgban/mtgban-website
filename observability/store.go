// Package observability records page visits in Postgres and answers the
// admin dashboard's usage aggregates.
package observability

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// InsertBatch writes events in one multi-row INSERT. ts uses the column default.
// An empty Visitor is stored as NULL so count(DISTINCT visitor) ignores anon hits.
// Each event binds 6 params; keep len(evs)*6 below Postgres's 65535 param limit.
func (c *Client) InsertBatch(ctx context.Context, evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO events (path, tier, device, visitor, is_bot, instance) VALUES ")
	args := make([]any, 0, len(evs)*6)
	for i, ev := range evs {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 6
		fmt.Fprintf(&b, "($%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6)
		var visitor any
		if ev.Visitor != "" {
			visitor = ev.Visitor
		}
		args = append(args, ev.Path, ev.Tier, ev.Device, visitor, ev.IsBot, ev.Instance)
	}
	_, err := c.db.ExecContext(ctx, b.String(), args...)
	return err
}

// PathAgg is a per-path aggregate. Uniques is the true distinct-visitor count
// over the range (anonymous NULL visitors are excluded).
type PathAgg struct {
	Path    string
	Hits    int64
	Uniques int64
}

// TierAgg is one tier's visit counts.
type TierAgg struct {
	Tier    string
	Hits    int64
	Uniques int64
}

// DeviceAgg is one path's visit counts split by device.
type DeviceAgg struct {
	Path    string
	Device  string
	Hits    int64
	Uniques int64
}

// TopPages returns paths for one instance ordered by hits since the given time.
func (c *Client) TopPages(ctx context.Context, since time.Time, includeBots bool, instance string) ([]PathAgg, error) {
	const q = `SELECT path, count(*), count(DISTINCT visitor)
FROM events
WHERE ts >= $1 AND instance = $2 AND ($3 OR NOT is_bot)
GROUP BY path ORDER BY count(*) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, instance, includeBots)
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

// UsageByTier returns hits/uniques for one instance grouped by membership tier.
func (c *Client) UsageByTier(ctx context.Context, since time.Time, includeBots bool, instance string) ([]TierAgg, error) {
	const q = `SELECT tier, count(*), count(DISTINCT visitor)
FROM events
WHERE ts >= $1 AND instance = $2 AND ($3 OR NOT is_bot)
GROUP BY tier ORDER BY count(*) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, instance, includeBots)
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

// DeviceSplit returns hits/uniques for one instance grouped by path and device.
func (c *Client) DeviceSplit(ctx context.Context, since time.Time, includeBots bool, instance string) ([]DeviceAgg, error) {
	const q = `SELECT path, device, count(*), count(DISTINCT visitor)
FROM events
WHERE ts >= $1 AND instance = $2 AND ($3 OR NOT is_bot)
GROUP BY path, device ORDER BY path, device`
	rows, err := c.db.QueryContext(ctx, q, since, instance, includeBots)
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

// SubViewBreakdown returns only newspaper/ and sleepers/ sub-view rows for one instance.
func (c *Client) SubViewBreakdown(ctx context.Context, since time.Time, includeBots bool, instance string) ([]PathAgg, error) {
	const q = `SELECT path, count(*), count(DISTINCT visitor)
FROM events
WHERE ts >= $1 AND instance = $2 AND ($3 OR NOT is_bot)
  AND (path LIKE 'newspaper/%' OR path LIKE 'sleepers/%')
GROUP BY path ORDER BY count(*) DESC`
	rows, err := c.db.QueryContext(ctx, q, since, instance, includeBots)
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
