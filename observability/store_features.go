package observability

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	featureColumns = 10    // parameters per row
	maxParams      = 65535 // Postgres bind parameter limit
)

var _ CounterStore = (*Client)(nil)

// UpsertMinutes adds rows to the minute's counts. Keys must be unique and sorted.
func (c *Client) UpsertMinutes(ctx context.Context, minute time.Time, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	if len(rows)*featureColumns > maxParams {
		return fmt.Errorf("observability: %d rows exceed the parameter limit", len(rows))
	}
	var sb strings.Builder
	sb.WriteString("INSERT INTO feature_events (ts, instance, tier, device, signed, is_bot, scope, name, value, n) VALUES ")
	args := make([]any, 0, len(rows)*featureColumns)
	ts := minute.UTC()
	for i, r := range rows {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('(')
		for j := 0; j < featureColumns; j++ {
			if j > 0 {
				sb.WriteByte(',')
			}
			sb.WriteByte('$')
			sb.WriteString(strconv.Itoa(i*featureColumns + j + 1))
		}
		sb.WriteByte(')')
		args = append(args, ts, r.Instance, r.Tier, r.Device, r.Signed, r.Bot, r.Scope, r.Name, r.Value, r.N)
	}
	sb.WriteString(" ON CONFLICT (ts, instance, tier, device, signed, is_bot, scope, name, value) DO UPDATE SET n = feature_events.n + EXCLUDED.n")
	if _, err := c.db.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("observability: upsert minutes: %w", err)
	}
	return nil
}

// FoldDay sets the UTC day's rows in feature_days to the sum of its minutes; folding again replaces, never adds.
func (c *Client) FoldDay(ctx context.Context, day time.Time) (int64, error) {
	start := day.UTC().Truncate(24 * time.Hour)
	const q = `INSERT INTO feature_days (day, instance, tier, device, signed, is_bot, scope, name, value, n)
SELECT $1::date, instance, tier, device, signed, is_bot, scope, name, value, sum(n)::bigint
FROM feature_events
WHERE ts >= $2 AND ts < $3
GROUP BY instance, tier, device, signed, is_bot, scope, name, value
ON CONFLICT (day, instance, tier, device, signed, is_bot, scope, name, value) DO UPDATE SET n = EXCLUDED.n`
	res, err := c.db.ExecContext(ctx, q, sqlDate(start), start, start.Add(24*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("observability: fold day %s: %w", sqlDate(start), err)
	}
	return res.RowsAffected()
}

// ReplaceDayRows deletes the instance's rows of names on the UTC day and inserts rows, in one transaction. Keys must be unique.
func (c *Client) ReplaceDayRows(ctx context.Context, day time.Time, instance string, names []string, rows []Row) error {
	if len(rows)*featureColumns > maxParams {
		return fmt.Errorf("observability: %d rows exceed the parameter limit", len(rows))
	}
	if len(names) == 0 && len(rows) == 0 {
		return nil
	}
	// A row the delete does not cover is refused: it would collide with or outlive the rows it should replace.
	seen := make(map[Row]bool, len(rows))
	for _, r := range rows {
		if r.Instance != instance || !slices.Contains(names, r.Name) {
			return fmt.Errorf("observability: replace day rows: %s under %q is outside instance %q and its names", r.Name, r.Instance, instance)
		}
		key := r
		key.N = 0
		if seen[key] {
			return fmt.Errorf("observability: replace day rows: duplicate key for %s", r.Name)
		}
		seen[key] = true
	}
	start := sqlDate(day.UTC().Truncate(24 * time.Hour))
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: replace day rows: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM feature_days WHERE day = $1::date AND instance = $2 AND name = ANY($3)`,
		start, instance, pq.Array(names)); err != nil {
		return fmt.Errorf("observability: replace day rows: %w", err)
	}
	if len(rows) > 0 {
		var sb strings.Builder
		sb.WriteString("INSERT INTO feature_days (day, instance, tier, device, signed, is_bot, scope, name, value, n) VALUES ")
		args := make([]any, 0, len(rows)*featureColumns)
		for i, r := range rows {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString("($")
			sb.WriteString(strconv.Itoa(i*featureColumns + 1))
			sb.WriteString("::date")
			for j := 1; j < featureColumns; j++ {
				sb.WriteString(",$")
				sb.WriteString(strconv.Itoa(i*featureColumns + j + 1))
			}
			sb.WriteByte(')')
			args = append(args, start, r.Instance, r.Tier, r.Device, r.Signed, r.Bot, r.Scope, r.Name, r.Value, r.N)
		}
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("observability: replace day rows: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: replace day rows: %w", err)
	}
	return nil
}

// PruneMinutes deletes minute rows before the cutoff; the caller folds their days first.
func (c *Client) PruneMinutes(ctx context.Context, before time.Time) (int64, error) {
	// Whole days only: a part-pruned day would shrink when refolded.
	before = wholeDay(before)
	res, err := c.db.ExecContext(ctx, `DELETE FROM feature_events WHERE ts < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("observability: prune minutes: %w", err)
	}
	return res.RowsAffected()
}

// MinuteDaysBefore lists, ascending, the UTC days with minute rows before the cutoff.
func (c *Client) MinuteDaysBefore(ctx context.Context, before time.Time) ([]time.Time, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT DISTINCT (ts AT TIME ZONE 'UTC')::date FROM feature_events WHERE ts < $1 ORDER BY 1`, before.UTC())
	if err != nil {
		return nil, fmt.Errorf("observability: minute days: %w", err)
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var d time.Time
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("observability: minute days: %w", err)
		}
		days = append(days, time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: minute days: %w", err)
	}
	return days, nil
}
