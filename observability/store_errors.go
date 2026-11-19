package observability

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// errorRowsPerDay is the most distinct error rows one instance keeps for a day.
const errorRowsPerDay = 200

// ErrorRowsPerDay is the most distinct error rows one instance keeps for a day.
const ErrorRowsPerDay = errorRowsPerDay

// errorCapLockSQL serialises one instance's writers so two cannot both see room for the last row.
const errorCapLockSQL = `SELECT pg_advisory_xact_lock(hashtext('feature_errors:' || $1::text))`

// ErrorRow is one script error count for a day.
type ErrorRow struct {
	Day                          time.Time // UTC date
	Device, Build, Script, Class string
	Line                         int
	N                            int64
}

// ErrorTop is one place and class of error summed over a build's days.
type ErrorTop struct {
	Script, Class      string
	Line               int
	N, Desktop, Mobile int64
	FirstDay, LastDay  time.Time
}

// UpsertErrors adds rows for one instance; refused counts new keys past the day's cap.
func (c *Client) UpsertErrors(ctx context.Context, instance string, rows []ErrorRow) (refused int, err error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("observability: upsert errors: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, errorCapLockSQL, instance); err != nil {
		return 0, fmt.Errorf("observability: upsert errors: %w", err)
	}
	const q = `INSERT INTO feature_errors (day, instance, device, build, script, line, class, n)
SELECT $1::date, $2::text, $3::text, $4::text, $5::text, $6::integer, $7::text, $8::bigint
WHERE EXISTS (SELECT 1 FROM feature_errors WHERE day = $1::date AND instance = $2 AND device = $3
              AND build = $4 AND script = $5 AND line = $6 AND class = $7)
   OR (SELECT count(*) FROM feature_errors WHERE day = $1::date AND instance = $2) < $9
ON CONFLICT (day, instance, device, build, script, line, class)
DO UPDATE SET n = feature_errors.n + EXCLUDED.n`
	for _, r := range rows {
		res, err := tx.ExecContext(ctx, q, wholeDay(r.Day), instance, r.Device, r.Build, r.Script, r.Line, r.Class, r.N, errorRowsPerDay)
		if err != nil {
			return 0, fmt.Errorf("observability: upsert errors: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("observability: upsert errors: %w", err)
		}
		if n == 0 {
			refused++
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("observability: upsert errors: %w", err)
	}
	return refused, nil
}

// TopErrors sums a build's errors by script, line and class over every day and device, largest first.
func (c *Client) TopErrors(ctx context.Context, instance, build string, limit int) ([]ErrorTop, error) {
	const q = `SELECT script, line, class, sum(n)::bigint,
    coalesce(sum(n) FILTER (WHERE device = 'desktop'), 0)::bigint,
    coalesce(sum(n) FILTER (WHERE device = 'mobile'), 0)::bigint,
    min(day), max(day)
FROM feature_errors WHERE instance = $1 AND build = $2
GROUP BY script, line, class
ORDER BY sum(n) DESC, script, line, class
LIMIT $3`
	rows, err := c.db.QueryContext(ctx, q, instance, build, limit)
	if err != nil {
		return nil, fmt.Errorf("observability: top errors: %w", err)
	}
	defer rows.Close()
	var out []ErrorTop
	for rows.Next() {
		var e ErrorTop
		if err := rows.Scan(&e.Script, &e.Line, &e.Class, &e.N, &e.Desktop, &e.Mobile, &e.FirstDay, &e.LastDay); err != nil {
			return nil, fmt.Errorf("observability: top errors: %w", err)
		}
		e.FirstDay, e.LastDay = utcDate(e.FirstDay), utcDate(e.LastDay)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: top errors: %w", err)
	}
	return out, nil
}

// ErrorFirstSeen sums errors by script and class, newest first sighting first; Line is 0.
func (c *Client) ErrorFirstSeen(ctx context.Context, instance string, limit int) ([]ErrorTop, error) {
	const q = `SELECT script, class, sum(n)::bigint,
    coalesce(sum(n) FILTER (WHERE device = 'desktop'), 0)::bigint,
    coalesce(sum(n) FILTER (WHERE device = 'mobile'), 0)::bigint,
    min(day), max(day)
FROM feature_errors WHERE instance = $1
GROUP BY script, class
ORDER BY min(day) DESC, script, class
LIMIT $2`
	rows, err := c.db.QueryContext(ctx, q, instance, limit)
	if err != nil {
		return nil, fmt.Errorf("observability: error first seen: %w", err)
	}
	defer rows.Close()
	var out []ErrorTop
	for rows.Next() {
		var e ErrorTop
		if err := rows.Scan(&e.Script, &e.Class, &e.N, &e.Desktop, &e.Mobile, &e.FirstDay, &e.LastDay); err != nil {
			return nil, fmt.Errorf("observability: error first seen: %w", err)
		}
		e.FirstDay, e.LastDay = utcDate(e.FirstDay), utcDate(e.LastDay)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: error first seen: %w", err)
	}
	return out, nil
}

// NewestErrorBuild is the build ranked by count on the instance's newest day with errors; "" when none.
func (c *Client) NewestErrorBuild(ctx context.Context, instance string) (string, error) {
	const q = `SELECT build FROM feature_errors
WHERE instance = $1 AND day = (SELECT max(day) FROM feature_errors WHERE instance = $1)
GROUP BY build ORDER BY sum(n) DESC, build LIMIT 1`
	var build string
	switch err := c.db.QueryRowContext(ctx, q, instance).Scan(&build); err {
	case nil:
		return build, nil
	case sql.ErrNoRows:
		return "", nil
	default:
		return "", fmt.Errorf("observability: newest error build: %w", err)
	}
}

// CountErrorRows counts the instance's error rows for a UTC day.
func (c *Client) CountErrorRows(ctx context.Context, instance string, day time.Time) (int, error) {
	var n int
	if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM feature_errors WHERE day = $1::date AND instance = $2`, wholeDay(day), instance).Scan(&n); err != nil {
		return 0, fmt.Errorf("observability: count error rows: %w", err)
	}
	return n, nil
}

// PruneErrors deletes error rows before the day in one statement, since the daily cap bounds it.
func (c *Client) PruneErrors(ctx context.Context, before time.Time) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM feature_errors WHERE day < $1::date`, wholeDay(before))
	if err != nil {
		return 0, fmt.Errorf("observability: prune errors: %w", err)
	}
	return res.RowsAffected()
}

// utcDate keeps a scanned date's calendar day at midnight UTC.
func utcDate(d time.Time) time.Time {
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
}
