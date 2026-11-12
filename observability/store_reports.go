package observability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// DayQuery asks feature_days for sums over periods of whole days.
// When Step does not divide Days the oldest period is shorter than Step.
type DayQuery struct {
	Instance string    // required; observability.SharedInstance for stock rows
	To       time.Time // newest day included, read as a UTC date
	Days     int       // days back from To, To included: 1 to 400
	Step     int       // days a period; 0 means Days, one period
	Signed   bool      // signed-in rows only; job and discord rows always pass
	Humans   bool      // leave bot rows out
	Names    []string  // nil for every name; a non-nil empty list matches none
	ByTier   bool
	ByDevice bool
	MinCell  int64 // leave out rows summing below this; 0 for admin
}

// DayTotal is one key's sum over one period.
type DayTotal struct {
	Period             int // 0 is the newest Step days, 1 the Step before
	Name, Scope, Value string
	Tier, Device       string // "" unless the query split by them
	N                  int64
	Days               int       // distinct days with a row in the period, not the period's length
	First, Last        time.Time // oldest and newest such day
}

// dateDay is a scanned date column as UTC midnight, whatever zone the driver gave it.
func dateDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// maxQueryDays bounds a DayQuery's window.
const maxQueryDays = 400

// validate refuses a query DayTotals must not send.
func (q DayQuery) validate() error {
	switch {
	case q.Instance == "":
		return errors.New("observability: day query has no instance")
	case q.Days < 1 || q.Days > maxQueryDays:
		return fmt.Errorf("observability: day query spans %d days, want 1 to %d", q.Days, maxQueryDays)
	case q.Step < 0:
		return errors.New("observability: day query has a negative step")
	case q.MinCell < 0:
		return errors.New("observability: day query has a negative minimum cell")
	case q.To.IsZero():
		return errors.New("observability: day query has no last day")
	}
	return nil
}

// dayTotalsSQL is DayTotals' statement and arguments; only the tier and device columns vary, from fixed strings.
func dayTotalsSQL(q DayQuery) (string, []any) {
	tier, device := "''::text", "''::text"
	if q.ByTier {
		tier = "tier"
	}
	if q.ByDevice {
		device = "device"
	}
	step := q.Step
	if step == 0 {
		step = q.Days
	}
	query := `SELECT ($2::date - day) / $4 AS period, name, scope, value, ` + tier + `, ` + device + `,
       sum(n)::bigint, count(DISTINCT day), min(day), max(day)
FROM feature_days
WHERE instance = $1
  AND day <= $2::date AND day > $2::date - $3::int
  AND (NOT $5 OR signed OR device IN ('job', 'discord'))
  AND (NOT $6 OR NOT is_bot)
  AND ($7::text[] IS NULL OR name = ANY($7))
GROUP BY 1, 2, 3, 4, 5, 6
HAVING sum(n) >= $8
ORDER BY name, scope, value, period, 5, 6`
	args := []any{q.Instance, sqlDate(q.To), q.Days, step, q.Signed, q.Humans, pq.Array(q.Names), q.MinCell}
	return query, args
}

// DayTotals sums the query's day rows per key and period; a bad query is refused unsent.
func (c *Client) DayTotals(ctx context.Context, q DayQuery) ([]DayTotal, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	query, args := dayTotalsSQL(q)
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: day totals: %w", err)
	}
	defer rows.Close()
	var out []DayTotal
	for rows.Next() {
		var t DayTotal
		if err := rows.Scan(&t.Period, &t.Name, &t.Scope, &t.Value, &t.Tier, &t.Device, &t.N, &t.Days, &t.First, &t.Last); err != nil {
			return nil, fmt.Errorf("observability: day totals: %w", err)
		}
		t.First, t.Last = dateDay(t.First), dateDay(t.Last)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: day totals: %w", err)
	}
	return out, nil
}

// foldedThroughSQL is the newest day before today with folded flush rows and a fold run finished after it.
const foldedThroughSQL = `SELECT max(day) FROM feature_days
WHERE name = 'metrics.flush' AND day < $1::date
  AND day < coalesce((SELECT (max(ts) AT TIME ZONE 'UTC')::date FROM feature_events
      WHERE name = 'job.run' AND scope = 'fold' AND value = 'ok' AND ts <= $2), $1::date)`

// FoldedThrough is the newest fully folded UTC day before now's, false when there is none.
// A day counts once it holds folded metrics.flush rows and, where a fold run is on record, one finished after it.
func (c *Client) FoldedThrough(ctx context.Context, now time.Time) (time.Time, bool, error) {
	var day sql.NullTime
	if err := c.db.QueryRowContext(ctx, foldedThroughSQL, sqlDate(now), now.UTC()).Scan(&day); err != nil {
		return time.Time{}, false, fmt.Errorf("observability: folded through: %w", err)
	}
	if !day.Valid {
		return time.Time{}, false, nil
	}
	return dateDay(day.Time), true, nil
}

// instanceWindowDays is how far back Instances looks for day rows.
const instanceWindowDays = 30

// Instances lists, sorted, the instances with day rows on now's UTC day or the 30 days before it, without SharedInstance or "".
func (c *Client) Instances(ctx context.Context, now time.Time) ([]string, error) {
	today := wholeDay(now)
	from := today.AddDate(0, 0, -instanceWindowDays)
	rows, err := c.db.QueryContext(ctx, `SELECT DISTINCT instance FROM feature_days
WHERE day >= $1::date AND day <= $2::date AND instance <> $3 AND instance <> '' ORDER BY 1`, sqlDate(from), sqlDate(today), SharedInstance)
	if err != nil {
		return nil, fmt.Errorf("observability: instances: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("observability: instances: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: instances: %w", err)
	}
	return out, nil
}

// FoldStamp changes whenever a metrics job has finished: the newest day row and the newest ok job.run minute.
func (c *Client) FoldStamp(ctx context.Context) (string, error) {
	var s string
	err := c.db.QueryRowContext(ctx, `SELECT coalesce((SELECT max(day)::text FROM feature_days), '') || '/' ||
       coalesce((SELECT (max(ts) AT TIME ZONE 'UTC')::text FROM feature_events WHERE name = 'job.run' AND value = 'ok'), '')`).Scan(&s)
	if err != nil {
		return "", fmt.Errorf("observability: fold stamp: %w", err)
	}
	return s, nil
}

// PageVisit is one page's signed-in human traffic, from events.
type PageVisit struct {
	Path                     string
	Views, MobileViews       int64
	Visitors, Once, FivePlus int64 // readers; on one day; on five or more days
}

// PageVisits sums the instance's signed-in human page hits in [from, until), with each reader's distinct UTC days.
func (c *Client) PageVisits(ctx context.Context, instance string, from, until time.Time) ([]PageVisit, error) {
	const q = `SELECT path, sum(hits)::bigint, sum(mobile_hits)::bigint, count(*),
       count(*) FILTER (WHERE days = 1), count(*) FILTER (WHERE days >= 5)
FROM (
    SELECT path, visitor, count(*) AS hits,
           count(*) FILTER (WHERE device = 'mobile') AS mobile_hits,
           count(DISTINCT (ts AT TIME ZONE 'UTC')::date) AS days
    FROM events
    WHERE ts >= $1 AND ts < $2 AND instance = $3 AND visitor IS NOT NULL AND NOT is_bot
    GROUP BY path, visitor
) v
GROUP BY path ORDER BY path`
	rows, err := c.db.QueryContext(ctx, q, from.UTC(), until.UTC(), instance)
	if err != nil {
		return nil, fmt.Errorf("observability: page visits: %w", err)
	}
	defer rows.Close()
	var out []PageVisit
	for rows.Next() {
		var p PageVisit
		if err := rows.Scan(&p.Path, &p.Views, &p.MobileViews, &p.Visitors, &p.Once, &p.FivePlus); err != nil {
			return nil, fmt.Errorf("observability: page visits: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: page visits: %w", err)
	}
	return out, nil
}

// InstanceHealth is what one instance's counter wrote about itself.
type InstanceHealth struct {
	Instance                       string
	LastFlush                      time.Time // newest minute with a metrics.flush row
	Rows                           int64     // minute rows stamped yesterday
	Dropped, FlushFailed, Rejected int64     // since the start of yesterday
}

// CounterHealth reads each instance's minute rows from the start of yesterday's UTC day.
func (c *Client) CounterHealth(ctx context.Context, yesterday time.Time) ([]InstanceHealth, error) {
	start := wholeDay(yesterday)
	const q = `SELECT instance,
       max(ts) FILTER (WHERE name = 'metrics.flush'),
       count(*) FILTER (WHERE ts < $2),
       coalesce(sum(n) FILTER (WHERE name = 'metrics.dropped'), 0)::bigint,
       coalesce(sum(n) FILTER (WHERE name = 'metrics.flush_fail'), 0)::bigint,
       coalesce(sum(n) FILTER (WHERE name = 'metrics.rejected'), 0)::bigint
FROM feature_events WHERE ts >= $1 GROUP BY instance ORDER BY instance`
	rows, err := c.db.QueryContext(ctx, q, start, start.Add(24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("observability: counter health: %w", err)
	}
	defer rows.Close()
	var out []InstanceHealth
	for rows.Next() {
		var h InstanceHealth
		var last sql.NullTime
		if err := rows.Scan(&h.Instance, &last, &h.Rows, &h.Dropped, &h.FlushFailed, &h.Rejected); err != nil {
			return nil, fmt.Errorf("observability: counter health: %w", err)
		}
		if last.Valid {
			h.LastFlush = last.Time.UTC()
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: counter health: %w", err)
	}
	return out, nil
}

// JobRun is the newest job.run minute for one job and result.
type JobRun struct {
	Instance, Job, Result string
	At                    time.Time
}

// JobRuns lists the newest job.run minute per instance, job and result, by job then newest first.
// Minute rows live 14 days, so a job missing here has not run in that time.
func (c *Client) JobRuns(ctx context.Context) ([]JobRun, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT instance, scope, value, max(ts) FROM feature_events
WHERE name = 'job.run' GROUP BY 1, 2, 3 ORDER BY 2, 4 DESC`)
	if err != nil {
		return nil, fmt.Errorf("observability: job runs: %w", err)
	}
	defer rows.Close()
	var out []JobRun
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.Instance, &r.Job, &r.Result, &r.At); err != nil {
			return nil, fmt.Errorf("observability: job runs: %w", err)
		}
		r.At = r.At.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: job runs: %w", err)
	}
	return out, nil
}

// HourTotal is one name's count in one hour, from the minute rows.
type HourTotal struct {
	Hour         time.Time
	Scope, Value string
	N            int64
}

// HourTotals sums one name's minute rows per UTC hour since since, with q's instance and its signed and bot filters.
func (c *Client) HourTotals(ctx context.Context, q DayQuery, since time.Time) ([]HourTotal, error) {
	if q.Instance == "" {
		return nil, errors.New("observability: hour totals has no instance")
	}
	if len(q.Names) != 1 {
		return nil, fmt.Errorf("observability: hour totals takes one name, not %d", len(q.Names))
	}
	const query = `SELECT date_trunc('hour', ts AT TIME ZONE 'UTC'), scope, value, sum(n)::bigint
FROM feature_events
WHERE instance = $1 AND name = $2 AND ts >= $3
  AND (NOT $4 OR signed OR device IN ('job', 'discord'))
  AND (NOT $5 OR NOT is_bot)
GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`
	rows, err := c.db.QueryContext(ctx, query, q.Instance, q.Names[0], since.UTC(), q.Signed, q.Humans)
	if err != nil {
		return nil, fmt.Errorf("observability: hour totals: %w", err)
	}
	defer rows.Close()
	var out []HourTotal
	for rows.Next() {
		var h HourTotal
		if err := rows.Scan(&h.Hour, &h.Scope, &h.Value, &h.N); err != nil {
			return nil, fmt.Errorf("observability: hour totals: %w", err)
		}
		// A timestamp without a zone: read its fields as UTC.
		y, m, d := h.Hour.Date()
		h.Hour = time.Date(y, m, d, h.Hour.Hour(), 0, 0, 0, time.UTC)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: hour totals: %w", err)
	}
	return out, nil
}
