package observability

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// wholeDay is t's UTC midnight: a cutoff that never splits a day.
func wholeDay(t time.Time) time.Time {
	return t.UTC().Truncate(24 * time.Hour)
}

// RollUpEvents moves page hits from whole UTC days before the cutoff into events_days.
// A path in labels keeps its name and any other is rolled as "other", since old rows hold raw paths.
// Rows under /api/ are deleted unrolled: the gateway's paths are unnormalised and may hold search text.
// Each day is its own statement, oldest first, so a cancelled run keeps the days it finished; the counts are their totals.
func (c *Client) RollUpEvents(ctx context.Context, before time.Time, labels []string) (rolled, deleted int64, err error) {
	return c.rollUpEventsWhere(ctx, before, "", labels)
}

// OldestEventDay is the UTC day of the oldest page hit on a whole day before the cutoff, false when there is none.
func (c *Client) OldestEventDay(ctx context.Context, before time.Time) (time.Time, bool, error) {
	return c.oldestEventDayWhere(ctx, before, "")
}

// RollUpEventDay rolls one UTC day's page hits up as RollUpEvents does, in one statement.
func (c *Client) RollUpEventDay(ctx context.Context, day time.Time, labels []string) (rolled, deleted int64, err error) {
	return c.rollUpEventDayWhere(ctx, day, "", labels)
}

// rollUpEventsWhere is RollUpEvents over the paths starting with pathPrefix, so tests touch only their rows.
func (c *Client) rollUpEventsWhere(ctx context.Context, before time.Time, pathPrefix string, labels []string) (rolled, deleted int64, err error) {
	cutoff := wholeDay(before)
	var last time.Time
	for {
		if err := ctx.Err(); err != nil {
			return rolled, deleted, fmt.Errorf("observability: roll up events: %w", err)
		}
		day, ok, err := c.oldestEventDayWhere(ctx, cutoff, pathPrefix)
		if err != nil || !ok {
			return rolled, deleted, err
		}
		// A day that comes back after its roll-up would loop forever.
		if !last.IsZero() && !day.After(last) {
			return rolled, deleted, fmt.Errorf("observability: roll up events: %s has rows after its roll-up", sqlDate(day))
		}
		last = day
		r, d, err := c.rollUpEventDayWhere(ctx, day, pathPrefix, labels)
		rolled, deleted = rolled+r, deleted+d
		if err != nil {
			return rolled, deleted, err
		}
	}
}

// oldestEventDayWhere is OldestEventDay over the paths starting with pathPrefix.
func (c *Client) oldestEventDayWhere(ctx context.Context, before time.Time, pathPrefix string) (time.Time, bool, error) {
	var oldest sql.NullTime
	err := c.db.QueryRowContext(ctx, `SELECT min(ts) FROM events WHERE ts < $1 AND left(path, length($2::text)) = $2::text`,
		wholeDay(before), pathPrefix).Scan(&oldest)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("observability: oldest event day: %w", err)
	}
	if !oldest.Valid {
		return time.Time{}, false, nil
	}
	return wholeDay(oldest.Time), true, nil
}

// rollUpEventDayWhere is RollUpEventDay over the paths starting with pathPrefix.
func (c *Client) rollUpEventDayWhere(ctx context.Context, day time.Time, pathPrefix string, labels []string) (rolled, deleted int64, err error) {
	// A day rolled in two pieces would add its uniques to themselves.
	start := wholeDay(day)
	if labels == nil {
		labels = []string{}
	}
	// One statement: the rows rolled are the rows deleted, and a concurrent run finds them gone.
	const q = `WITH gone AS (
    DELETE FROM events
    WHERE ts >= $1 AND ts < $4 AND left(path, length($2::text)) = $2::text
    RETURNING ts, instance, path, tier, device, visitor, is_bot
), rolled AS (
    INSERT INTO events_days (day, instance, path, tier, device, is_bot, hits, uniques)
    SELECT (ts AT TIME ZONE 'UTC')::date, COALESCE(instance, ''),
        CASE WHEN path = ANY($3::text[]) THEN path ELSE 'other' END,
        tier, device, is_bot, count(*), count(DISTINCT visitor)
    FROM gone
    WHERE left(path, 5) <> '/api/'
    GROUP BY 1, 2, 3, tier, device, is_bot
    -- Overcounts uniques; reached only if a day is rolled twice.
    ON CONFLICT (day, instance, path, tier, device, is_bot) DO UPDATE
    SET hits = events_days.hits + EXCLUDED.hits, uniques = events_days.uniques + EXCLUDED.uniques
    RETURNING 1
)
SELECT (SELECT count(*) FROM rolled), (SELECT count(*) FROM gone)`
	if err := c.db.QueryRowContext(ctx, q, start, pathPrefix, pq.Array(labels), start.Add(24*time.Hour)).Scan(&rolled, &deleted); err != nil {
		return 0, 0, fmt.Errorf("observability: roll up events %s: %w", sqlDate(start), err)
	}
	return rolled, deleted, nil
}
