package observability

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFeatureStatementsCreateEventsDays(t *testing.T) {
	joined := strings.Join(featureStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS events_days",
		"PRIMARY KEY (day, instance, path, tier, device, is_bot)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("feature schema lacks %q", want)
		}
	}
	if strings.Contains(joined, "visitor") {
		t.Error("events_days keeps no visitor")
	}
}

const rollupInstance = "__test__rollup"

// rollupClient is a testClient that also deletes the roll-up tests' API paths and day rows.
func rollupClient(t *testing.T) *Client {
	t.Helper()
	c := testClient(t)
	t.Cleanup(func() {
		_, _ = c.db.Exec(`DELETE FROM events WHERE starts_with(path, '/api/__test__')`)
		_, _ = c.db.Exec(`DELETE FROM events_days WHERE starts_with(path, '__test__') OR starts_with(path, '/api/__test__') OR instance = $1`, rollupInstance)
	})
	return c
}

// seedEvent inserts one page hit; a zero ts takes the column default, a nil instance or visitor stays NULL.
func seedEvent(t *testing.T, c *Client, ts time.Time, instance any, path, tier string, visitor any, bot bool) {
	t.Helper()
	var at any
	if !ts.IsZero() {
		at = ts
	}
	_, err := c.db.Exec(`INSERT INTO events (ts, path, tier, device, visitor, is_bot, instance)
		VALUES (COALESCE($1::timestamptz, now()), $2, $3, 'desktop', $4, $5, $6)`, at, path, tier, visitor, bot, instance)
	if err != nil {
		t.Fatal(err)
	}
}

func rollUp(t *testing.T, c *Client, before time.Time, prefix string, labels ...string) (rolled, deleted int64) {
	t.Helper()
	rolled, deleted, err := c.rollUpEventsWhere(context.Background(), before, prefix, labels)
	if err != nil {
		t.Fatal(err)
	}
	return rolled, deleted
}

// dayHits reads an events_days row, or -1, -1 when there is none.
func dayHits(t *testing.T, c *Client, day time.Time, instance, path, tier string, bot bool) (hits, uniques int64) {
	t.Helper()
	err := c.db.QueryRow(`SELECT hits, uniques FROM events_days
		WHERE day = $1::date AND instance = $2 AND path = $3 AND tier = $4 AND device = 'desktop' AND is_bot = $5`,
		sqlDate(day), instance, path, tier, bot).Scan(&hits, &uniques)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, -1
	}
	if err != nil {
		t.Fatal(err)
	}
	return hits, uniques
}

func countWhere(t *testing.T, c *Client, q string, args ...any) int {
	t.Helper()
	var n int
	if err := c.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRollUpEventsMovesWholeOldDays(t *testing.T) {
	c := rollupClient(t)
	v := HashVisitor("x@y.com")
	const path = "__test__rollup/a"
	seedEvent(t, c, utc(2001, 5, 1, 10, 0), rollupInstance, path, "Vintage", v, false)
	seedEvent(t, c, utc(2001, 5, 1, 11, 0), rollupInstance, path, "Vintage", v, false)
	seedEvent(t, c, utc(2001, 5, 1, 12, 0), rollupInstance, path, "Vintage", nil, false)
	seedEvent(t, c, utc(2001, 5, 1, 13, 0), rollupInstance, path, "Any", nil, true)
	seedEvent(t, c, utc(2001, 5, 2, 10, 0), rollupInstance, path, "Vintage", v, false)
	seedEvent(t, c, time.Time{}, rollupInstance, path, "Vintage", v, false)

	cutoff := utc(2001, 5, 2, 15, 0)
	rolled, deleted := rollUp(t, c, cutoff, "__test__rollup/", path)
	if rolled != 2 || deleted != 4 {
		t.Fatalf("rolled %d, deleted %d; want 2 and 4", rolled, deleted)
	}
	may1, may2 := utc(2001, 5, 1, 0, 0), utc(2001, 5, 2, 0, 0)
	if h, u := dayHits(t, c, may1, rollupInstance, path, "Vintage", false); h != 3 || u != 1 {
		t.Errorf("2001-05-01 Vintage: hits %d, uniques %d; want 3 and 1", h, u)
	}
	if h, u := dayHits(t, c, may1, rollupInstance, path, "Any", true); h != 1 || u != 0 {
		t.Errorf("2001-05-01 bot: hits %d, uniques %d; want 1 and 0", h, u)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events_days WHERE day = $1::date AND path = $2`, sqlDate(may2), path); n != 0 {
		t.Errorf("2001-05-02 has %d day rows; the cutoff falls inside it", n)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events WHERE path = $1 AND ts >= $2`, path, may2); n != 2 {
		t.Errorf("events keeps %d rows from 2001-05-02 on, want 2", n)
	}

	rolled, deleted = rollUp(t, c, cutoff, "__test__rollup/", path)
	if rolled != 0 || deleted != 0 {
		t.Errorf("second run: rolled %d, deleted %d; want 0 and 0", rolled, deleted)
	}
	if h, _ := dayHits(t, c, may1, rollupInstance, path, "Vintage", false); h != 3 {
		t.Errorf("after a second run hits = %d, want 3", h)
	}
}

func TestRollUpEventsKeepsARowWithNoInstance(t *testing.T) {
	c := rollupClient(t)
	const path = "__test__rollup/null/a"
	seedEvent(t, c, utc(2001, 5, 10, 9, 0), nil, path, "Vintage", nil, false)
	if rolled, deleted := rollUp(t, c, utc(2001, 5, 11, 0, 0), "__test__rollup/null/", path); rolled != 1 || deleted != 1 {
		t.Fatalf("rolled %d, deleted %d; want 1 and 1", rolled, deleted)
	}
	if h, _ := dayHits(t, c, utc(2001, 5, 10, 0, 0), "", path, "Vintage", false); h != 1 {
		t.Errorf("hits under the empty instance = %d, want 1", h)
	}
}

// Rows older than the bounded labels hold raw paths; only a listed label survives the roll-up.
func TestRollUpEventsFoldsUnlistedPathsIntoOther(t *testing.T) {
	c := rollupClient(t)
	v := HashVisitor("x@y.com")
	const label = "__test__rollup/label/a"
	day := utc(2001, 5, 14, 0, 0)
	seedEvent(t, c, day.Add(9*time.Hour), rollupInstance, label, "Vintage", v, false)
	seedEvent(t, c, day.Add(10*time.Hour), rollupInstance, "__test__rollup/label/debug/some text", "Vintage", v, false)
	seedEvent(t, c, day.Add(11*time.Hour), rollupInstance, "__test__rollup/label/debug/other text", "Vintage", v, false)
	rolled, deleted := rollUp(t, c, day.Add(24*time.Hour), "__test__rollup/label/", label)
	if rolled != 2 || deleted != 3 {
		t.Fatalf("rolled %d, deleted %d; want 2 and 3", rolled, deleted)
	}
	if h, u := dayHits(t, c, day, rollupInstance, label, "Vintage", false); h != 1 || u != 1 {
		t.Errorf("listed path: hits %d, uniques %d; want 1 and 1", h, u)
	}
	if h, u := dayHits(t, c, day, rollupInstance, "other", "Vintage", false); h != 2 || u != 1 {
		t.Errorf("other: hits %d, uniques %d; want 2 and 1, one visitor over both paths", h, u)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events_days WHERE position('text' in path) > 0 OR position('debug' in path) > 0`); n != 0 {
		t.Errorf("events_days keeps %d rows with the raw path's text", n)
	}
}

// A cutoff anywhere in a day, in any zone, means that day's UTC midnight.
func TestWholeDay(t *testing.T) {
	plus5 := time.FixedZone("+05", 5*3600)
	minus8 := time.FixedZone("-08", -8*3600)
	for _, c := range []struct {
		in   time.Time
		want time.Time
	}{
		{utc(2001, 5, 2, 0, 0), utc(2001, 5, 2, 0, 0)},
		{utc(2001, 5, 2, 23, 59), utc(2001, 5, 2, 0, 0)},
		{time.Date(2001, 5, 2, 1, 0, 0, 0, plus5), utc(2001, 5, 1, 0, 0)},
		{time.Date(2001, 5, 2, 20, 0, 0, 0, minus8), utc(2001, 5, 3, 0, 0)},
		{time.Date(2001, 5, 2, 0, 0, 0, 1, time.UTC), utc(2001, 5, 2, 0, 0)},
	} {
		if got := wholeDay(c.in); !got.Equal(c.want) || got.Location() != time.UTC {
			t.Errorf("wholeDay(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Each old day is rolled by a statement of its own, oldest first; a day rolled alone leaves the later ones.
func TestRollUpEventsRollsADayAtATime(t *testing.T) {
	c := rollupClient(t)
	const prefix = "__test__rollup/days/"
	const path = prefix + "a"
	days := []time.Time{utc(2001, 6, 1, 0, 0), utc(2001, 6, 2, 0, 0), utc(2001, 6, 3, 0, 0)}
	for i, d := range days {
		for range i + 1 {
			seedEvent(t, c, d.Add(9*time.Hour), rollupInstance, path, "Vintage", nil, false)
		}
	}
	ctx := context.Background()
	cutoff := utc(2001, 6, 4, 0, 0)

	oldest, ok, err := c.oldestEventDayWhere(ctx, cutoff, prefix)
	if err != nil || !ok || !oldest.Equal(days[0]) {
		t.Fatalf("oldest = %v, %v, %v; want %v", oldest, ok, err, days[0])
	}
	if _, ok, err := c.oldestEventDayWhere(ctx, days[0], prefix); err != nil || ok {
		t.Fatalf("oldest before the first day: %v, %v; want none", ok, err)
	}
	if rolled, deleted, err := c.rollUpEventDayWhere(ctx, oldest, prefix, []string{path}); err != nil || rolled != 1 || deleted != 1 {
		t.Fatalf("first day: rolled %d, deleted %d, %v; want 1 and 1", rolled, deleted, err)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events WHERE path = $1`, path); n != 5 {
		t.Errorf("events keeps %d rows after the first day, want the later days' 5", n)
	}
	if next, _, _ := c.oldestEventDayWhere(ctx, cutoff, prefix); !next.Equal(days[1]) {
		t.Errorf("oldest after the first day = %v, want %v", next, days[1])
	}

	rolled, deleted := rollUp(t, c, cutoff, prefix, path)
	if rolled != 2 || deleted != 5 {
		t.Fatalf("the rest: rolled %d, deleted %d; want 2 and 5", rolled, deleted)
	}
	for i, d := range days {
		if h, _ := dayHits(t, c, d, rollupInstance, path, "Vintage", false); h != int64(i+1) {
			t.Errorf("%s: hits %d, want %d", sqlDate(d), h, i+1)
		}
	}

	// A cancelled context rolls nothing.
	seedEvent(t, c, days[0].Add(time.Hour), rollupInstance, path, "Vintage", nil, false)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := c.rollUpEventsWhere(cancelled, cutoff, prefix, []string{path}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled run: %v, want context.Canceled", err)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events WHERE path = $1`, path); n != 1 {
		t.Errorf("events keeps %d rows after a cancelled run, want 1", n)
	}
}

func TestRollUpEventsDropsAPIPaths(t *testing.T) {
	c := rollupClient(t)
	const path = "/api/__test__rollup/search/some text"
	seedEvent(t, c, utc(2001, 5, 12, 9, 0), rollupInstance, path, "api", nil, false)
	if rolled, deleted := rollUp(t, c, utc(2001, 5, 13, 0, 0), "/api/__test__rollup/"); rolled != 0 || deleted != 1 {
		t.Fatalf("rolled %d, deleted %d; want 0 and 1", rolled, deleted)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events WHERE path = $1`, path); n != 0 {
		t.Errorf("events keeps %d API rows, want 0", n)
	}
	if n := countWhere(t, c, `SELECT count(*) FROM events_days WHERE path = $1`, path); n != 0 {
		t.Errorf("events_days has %d API rows, want 0", n)
	}
}
