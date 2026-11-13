package observability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpsertMinutesRefusesAnOversizedBatch(t *testing.T) {
	c := &Client{}
	err := c.UpsertMinutes(context.Background(), time.Now(), make([]Row, 6554))
	if err == nil {
		t.Fatal("6554 rows is over the parameter limit")
	}
}

// featureClient is a testClient whose rows for the test's instance are deleted on cleanup.
func featureClient(t *testing.T) (*Client, string) {
	t.Helper()
	c := testClient(t)
	inst := "test-" + t.Name()
	t.Cleanup(func() {
		_, _ = c.db.Exec("DELETE FROM feature_events WHERE instance = $1", inst)
		_, _ = c.db.Exec("DELETE FROM feature_days WHERE instance = $1", inst)
	})
	return c, inst
}

// dayN is the n of the instance's day row for name and value, or -1 when there is none.
func dayN(t *testing.T, c *Client, instance string, day time.Time, name, value string) int64 {
	t.Helper()
	var n int64
	err := c.db.QueryRow(`SELECT n FROM feature_days WHERE instance = $1 AND day = $2::date AND name = $3 AND value = $4`,
		instance, sqlDate(day), name, value).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return -1
	}
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// minuteCount counts the instance's minute rows at ts.
func minuteCount(t *testing.T, c *Client, instance string, ts time.Time) int {
	t.Helper()
	var n int
	if err := c.db.QueryRow(`SELECT count(*) FROM feature_events WHERE instance = $1 AND ts = $2`, instance, ts).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func utc(y int, m time.Month, d, h, mi int) time.Time {
	return time.Date(y, m, d, h, mi, 0, 0, time.UTC)
}

func upsert(t *testing.T, c *Client, minute time.Time, rows ...Row) {
	t.Helper()
	if err := c.UpsertMinutes(context.Background(), minute, rows); err != nil {
		t.Fatal(err)
	}
}

func fold(t *testing.T, c *Client, day time.Time) int64 {
	t.Helper()
	n, err := c.FoldDay(context.Background(), day)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFoldDaySumsADaysMinutes(t *testing.T) {
	c, inst := featureClient(t)
	a := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", Value: "a", N: 2}
	b := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", Value: "b", N: 1}
	upsert(t, c, utc(2001, 1, 2, 0, 0), a)
	a.N = 3
	upsert(t, c, utc(2001, 1, 2, 23, 59), a, b)
	a.N = 100
	upsert(t, c, utc(2001, 1, 3, 0, 0), a)

	fold(t, c, utc(2001, 1, 2, 15, 4))
	day := utc(2001, 1, 2, 0, 0)
	if n := dayN(t, c, inst, day, "search.x", "a"); n != 5 {
		t.Errorf("a = %d, want 5", n)
	}
	if n := dayN(t, c, inst, day, "search.x", "b"); n != 1 {
		t.Errorf("b = %d, want 1", n)
	}
	if n := dayN(t, c, inst, utc(2001, 1, 3, 0, 0), "search.x", "a"); n != -1 {
		t.Errorf("2001-01-03 has a day row (n %d); only 2001-01-02 was folded", n)
	}
}

func TestFoldDayTwiceGivesTheSameTotals(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 1, 5, 0, 0)
	row := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", N: 4}
	upsert(t, c, day.Add(time.Hour), row)
	fold(t, c, day)
	fold(t, c, day)
	if n := dayN(t, c, inst, day, "search.x", ""); n != 4 {
		t.Fatalf("after two folds n = %d, want 4", n)
	}
	row.N = 1
	upsert(t, c, day.Add(2*time.Hour), row)
	fold(t, c, day)
	if n := dayN(t, c, inst, day, "search.x", ""); n != 5 {
		t.Fatalf("after a late minute n = %d, want 5", n)
	}
}

func TestFoldDayKeepsDimensionsApart(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 1, 7, 0, 0)
	var rows []Row
	for _, device := range []string{"desktop", "mobile"} {
		for _, signed := range []bool{false, true} {
			rows = append(rows, Row{Dims: Dims{Instance: inst, Device: device, Signed: signed}, Name: "search.x", Value: "v", N: 1})
		}
	}
	upsert(t, c, day, rows...)
	fold(t, c, day)
	var count int
	if err := c.db.QueryRow(`SELECT count(*) FROM feature_days WHERE instance = $1 AND day = $2::date`, inst, sqlDate(day)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("day rows = %d, want 4", count)
	}
}

func TestFoldDayLeavesADayWithNoMinutesAlone(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 1, 9, 0, 0)
	_, err := c.db.Exec(`INSERT INTO feature_days (day, instance, tier, device, signed, name, n)
		VALUES ($1::date, $2, '', 'desktop', false, 'search.x', 7)`, sqlDate(day), inst)
	if err != nil {
		t.Fatal(err)
	}
	if n := fold(t, c, day); n != 0 {
		t.Errorf("FoldDay = %d, want 0", n)
	}
	if n := dayN(t, c, inst, day, "search.x", ""); n != 7 {
		t.Errorf("n = %d, want 7", n)
	}
}

func TestPruneMinutesDeletesOnlyOlderRows(t *testing.T) {
	c, inst := featureClient(t)
	older, newer := utc(2001, 3, 1, 12, 0), utc(2001, 3, 20, 12, 0)
	row := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", N: 1}
	upsert(t, c, older, row)
	upsert(t, c, newer, row)
	n, err := c.PruneMinutes(context.Background(), utc(2001, 3, 10, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("PruneMinutes = %d, want at least 1", n)
	}
	if got := minuteCount(t, c, inst, older); got != 0 {
		t.Errorf("older minute rows = %d, want 0", got)
	}
	if got := minuteCount(t, c, inst, newer); got != 1 {
		t.Errorf("newer minute rows = %d, want 1", got)
	}
}

func TestPruneMinutesKeepsThePartDay(t *testing.T) {
	c, inst := featureClient(t)
	whole, part := utc(2001, 3, 9, 12, 0), utc(2001, 3, 10, 9, 0)
	row := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", N: 1}
	upsert(t, c, whole, row)
	upsert(t, c, part, row)
	if _, err := c.PruneMinutes(context.Background(), utc(2001, 3, 10, 13, 0)); err != nil {
		t.Fatal(err)
	}
	if got := minuteCount(t, c, inst, whole); got != 0 {
		t.Errorf("2001-03-09 minute rows = %d, want 0", got)
	}
	if got := minuteCount(t, c, inst, part); got != 1 {
		t.Errorf("2001-03-10 minute rows = %d, want 1: the cutoff falls inside that day", got)
	}
}

func TestReplaceDayRowsRefusesAnOversizedBatch(t *testing.T) {
	if err := (&Client{}).ReplaceDayRows(context.Background(), time.Now(), "i", []string{""}, make([]Row, 6554)); err == nil {
		t.Fatal("6554 rows is over the parameter limit")
	}
}

func TestReplaceDayRowsWithNothingIsANoOp(t *testing.T) {
	if err := (&Client{}).ReplaceDayRows(context.Background(), time.Now(), "i", nil, nil); err != nil {
		t.Fatal(err)
	}
}

// The zero Client has no database, so a refusal that reached it would panic.
func TestReplaceDayRowsRefusesARowItDoesNotDelete(t *testing.T) {
	ok := Row{Dims: Dims{Instance: "i", Device: "job"}, Name: "stock.x", N: 1}
	otherName, otherInstance := ok, ok
	otherName.Name = "stock.y"
	otherInstance.Instance = "j"
	for _, r := range []Row{otherName, otherInstance} {
		if err := (&Client{}).ReplaceDayRows(context.Background(), time.Now(), "i", []string{"stock.x"}, []Row{ok, r}); err == nil {
			t.Errorf("row %+v is outside instance i and names [stock.x]", r)
		}
	}
	if err := (&Client{}).ReplaceDayRows(context.Background(), time.Now(), "i", nil, []Row{ok}); err == nil {
		t.Error("rows with no names to replace")
	}
}

func TestReplaceDayRowsRefusesADuplicateKey(t *testing.T) {
	a := Row{Dims: Dims{Instance: "i", Device: "job"}, Name: "stock.x", Value: "v", N: 1}
	b := a
	b.N = 2
	err := (&Client{}).ReplaceDayRows(context.Background(), time.Now(), "i", []string{"stock.x"}, []Row{a, b})
	if err == nil || !strings.Contains(err.Error(), "stock.x") || strings.Contains(err.Error(), `"v"`) {
		t.Fatalf("err = %v, want a duplicate error naming stock.x and not its value", err)
	}
}

func replaceDay(t *testing.T, c *Client, day time.Time, instance string, names []string, rows ...Row) {
	t.Helper()
	if err := c.ReplaceDayRows(context.Background(), day, instance, names, rows); err != nil {
		t.Fatal(err)
	}
}

var stockXY = []string{"stock.x", "stock.y"}

func TestReplaceDayRowsReplaces(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 4, 1, 0, 0)
	dims := Dims{Instance: inst, Device: "job"}
	replaceDay(t, c, day.Add(5*time.Hour), inst, stockXY,
		Row{Dims: dims, Name: "stock.x", Value: "1-9", N: 5},
		Row{Dims: dims, Name: "stock.x", Value: "10+", N: 2},
		Row{Dims: dims, Name: "stock.y", N: 9})
	replaceDay(t, c, day, inst, []string{"stock.x"}, Row{Dims: dims, Name: "stock.x", Value: "1-9", N: 6})
	if n := dayN(t, c, inst, day, "stock.x", "1-9"); n != 6 {
		t.Errorf("stock.x 1-9 = %d, want 6", n)
	}
	if n := dayN(t, c, inst, day, "stock.x", "10+"); n != -1 {
		t.Errorf("stock.x 10+ = %d, want no row", n)
	}
	if n := dayN(t, c, inst, day, "stock.y", ""); n != 9 {
		t.Errorf("stock.y = %d, want 9: it was not in the second run's names", n)
	}
}

func TestReplaceDayRowsLeavesOtherDaysAndInstances(t *testing.T) {
	c, inst := featureClient(t)
	other := inst + "-other"
	t.Cleanup(func() { _, _ = c.db.Exec("DELETE FROM feature_days WHERE instance = $1", other) })
	day, next := utc(2001, 4, 1, 0, 0), utc(2001, 4, 2, 0, 0)
	row := func(instance string, n int64) Row {
		return Row{Dims: Dims{Instance: instance, Device: "job"}, Name: "stock.x", Value: "1-9", N: n}
	}
	replaceDay(t, c, day, other, stockXY, row(other, 3))
	replaceDay(t, c, next, inst, stockXY, row(inst, 4))
	replaceDay(t, c, day, inst, stockXY, row(inst, 5))
	replaceDay(t, c, day, inst, stockXY, row(inst, 6))
	if n := dayN(t, c, other, day, "stock.x", "1-9"); n != 3 {
		t.Errorf("other instance = %d, want 3", n)
	}
	if n := dayN(t, c, inst, next, "stock.x", "1-9"); n != 4 {
		t.Errorf("next day = %d, want 4", n)
	}
	if n := dayN(t, c, inst, day, "stock.x", "1-9"); n != 6 {
		t.Errorf("replaced day = %d, want 6", n)
	}
}

func TestReplaceDayRowsDropsANameWithNoRows(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 4, 3, 0, 0)
	dims := Dims{Instance: inst, Device: "job"}
	replaceDay(t, c, day, inst, stockXY,
		Row{Dims: dims, Name: "stock.x", N: 1},
		Row{Dims: dims, Name: "stock.y", Value: "a", N: 2},
		Row{Dims: dims, Name: "stock.y", Value: "b", N: 3})
	replaceDay(t, c, day, inst, stockXY, Row{Dims: dims, Name: "stock.x", N: 4})
	if n := dayN(t, c, inst, day, "stock.x", ""); n != 4 {
		t.Errorf("stock.x = %d, want 4", n)
	}
	for _, v := range []string{"a", "b"} {
		if n := dayN(t, c, inst, day, "stock.y", v); n != -1 {
			t.Errorf("stock.y %s = %d, want no row", v, n)
		}
	}
	replaceDay(t, c, day, inst, stockXY)
	if n := dayN(t, c, inst, day, "stock.x", ""); n != -1 {
		t.Errorf("stock.x = %d after a run with no rows, want no row", n)
	}
}

func TestReplaceDayRowsKeepsTheOldRowsOnAFailure(t *testing.T) {
	c, inst := featureClient(t)
	day := utc(2001, 4, 4, 0, 0)
	dims := Dims{Instance: inst, Device: "job"}
	replaceDay(t, c, day, inst, stockXY, Row{Dims: dims, Name: "stock.x", N: 7})
	// Postgres refuses a NUL byte in text, so the insert fails after the delete ran.
	bad := Row{Dims: dims, Name: "stock.y", Value: "\x00", N: 1}
	if err := c.ReplaceDayRows(context.Background(), day, inst, stockXY, []Row{{Dims: dims, Name: "stock.x", N: 8}, bad}); err == nil {
		t.Fatal("an insert with a NUL byte succeeded")
	}
	if n := dayN(t, c, inst, day, "stock.x", ""); n != 7 {
		t.Errorf("stock.x = %d after a failed replacement, want 7", n)
	}
}

func TestMinuteDaysBefore(t *testing.T) {
	c, inst := featureClient(t)
	row := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.x", N: 1}
	upsert(t, c, utc(2001, 2, 3, 23, 30), row)
	upsert(t, c, utc(2001, 2, 4, 0, 10), row)
	d3, d4 := utc(2001, 2, 3, 0, 0), utc(2001, 2, 4, 0, 0)
	has := func(days []time.Time, d time.Time) bool {
		return slices.ContainsFunc(days, d.Equal)
	}

	days, err := c.MinuteDaysBefore(context.Background(), utc(2001, 2, 5, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !has(days, d3) || !has(days, d4) {
		t.Errorf("days before 2001-02-05 = %v, want 2001-02-03 and 2001-02-04", days)
	}
	if !slices.IsSortedFunc(days, time.Time.Compare) {
		t.Errorf("days %v are not ascending", days)
	}

	days, err = c.MinuteDaysBefore(context.Background(), d4)
	if err != nil {
		t.Fatal(err)
	}
	if !has(days, d3) || has(days, d4) {
		t.Errorf("days before 2001-02-04 = %v, want 2001-02-03 and not 2001-02-04", days)
	}
}

func TestIntegrationUpsertMinutesAdds(t *testing.T) {
	c, inst := featureClient(t)
	ctx := context.Background()
	minute := time.Now().UTC().Truncate(time.Minute)
	row := Row{Dims: Dims{Instance: inst, Tier: "Vintage", Device: "desktop"}, Scope: "search", Name: "test.name", Value: "v", N: 2}
	if err := c.UpsertMinutes(ctx, minute, []Row{row}); err != nil {
		t.Fatal(err)
	}
	row.N = 3
	if err := c.UpsertMinutes(ctx, minute, []Row{row}); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := c.db.QueryRow("SELECT n FROM feature_events WHERE instance = $1", inst).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
}

func TestIntegrationUpsertMinutesKeepsDimensionsApart(t *testing.T) {
	c, inst := featureClient(t)
	minute := time.Now().UTC().Truncate(time.Minute)
	a := Row{Dims: Dims{Instance: inst, Device: "desktop", Signed: true}, Name: "test.name", N: 1}
	b := a
	b.Signed = false
	if err := c.UpsertMinutes(context.Background(), minute, []Row{b, a}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := c.db.QueryRow("SELECT count(*) FROM feature_events WHERE instance = $1", inst).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows = %d, want 2", count)
	}
}

func TestIntegrationConcurrentWritersAdd(t *testing.T) {
	c, inst := featureClient(t)
	minute := time.Now().UTC().Truncate(time.Minute)
	rows := make([]Row, 50)
	for i := range rows {
		rows[i] = Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "test.name", Value: fmt.Sprintf("v%02d", i), N: 1}
	}
	const writers = 8
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			errs <- c.UpsertMinutes(context.Background(), minute, rows)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
	}
	var count, bad int
	err := c.db.QueryRow("SELECT count(*), count(*) FILTER (WHERE n <> $2) FROM feature_events WHERE instance = $1", inst, writers).Scan(&count, &bad)
	if err != nil {
		t.Fatal(err)
	}
	if count != 50 || bad != 0 {
		t.Fatalf("rows = %d, off-count = %d; want 50 rows all at %d", count, bad, writers)
	}
}

func TestIntegrationUpsertBindsTheMinute(t *testing.T) {
	c, inst := featureClient(t)
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	row := Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "test.name", N: 1}
	if err := c.UpsertMinutes(context.Background(), minute, []Row{row}); err != nil {
		t.Fatal(err)
	}
	var ts time.Time
	if err := c.db.QueryRow("SELECT ts FROM feature_events WHERE instance = $1", inst).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if !ts.Equal(minute) {
		t.Fatalf("ts = %v, want %v", ts, minute)
	}
}

// Every field is distinct, so a swapped column pair cannot read back right.
func TestIntegrationUpsertWritesEveryColumn(t *testing.T) {
	c, inst := featureClient(t)
	minute := time.Now().UTC().Truncate(time.Minute)
	want := Row{
		Dims:  Dims{Instance: inst, Tier: "col-tier", Device: "col-device", Signed: true, Bot: true},
		Scope: "col-scope", Name: "col.name", Value: "col-value", N: 7,
	}
	if err := c.UpsertMinutes(context.Background(), minute, []Row{want}); err != nil {
		t.Fatal(err)
	}
	var got Row
	var ts time.Time
	err := c.db.QueryRow(`SELECT ts, instance, tier, device, signed, is_bot, scope, name, value, n
		FROM feature_events WHERE instance = $1`, inst).
		Scan(&ts, &got.Instance, &got.Tier, &got.Device, &got.Signed, &got.Bot, &got.Scope, &got.Name, &got.Value, &got.N)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !ts.Equal(minute) {
		t.Fatalf("read back %+v at %v, want %+v at %v", got, ts, want, minute)
	}
}
