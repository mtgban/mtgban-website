package observability

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFeatureErrorsStatement(t *testing.T) {
	joined := strings.Join(featureStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS feature_errors",
		"PRIMARY KEY (day, instance, device, build, script, line, class)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("feature schema lacks %q", want)
		}
	}
	_, ddl, _ := strings.Cut(joined, "feature_errors")
	for _, never := range []string{"message", "stack", "url", "visitor", "tier"} {
		if strings.Contains(ddl, never) {
			t.Errorf("feature_errors must not have a %s column", never)
		}
	}
}

// The cap's lock is a transaction lock: a session lock does not survive PgBouncer.
func TestErrorCapLockIsATransactionLock(t *testing.T) {
	if !strings.Contains(errorCapLockSQL, "pg_advisory_xact_lock(") {
		t.Errorf("the cap lock is %q, want pg_advisory_xact_lock", errorCapLockSQL)
	}
	src, err := os.ReadFile("store_errors.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"pg_advisory_lock(", "pg_try_advisory_lock(", "pg_advisory_unlock"} {
		if strings.Contains(string(src), banned) {
			t.Errorf("store_errors.go uses the session lock call %s", banned)
		}
	}
}

// errorTestClient is testClient with this test's feature_errors rows deleted on cleanup.
func errorTestClient(t *testing.T) (*Client, string) {
	t.Helper()
	c := testClient(t)
	if !c.FeaturesReady() {
		t.Skip("feature tables not ready")
	}
	instance := "test-" + t.Name()
	t.Cleanup(func() {
		_, _ = c.db.Exec(`DELETE FROM feature_errors WHERE instance LIKE $1 || '%'`, instance)
	})
	return c, instance
}

// errRows builds desktop navbar.js TypeError rows for lines from to to-1.
func errRows(day time.Time, from, to int) []ErrorRow {
	var out []ErrorRow
	for i := from; i < to; i++ {
		out = append(out, ErrorRow{Day: day, Device: "desktop", Build: strings.Repeat("ab", 20), Script: "navbar.js", Class: "TypeError", Line: i, N: 1})
	}
	return out
}

func countRows(t *testing.T, c *Client, instance string, day time.Time) int {
	t.Helper()
	n, err := c.CountErrorRows(context.Background(), instance, day)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func upsertErrs(t *testing.T, c *Client, instance string, rows []ErrorRow) int {
	t.Helper()
	refused, err := c.UpsertErrors(context.Background(), instance, rows)
	if err != nil {
		t.Fatal(err)
	}
	return refused
}

func TestUpsertErrorsCapsADayAt200Rows(t *testing.T) {
	c, instance := errorTestClient(t)
	ctx := context.Background()
	today := time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC)

	if refused := upsertErrs(t, c, instance, errRows(today, 1, 206)); refused != 5 {
		t.Errorf("refused %d, want 5", refused)
	}
	if n := countRows(t, c, instance, today); n != 200 {
		t.Errorf("%d rows, want 200", n)
	}

	more := errRows(today, 1, 2)
	more[0].N = 3
	more = append(more, errRows(today, 999, 1000)...)
	if refused := upsertErrs(t, c, instance, more); refused != 1 {
		t.Errorf("refused %d, want 1 (the new line only)", refused)
	}
	var n int64
	if err := c.db.QueryRowContext(ctx, `SELECT n FROM feature_errors WHERE instance = $1 AND line = 1`, instance).Scan(&n); err != nil || n != 4 {
		t.Errorf("line 1 n = %d (%v), want 4", n, err)
	}
	var absent int
	if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM feature_errors WHERE instance = $1 AND line = 999`, instance).Scan(&absent); err != nil || absent != 0 {
		t.Errorf("line 999 has %d rows (%v), want none", absent, err)
	}

	if refused := upsertErrs(t, c, instance, errRows(today.AddDate(0, 0, 1), 1, 2)); refused != 0 {
		t.Errorf("the next day refused %d, want 0", refused)
	}

	if refused := upsertErrs(t, c, instance+"-b", errRows(today, 1, 206)); refused != 5 {
		t.Errorf("a second instance refused %d, want 5", refused)
	}
	if n := countRows(t, c, instance, today); n != 200 {
		t.Errorf("the first instance has %d rows, want 200 untouched", n)
	}
}

func TestConcurrentErrorWritersShareTheCap(t *testing.T) {
	c, instance := errorTestClient(t)
	day := time.Date(2001, 2, 4, 0, 0, 0, 0, time.UTC)
	refused := make([]int, 4)
	errs := make([]error, 4)
	var wg sync.WaitGroup
	for i := range refused {
		wg.Go(func() {
			refused[i], errs[i] = c.UpsertErrors(context.Background(), instance, errRows(day, i*100, (i+1)*100))
		})
	}
	wg.Wait()
	sum := 0
	for i := range refused {
		if errs[i] != nil {
			t.Errorf("writer %d: %v", i, errs[i])
		}
		sum += refused[i]
	}
	if sum != 200 {
		t.Errorf("refused %d in all, want 200", sum)
	}
	if n := countRows(t, c, instance, day); n != 200 {
		t.Errorf("%d rows, want 200", n)
	}
}

func TestTopErrors(t *testing.T) {
	c, instance := errorTestClient(t)
	ctx := context.Background()
	day1 := time.Date(2001, 3, 1, 0, 0, 0, 0, time.UTC)
	day3 := day1.AddDate(0, 0, 2)
	a, b := strings.Repeat("aa", 20), strings.Repeat("bb", 20)
	upsertErrs(t, c, instance, []ErrorRow{
		{Day: day1, Device: "desktop", Build: a, Script: "navbar.js", Line: 10, Class: "TypeError", N: 5},
		{Day: day3, Device: "mobile", Build: a, Script: "navbar.js", Line: 10, Class: "TypeError", N: 2},
		{Day: day1, Device: "desktop", Build: a, Script: "utils.js", Line: 7, Class: "RangeError", N: 9},
		{Day: day1, Device: "desktop", Build: b, Script: "navbar.js", Line: 10, Class: "TypeError", N: 50},
	})

	got, err := c.TopErrors(ctx, instance, a, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	u, nb := got[0], got[1]
	if u.Script != "utils.js" || u.Line != 7 || u.Class != "RangeError" || u.N != 9 || u.Desktop != 9 || u.Mobile != 0 {
		t.Errorf("first row %+v", u)
	}
	if nb.Script != "navbar.js" || nb.Line != 10 || nb.Class != "TypeError" || nb.N != 7 || nb.Desktop != 5 || nb.Mobile != 2 {
		t.Errorf("second row %+v", nb)
	}
	if !nb.FirstDay.Equal(day1) || !nb.LastDay.Equal(day3) {
		t.Errorf("days %v to %v, want %v to %v", nb.FirstDay, nb.LastDay, day1, day3)
	}

	one, err := c.TopErrors(ctx, instance, a, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 {
		t.Errorf("limit 1 gave %d rows", len(one))
	}
}

// A script and class first seen in an older build keeps that day across builds and lines.
func TestErrorFirstSeen(t *testing.T) {
	c, instance := errorTestClient(t)
	ctx := context.Background()
	day1 := time.Date(2001, 4, 1, 0, 0, 0, 0, time.UTC)
	day5 := day1.AddDate(0, 0, 4)
	a, b := strings.Repeat("aa", 20), strings.Repeat("bb", 20)
	upsertErrs(t, c, instance, []ErrorRow{
		{Day: day1, Device: "desktop", Build: a, Script: "navbar.js", Line: 10, Class: "TypeError", N: 5},
		{Day: day5, Device: "mobile", Build: b, Script: "navbar.js", Line: 12, Class: "TypeError", N: 2},
		{Day: day5, Device: "desktop", Build: b, Script: "utils.js", Line: 7, Class: "RangeError", N: 9},
	})
	upsertErrs(t, c, instance+"-b", []ErrorRow{
		{Day: day5, Device: "desktop", Build: b, Script: "navbar.js", Line: 10, Class: "TypeError", N: 1},
	})
	got, err := c.ErrorFirstSeen(ctx, instance, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	u, nb := got[0], got[1]
	if u.Script != "utils.js" || u.Class != "RangeError" || u.Line != 0 || u.N != 9 || !u.FirstDay.Equal(day5) {
		t.Errorf("first row %+v", u)
	}
	if nb.Script != "navbar.js" || nb.Class != "TypeError" || nb.Line != 0 || nb.N != 7 || nb.Desktop != 5 || nb.Mobile != 2 ||
		!nb.FirstDay.Equal(day1) || !nb.LastDay.Equal(day5) {
		t.Errorf("second row %+v, want navbar.js TypeError first seen %v in build a", nb, day1)
	}
	if one, err := c.ErrorFirstSeen(ctx, instance, 1); err != nil || len(one) != 1 {
		t.Errorf("limit 1 gave %d rows, %v", len(one), err)
	}
}

func TestNewestErrorBuild(t *testing.T) {
	c, instance := errorTestClient(t)
	ctx := context.Background()
	day1 := time.Date(2001, 3, 10, 0, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	a, b, made := strings.Repeat("aa", 20), strings.Repeat("bb", 20), strings.Repeat("cc", 20)
	upsertErrs(t, c, instance, []ErrorRow{
		{Day: day1, Device: "desktop", Build: a, Script: "navbar.js", Line: 1, Class: "Error", N: 100},
		{Day: day2, Device: "desktop", Build: b, Script: "navbar.js", Line: 1, Class: "Error", N: 3},
		{Day: day2, Device: "desktop", Build: made, Script: "navbar.js", Line: 2, Class: "Error", N: 1},
	})
	if got, err := c.NewestErrorBuild(ctx, instance); err != nil || got != b {
		t.Errorf("NewestErrorBuild = %q, %v; want %q", got, err, b)
	}
	if got, err := c.NewestErrorBuild(ctx, instance+"-none"); err != nil || got != "" {
		t.Errorf("an instance with no rows: %q, %v", got, err)
	}
}

func TestPruneErrors(t *testing.T) {
	c, instance := errorTestClient(t)
	ctx := context.Background()
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	kept := time.Date(2001, 4, 10, 0, 0, 0, 0, time.UTC)
	upsertErrs(t, c, instance, append(errRows(old, 1, 2), errRows(kept, 1, 2)...))
	if _, err := c.PruneErrors(ctx, time.Date(2001, 1, 10, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, c, instance, old); n != 0 {
		t.Errorf("the old day kept %d rows", n)
	}
	if n := countRows(t, c, instance, kept); n != 1 {
		t.Errorf("the kept day has %d rows, want 1", n)
	}
}
