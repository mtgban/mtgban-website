package observability

import (
	"context"
	"fmt"
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
	})
	return c, inst
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
