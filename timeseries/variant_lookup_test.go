package timeseries

import (
	"context"
	"database/sql"
	"testing"
)

// Resolving a ban_id is the hottest thing a chart page does, and the warm pass
// has already read that exact row. A hit must not reach the network - which is
// worth a round-trip, not a millisecond, whenever the app and the archive are
// in different regions.
func TestLookupVariantAnswersFromTheWarmedMap(t *testing.T) {
	// No server behind it: a query would fail, so a successful lookup is proof
	// the warmed map answered.
	db, err := sql.Open("postgres", "postgres://127.0.0.1:1/nothing?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := &Client{db: db}

	want := VariantInfo{BanID: 13456, MtgjsonUUID: "7c3ea479-e463-58e7-b1b0-b217c77dae79", IsFoil: true}
	warmed := map[int64]VariantInfo{want.BanID: want}
	c.variants.byBanID.Store(&warmed)

	got, ok, err := c.LookupVariant(context.Background(), want.BanID)
	if err != nil || !ok {
		t.Fatalf("warmed lookup = %v/%v, want a hit", ok, err)
	}
	if got != want {
		t.Errorf("warmed lookup = %+v, want %+v", got, want)
	}

	// A ban_id minted since the warm still reaches the server, and says so when
	// there is none.
	if _, ok, err := c.LookupVariant(context.Background(), 99999); ok || err == nil {
		t.Errorf("unwarmed lookup = %v/%v, want it to reach the server and fail", ok, err)
	}
}

// A client that never warmed - charts on a deployment with no long-form reads,
// or a request that arrives before startup finishes - must not dereference a
// map that was never built.
func TestLookupVariantWithoutAWarmPass(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://127.0.0.1:1/nothing?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := &Client{db: db}

	if c.variants.byBanID.Load() != nil {
		t.Fatal("a fresh client should carry no warmed map")
	}
	if _, ok, err := c.LookupVariant(context.Background(), 1); ok || err == nil {
		t.Errorf("lookup = %v/%v, want the query path and its error", ok, err)
	}
}
