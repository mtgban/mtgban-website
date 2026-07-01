package timeseries

import (
	"context"
	"os"
	"strconv"
	"testing"
)

// TestTCGPricesLive exercises the tcg_prices code paths end to end against a
// real Postgres, verifying the exact production flow: EnsureTCGSchema's
// multi-statement DDL via lib/pq, the batched upsert, the read helpers, and the
// per-category date cursors.
//
// It is skipped unless TCGLIVE_HOST is set, so ordinary `go test` and CI never
// touch a database. It writes only under a sentinel category id and deletes its
// rows on completion, so it never collides with real data.
//
// Run it with, e.g.:
//
//	TCGLIVE_HOST=... TCGLIVE_PORT=5432 TCGLIVE_USER=... TCGLIVE_PASSWORD=... \
//	TCGLIVE_DBNAME=card_prices TCGLIVE_SSLMODE=require \
//	go test ./timeseries/ -run TestTCGPricesLive -v
const liveSentinelCategory = 999001

func liveConfig(t *testing.T) SqlConfig {
	t.Helper()
	host := os.Getenv("TCGLIVE_HOST")
	if host == "" {
		t.Skip("TCGLIVE_HOST not set; skipping live DB integration test")
	}
	port, _ := strconv.Atoi(os.Getenv("TCGLIVE_PORT"))
	if port == 0 {
		port = 5432
	}
	return SqlConfig{
		Host:     host,
		Port:     port,
		User:     os.Getenv("TCGLIVE_USER"),
		Password: os.Getenv("TCGLIVE_PASSWORD"),
		DBName:   os.Getenv("TCGLIVE_DBNAME"),
		SSLMode:  os.Getenv("TCGLIVE_SSLMODE"),
	}
}

func f(v float64) *float64 { return &v }

func TestTCGPricesLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Cleanup runs LIFO, so register Close first (it runs last): the row
	// cleanup below must still have an open connection when it fires.
	t.Cleanup(func() { _ = c.Close() })

	if err := c.EnsureTCGSchema(ctx); err != nil {
		t.Fatalf("EnsureTCGSchema: %v", err)
	}

	// Start clean and delete our sentinel rows when the test finishes.
	clear := func() {
		if _, err := c.db.ExecContext(ctx, `DELETE FROM tcg_prices WHERE category_id = $1`, liveSentinelCategory); err != nil {
			t.Errorf("cleanup delete: %v", err)
		}
	}
	clear()
	t.Cleanup(clear)

	const product = 111222333
	rows := []TCGPriceRow{
		{Date: "2024-02-08", CategoryID: liveSentinelCategory, ProductID: product, SubTypeName: "Normal",
			LowPrice: f(1.00), MidPrice: f(2.00), HighPrice: f(99.00), MarketPrice: f(1.50)}, // DirectLow left nil
		{Date: "2024-02-08", CategoryID: liveSentinelCategory, ProductID: product, SubTypeName: "Foil",
			MarketPrice: f(10.00)},
		{Date: "2024-02-09", CategoryID: liveSentinelCategory, ProductID: product, SubTypeName: "Normal",
			MarketPrice: f(1.75)},
	}
	n, err := c.UpsertTCGPrices(ctx, rows, 0)
	if err != nil {
		t.Fatalf("UpsertTCGPrices: %v", err)
	}
	if n != 3 {
		t.Errorf("upsert affected %d rows, want 3", n)
	}

	// Latest for (product, Normal) is the 2024-02-09 row.
	latest, err := c.GetLatestTCGPrice(ctx, liveSentinelCategory, product, "Normal")
	if err != nil {
		t.Fatalf("GetLatestTCGPrice: %v", err)
	}
	if latest.Date != "2024-02-09" || latest.MarketPrice == nil || *latest.MarketPrice != 1.75 {
		t.Errorf("latest = %+v, want date 2024-02-09 market 1.75", latest)
	}

	// History for (product, Normal) is two rows, newest first, and the null
	// DirectLowPrice must round-trip as nil (not 0).
	hist, err := c.GetTCGPriceHistory(ctx, liveSentinelCategory, product, "Normal")
	if err != nil {
		t.Fatalf("GetTCGPriceHistory: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history has %d rows, want 2: %+v", len(hist), hist)
	}
	if hist[0].Date != "2024-02-09" || hist[1].Date != "2024-02-08" {
		t.Errorf("history order = [%s, %s], want [2024-02-09, 2024-02-08]", hist[0].Date, hist[1].Date)
	}
	if hist[1].DirectLowPrice != nil {
		t.Errorf("expected nil DirectLowPrice on 2024-02-08 row, got %v", *hist[1].DirectLowPrice)
	}

	// Date cursors span both dates across all products/sub-types in the category.
	earliest, ok, err := c.GetTCGEarliestDate(ctx, liveSentinelCategory)
	if err != nil || !ok {
		t.Fatalf("GetTCGEarliestDate: ok=%v err=%v", ok, err)
	}
	if got := earliest.Format("2006-01-02"); got != "2024-02-08" {
		t.Errorf("earliest = %s, want 2024-02-08", got)
	}
	newest, ok, err := c.GetTCGLatestDate(ctx, liveSentinelCategory)
	if err != nil || !ok {
		t.Fatalf("GetTCGLatestDate: ok=%v err=%v", ok, err)
	}
	if got := newest.Format("2006-01-02"); got != "2024-02-09" {
		t.Errorf("latest date = %s, want 2024-02-09", got)
	}

	// Re-upserting is idempotent (no duplicate rows) and overwrites in place.
	rows[2].MarketPrice = f(2.00)
	if _, err := c.UpsertTCGPrices(ctx, rows, 0); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	hist2, err := c.GetTCGPriceHistory(ctx, liveSentinelCategory, product, "Normal")
	if err != nil {
		t.Fatalf("GetTCGPriceHistory (2): %v", err)
	}
	if len(hist2) != 2 {
		t.Errorf("history grew to %d rows after re-upsert, want 2 (no duplicates)", len(hist2))
	}
	latest2, err := c.GetLatestTCGPrice(ctx, liveSentinelCategory, product, "Normal")
	if err != nil {
		t.Fatalf("GetLatestTCGPrice (2): %v", err)
	}
	if latest2.MarketPrice == nil || *latest2.MarketPrice != 2.00 {
		t.Errorf("overwrite failed: latest market = %v, want 2.00", latest2.MarketPrice)
	}

	// Cursor for an untouched category reports no data.
	if _, ok, err := c.GetTCGLatestDate(ctx, liveSentinelCategory+1); err != nil || ok {
		t.Errorf("empty category cursor: ok=%v err=%v, want ok=false nil", ok, err)
	}
}
