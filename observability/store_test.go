// observability/store_test.go
package observability

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// testClient connects to the observability DB described by env vars. It skips
// unless OBSERVABILITY_TEST is set. Inserted rows use a sentinel path and are
// deleted on cleanup so the test is safe to run against the shared DB.
func testClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("OBSERVABILITY_TEST") == "" {
		t.Skip("OBSERVABILITY_TEST not set; skipping DB integration test")
	}
	port, _ := strconv.Atoi(getenv("OBS_PORT", "5432"))
	cfg := SqlConfig{
		Host:     getenv("OBS_HOST", "127.0.0.1"),
		Port:     port,
		User:     getenv("OBS_USER", "observability_app"),
		Password: os.Getenv("OBS_PASS"),
		DBName:   getenv("OBS_DB", "observability"),
		SSLMode:  getenv("OBS_SSLMODE", "disable"),
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		c.db.Exec("DELETE FROM events WHERE path LIKE '__test__%'")
		c.Close()
	})
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestIntegrationInsertRefreshRead(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	evs := []Event{
		{Path: "__test__/a", Tier: "Vintage", Device: "desktop", Visitor: HashVisitor("x@y.com")},
		{Path: "__test__/a", Tier: "Vintage", Device: "desktop", Visitor: HashVisitor("x@y.com")},
		{Path: "__test__/a", Tier: "Any", Device: "mobile"},
		{Path: "__test__/a", Tier: "Any", Device: "mobile", IsBot: true},
	}
	if err := c.InsertBatch(ctx, evs); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}
	if err := c.RefreshRollup(ctx); err != nil {
		t.Fatalf("RefreshRollup: %v", err)
	}

	since := time.Now().AddDate(0, 0, -1)
	pages, err := c.TopPages(ctx, since, false)
	if err != nil {
		t.Fatalf("TopPages: %v", err)
	}
	var hits int64
	for _, p := range pages {
		if p.Path == "__test__/a" {
			hits = p.Hits
		}
	}
	// 3 human hits (bot excluded by default).
	if hits != 3 {
		t.Fatalf("expected 3 human hits for __test__/a, got %d", hits)
	}
}
