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

func TestIntegrationInstanceFilterAndUniques(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// One visitor hitting two paths across "days" plus an anon and a bot hit,
	// all for instance "__inst_a__"; one hit for a different instance.
	v := HashVisitor("x@y.com")
	evs := []Event{
		{Path: "__test__/a", Tier: "Vintage", Device: "desktop", Visitor: v, Instance: "__inst_a__"},
		{Path: "__test__/a", Tier: "Vintage", Device: "desktop", Visitor: v, Instance: "__inst_a__"},
		{Path: "__test__/b", Tier: "Vintage", Device: "desktop", Visitor: v, Instance: "__inst_a__"},
		{Path: "__test__/a", Tier: "Any", Device: "mobile", Instance: "__inst_a__"},
		{Path: "__test__/a", Tier: "Any", Device: "mobile", IsBot: true, Instance: "__inst_a__"},
		{Path: "__test__/a", Tier: "Vintage", Device: "desktop", Visitor: HashVisitor("z@z.com"), Instance: "__inst_b__"},
	}
	if err := c.InsertBatch(ctx, evs); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	since := time.Now().AddDate(0, 0, -1)
	pages, err := c.TopPages(ctx, since, false, "__inst_a__")
	if err != nil {
		t.Fatalf("TopPages: %v", err)
	}
	got := map[string]PathAgg{}
	for _, p := range pages {
		got[p.Path] = p
	}
	// instance filter excludes __inst_b__; bot excluded by default.
	// __test__/a: 3 human hits (2 by v, 1 anon), 1 distinct visitor (anon NULL not counted).
	if a := got["__test__/a"]; a.Hits != 3 || a.Uniques != 1 {
		t.Fatalf("__test__/a: got hits=%d uniques=%d, want 3/1", a.Hits, a.Uniques)
	}
	if _, ok := got["__test__/b"]; !ok {
		t.Fatal("__test__/b missing for __inst_a__")
	}

	// The other instance's rows must not appear.
	pagesB, err := c.TopPages(ctx, since, false, "__inst_b__")
	if err != nil {
		t.Fatalf("TopPages inst_b: %v", err)
	}
	for _, p := range pagesB {
		if p.Path == "__test__/b" {
			t.Fatal("__inst_b__ should not see __inst_a__'s __test__/b")
		}
	}
}
