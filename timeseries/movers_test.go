package timeseries

import (
	"context"
	"os"
	"strconv"
	"testing"
)

func getenvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// moversTestClient connects to the price DB described by env vars, skipping
// unless TIMESERIES_TEST is set.
func moversTestClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("TIMESERIES_TEST") == "" {
		t.Skip("TIMESERIES_TEST not set; skipping DB integration test")
	}
	port, _ := strconv.Atoi(getenvOr("TS_PORT", "5432"))
	cfg := SQLConfig{
		Host:     getenvOr("TS_HOST", "127.0.0.1"),
		Port:     port,
		User:     getenvOr("TS_USER", "mtgelmo666"),
		Password: os.Getenv("TS_PASS"),
		DBName:   getenvOr("TS_DB", "card_prices"),
		SSLMode:  getenvOr("TS_SSLMODE", "require"),
		ReadOnly: true,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestGetMoversAnchorsToColumnLatest guards the sealed-EV date-anchor bug: a
// metric that has data must return movers even when its column lags the global
// latest date. Index 8 (sealed EV) lags the singles pull by a day; index 2
// (tcgplayer low) does not. Before the fix, index 8 returned zero.
func TestGetMoversAnchorsToColumnLatest(t *testing.T) {
	c := moversTestClient(t)
	ctx := context.Background()
	for _, idx := range []int{2, 8} {
		rows, err := c.GetMovers(ctx, idx, 90, 0, 0)
		if err != nil {
			t.Fatalf("GetMovers(%d): %v", idx, err)
		}
		if len(rows) == 0 {
			t.Errorf("GetMovers(%d) returned 0 movers; a metric with data must return some", idx)
		}
	}
}
