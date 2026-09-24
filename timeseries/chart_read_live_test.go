package timeseries

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// chartLiveConfig reads the archive connection out of a site config file named
// by CHARTLIVE_CONFIG, so timing a real deployment needs no credentials on the
// command line and none copied into the environment.
func chartLiveConfig(t *testing.T) SQLConfig {
	t.Helper()
	path := os.Getenv("CHARTLIVE_CONFIG")
	if path == "" {
		t.Skip("CHARTLIVE_CONFIG not set; skipping live chart read timing")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg struct {
		SQLConfig SQLConfig `json:"sql_config"`
	}
	if err := json.Unmarshal(blob, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg.SQLConfig.Host == "" {
		t.Fatalf("%s has no sql_config.host", path)
	}
	return cfg.SQLConfig
}

// TestChartReadLatencyLive times the read a chart page makes, through the same
// client the site uses - prepared statement, lib/pq, the per-row scan and the
// date -> (provider -> price) pivot - so the number includes everything between
// the handler asking and the handler holding a series.
//
// Strictly read-only: it runs HGetAllByBanID and nothing else, so it is safe to
// point at production. The connection comes from a site config file, so no
// credentials have to be copied anywhere to run it.
//
//	CHARTLIVE_CONFIG=config_mtgban_production.json CHARTLIVE_BAN_ID=790 \
//	go test ./timeseries/ -run TestChartReadLatencyLive -v
func TestChartReadLatencyLive(t *testing.T) {
	banID, _ := strconv.ParseInt(os.Getenv("CHARTLIVE_BAN_ID"), 10, 64)
	if banID == 0 {
		t.Skip("CHARTLIVE_BAN_ID not set; skipping live chart read timing")
	}
	ctx := context.Background()
	c, err := NewClient(chartLiveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// Warm the pool and the server-side plan, so the table below times a read
	// on an established connection rather than a handshake.
	if _, err := c.HGetAllByBanID(ctx, banID, Lookback(30)); err != nil {
		t.Fatalf("warm read: %v", err)
	}

	const reps = 5
	t.Logf("ban_id %d, %d reps, best of each", banID, reps)
	t.Log("lookback   days    points   best      median")
	for _, days := range []int{30, 90, 180, 365, 730, 1825, 3650} {
		var best, median time.Duration
		var points int
		times := make([]time.Duration, 0, reps)
		for range reps {
			start := time.Now()
			res, err := c.HGetAllByBanID(ctx, banID, Lookback(days))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("HGetAllByBanID(%d): %v", days, err)
			}
			points = 0
			for _, pp := range res {
				points += len(pp)
			}
			times = append(times, elapsed)
		}
		best = times[0]
		for _, d := range times {
			if d < best {
				best = d
			}
		}
		// Small n, so a plain sort-free median: count how many are below each.
		for _, d := range times {
			below := 0
			for _, o := range times {
				if o < d {
					below++
				}
			}
			if below == reps/2 {
				median = d
			}
		}
		t.Logf("%8dd  %5d  %8d  %-9s %s", days, days, points,
			best.Round(time.Millisecond), median.Round(time.Millisecond))
	}
}
