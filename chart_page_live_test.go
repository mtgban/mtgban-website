package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestChartPageCostLive measures what one chart page costs the server, end to
// end and against real data: the archive read, the projection onto the date
// axis, and the bytes the template then writes into the HTML. Read-only, so it
// is safe to point at production.
//
//	CHARTLIVE_CONFIG=config_mtgban_production.json CHARTLIVE_BAN_ID=790 \
//	go test -run TestChartPageCostLive -v
func TestChartPageCostLive(t *testing.T) {
	banID, _ := strconv.ParseInt(os.Getenv("CHARTLIVE_BAN_ID"), 10, 64)
	path := os.Getenv("CHARTLIVE_CONFIG")
	if banID == 0 || path == "" {
		t.Skip("CHARTLIVE_CONFIG / CHARTLIVE_BAN_ID not set; skipping live chart page cost")
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg struct {
		SQLConfig        *timeseries.SQLConfig `json:"sql_config"`
		TimeseriesConfig TimeseriesConfig      `json:"timeseries_config"`
	}
	if err := json.Unmarshal(blob, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// Chart the providers the deployment charts, in its own order.
	Config.TimeseriesConfig = cfg.TimeseriesConfig
	buildProviderRegistry()

	client, err := timeseries.NewClient(*cfg.SQLConfig)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	if _, err := client.HGetAllByBanID(ctx, banID, timeseries.Lookback(30)); err != nil {
		t.Fatalf("warm read: %v", err)
	}

	t.Logf("ban_id %d, %d providers configured", banID, len(providerRegistry))
	t.Log("lookback   read     project   labels  series  gaps    inline-HTML")
	for _, days := range []int{30, 90, 180, 365, 730, 1825, 3650} {
		lb := timeseries.Lookback(days)

		start := time.Now()
		results, err := client.HGetAllByBanID(ctx, banID, lb)
		if err != nil {
			t.Fatalf("HGetAllByBanID(%d): %v", days, err)
		}
		read := time.Since(start)

		start = time.Now()
		earliest := earliestChartedDate(results, lb)
		labels := getDateAxisValues(earliest)
		datasets := chartDatasetsFrom(results, labels)
		payload := chartPayloadBytes(labels, datasets)
		project := time.Since(start)

		slots := len(datasets) * len(labels)
		var series int
		for _, pp := range results {
			series += len(pp)
		}
		t.Logf("%8dd  %-8s %-9s %6d  %6d  %6d  %s",
			days, read.Round(time.Millisecond), project.Round(time.Millisecond),
			len(labels), series, slots-series, humanBytes(payload))
	}

	// A roster chart reads one card at a time (search.go's chartIDs loop), so
	// its latency is the round trips added up. Time that against the same reads
	// issued together, which is what the pool is sized for.
	t.Run("roster", func(t *testing.T) {
		ids := make([]int64, 0, 10)
		for i := range int64(10) {
			ids = append(ids, banID+i)
		}
		lb := timeseries.Lookback(3650)

		start := time.Now()
		for _, id := range ids {
			if _, err := client.HGetAllByBanID(ctx, id, lb); err != nil {
				t.Fatalf("serial read %d: %v", id, err)
			}
		}
		serial := time.Since(start)

		// Open the pool's connections before timing anything concurrent. A burst
		// against a pool holding one connection pays TCP + TLS + SCRAM for each
		// of the rest, which is round trips, not query time - and it would show
		// up here as concurrency not helping.
		warm := make(chan error, len(ids))
		for _, id := range ids {
			go func() {
				_, err := client.HGetAllByBanID(ctx, id, timeseries.Lookback(1))
				warm <- err
			}()
		}
		for range ids {
			if err := <-warm; err != nil {
				t.Fatalf("pool warm: %v", err)
			}
		}

		start = time.Now()
		errs := make(chan error, len(ids))
		for _, id := range ids {
			go func() {
				_, err := client.HGetAllByBanID(ctx, id, lb)
				errs <- err
			}()
		}
		for range ids {
			if err := <-errs; err != nil {
				t.Fatalf("concurrent read: %v", err)
			}
		}
		concurrent := time.Since(start)

		t.Logf("%d cards: serial %s, concurrent %s (%.1fx)",
			len(ids), serial.Round(time.Millisecond), concurrent.Round(time.Millisecond),
			float64(serial)/float64(concurrent))
	})
}
