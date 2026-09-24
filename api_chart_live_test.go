package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestChartDataAPILive drives the chart endpoint against a real archive, which
// is the only way to see the handler, the resolution, the read and the encoding
// agree. Read-only, and skipped unless pointed at a config and a ban_id.
//
//	CHARTLIVE_CONFIG=config_mtgban_production.json CHARTLIVE_BAN_ID=790 \
//	go test -run TestChartDataAPILive -v
func TestChartDataAPILive(t *testing.T) {
	banID := os.Getenv("CHARTLIVE_BAN_ID")
	path := os.Getenv("CHARTLIVE_CONFIG")
	if banID == "" || path == "" {
		t.Skip("CHARTLIVE_CONFIG / CHARTLIVE_BAN_ID not set; skipping live chart API test")
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

	client, err := timeseries.NewClient(*cfg.SQLConfig)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	defer func(db *timeseries.Client, ts TimeseriesConfig, reg []providerDisplay, dev, sig bool) {
		PricesArchiveDB, Config.TimeseriesConfig, providerRegistry = db, ts, reg
		DevMode, SigCheck = dev, sig
	}(PricesArchiveDB, Config.TimeseriesConfig, providerRegistry, DevMode, SigCheck)

	PricesArchiveDB = client
	Config.TimeseriesConfig = cfg.TimeseriesConfig
	buildProviderRegistry()
	// Without this the lookback is unbounded in dev, and the point here is
	// that the range bounds what gets read.
	DevMode, SigCheck = false, true

	get := func(t *testing.T, target string) ChartAPIResponse {
		t.Helper()
		w := httptest.NewRecorder()
		ChartDataAPI(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 200 {
			t.Fatalf("GET %s: status %d, body %s", target, w.Code, w.Body.String())
		}
		var resp ChartAPIResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("GET %s: decoding: %v", target, err)
		}
		return resp
	}

	id := "ban:" + banID

	// The tier ceiling with no signature is 30 days, so that is what a request
	// naming no range gets, and a wider one cannot talk its way past it.
	t.Run("the range is clamped to the tier", func(t *testing.T) {
		unbounded := get(t, "/api/chart/"+id)
		wide := get(t, "/api/chart/"+id+"?range=3650")
		if unbounded.MaxLookbackDays != 30 || unbounded.LoadedDays != 30 {
			t.Errorf("no range: maxLookbackDays=%d loadedDays=%d, want 30/30",
				unbounded.MaxLookbackDays, unbounded.LoadedDays)
		}
		if wide.LoadedDays != 30 {
			t.Errorf("range=3650: loadedDays=%d, want it cut to the 30-day ceiling", wide.LoadedDays)
		}
		if len(wide.AxisLabels) > 31 {
			t.Errorf("range=3650: %d axis labels, want no more than 31", len(wide.AxisLabels))
		}
	})

	// A narrower range than the ceiling reads and returns less.
	t.Run("a narrower range reads less", func(t *testing.T) {
		wide := get(t, "/api/chart/"+id+"?range=30")
		narrow := get(t, "/api/chart/"+id+"?range=7")
		if narrow.LoadedDays != 7 {
			t.Errorf("loadedDays=%d, want 7", narrow.LoadedDays)
		}
		if len(narrow.AxisLabels) >= len(wide.AxisLabels) {
			t.Errorf("7 days gave %d labels, 30 days gave %d; the range is not reaching the query",
				len(narrow.AxisLabels), len(wide.AxisLabels))
		}
		for _, ds := range narrow.Datasets {
			if len(ds.Data) != len(narrow.AxisLabels) {
				t.Errorf("dataset %q has %d points against %d labels",
					ds.Name, len(ds.Data), len(narrow.AxisLabels))
			}
		}
	})

	// Gaps go over as null, and the response carries no sentinel string.
	t.Run("gaps are null on the wire", func(t *testing.T) {
		w := httptest.NewRecorder()
		ChartDataAPI(w, httptest.NewRequest("GET", "/api/chart/"+id+"?range=30", nil))
		body := w.Body.String()
		if strings.Contains(body, "Number.NaN") {
			t.Error("response still carries the Number.NaN sentinel")
		}
		if !strings.Contains(body, `"loadedDays":`) {
			t.Error("response does not say how much it loaded")
		}
	})

	// A roster answers in one request, and each line says which card it is.
	t.Run("a roster answers as a roster", func(t *testing.T) {
		second := os.Getenv("CHARTLIVE_BAN_ID_2")
		if second == "" {
			t.Skip("CHARTLIVE_BAN_ID_2 not set; skipping the roster case")
		}
		resp := get(t, "/api/chart/"+id+","+"ban:"+second+"?range=30")
		if len(resp.References) == 0 {
			t.Error("a roster response carries no reference list")
		}
		cards := map[string]bool{}
		for _, ds := range resp.Datasets {
			if ds.CardID == "" || ds.Reference == "" {
				t.Errorf("roster dataset %q carries no card/reference identity", ds.Name)
			}
			cards[ds.CardID] = true
		}
		if len(cards) != 2 {
			t.Errorf("got lines for %d cards, want 2", len(cards))
		}
	})
}
