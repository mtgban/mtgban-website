package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type ChartAPIResponse struct {
	MaxLookbackDays int               `json:"maxLookbackDays"`
	AxisLabels      []string          `json:"axisLabels"`
	Datasets        []ChartAPIDataset `json:"datasets"`
	Checkpoints     []ChartCheckpoint `json:"checkpoints"`
}

type ChartAPIDataset struct {
	Name  string   `json:"name"`
	Data  []string `json:"data"`
	Color string   `json:"color"`
}

func ChartDataAPI(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimPrefix(r.URL.Path, "/api/chart/")
	uuid = strings.TrimSuffix(uuid, "/")
	if uuid == "" {
		errorResponse(w, http.StatusBadRequest, "missing card UUID")
		return
	}

	if PricesArchiveDB == nil {
		errorResponse(w, http.StatusServiceUnavailable, "charts not available")
		return
	}

	// Long-form reads unlock charting by any id (ban:, tcg:, scryfall:, mtgjson:,
	// bare uuid/number) and non-Magic products. The legacy path below stays
	// mtgjson-uuid only.
	if Config.TimeseriesConfig.LongFormReads {
		chartDataAPILong(w, r, uuid)
		return
	}

	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	sig := r.FormValue("sig")

	lb := chartLookback(sig)
	maxDays := lb.Days()

	earliest, _ := earliestChartDate(r.Context(), co.UUID, co.Foil, co.Etched, lb)

	if rangeStr := r.FormValue("range"); rangeStr != "" {
		if days, err := strconv.Atoi(rangeStr); err == nil && days > 0 {
			if days > maxDays {
				days = maxDays
			}
			cutoff := time.Now().AddDate(0, 0, -days)
			if cutoff.After(earliest) {
				earliest = cutoff
			}
		}
	}

	axisLabels := getDateAxisValues(earliest)
	datasets := getDatasets(r.Context(), uuid, co.Sealed, axisLabels, lb)

	var apiDatasets []ChartAPIDataset
	for _, ds := range datasets {
		if len(ds.Data) == 0 {
			continue
		}
		apiDatasets = append(apiDatasets, ChartAPIDataset{
			Name:  ds.Name,
			Data:  ds.Data,
			Color: ds.Color,
		})
	}

	resp := ChartAPIResponse{
		MaxLookbackDays: maxDays,
		AxisLabels:      axisLabels,
		Datasets:        apiDatasets,
		Checkpoints:     relevantCheckpoints(co.Name, earliest),
	}

	w.Header().Set("Content-Type", "application/json")
	// An empty chart (DB outage or warmup) must not be cached for an hour
	if len(apiDatasets) != 0 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	json.NewEncoder(w).Encode(resp)
}

// chartDataAPILong serves the chart for any resolvable id (ban:, tcg:, scryfall:,
// mtgjson:, or a bare uuid/number), including non-Magic products, from the long
// tables. Reached only when long-form reads are enabled.
func chartDataAPILong(w http.ResponseWriter, r *http.Request, rawID string) {
	target, err := resolveChartTarget(r.Context(), rawID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	sig := r.FormValue("sig")
	lb := chartLookback(sig)
	maxDays := lb.Days()

	earliest, _ := chartTargetEarliest(r.Context(), target, lb)

	if rangeStr := r.FormValue("range"); rangeStr != "" {
		if days, err := strconv.Atoi(rangeStr); err == nil && days > 0 {
			if days > maxDays {
				days = maxDays
			}
			cutoff := time.Now().AddDate(0, 0, -days)
			if cutoff.After(earliest) {
				earliest = cutoff
			}
		}
	}

	axisLabels := getDateAxisValues(earliest)
	datasets := getChartDatasets(r.Context(), target, axisLabels, lb)

	var apiDatasets []ChartAPIDataset
	for _, ds := range datasets {
		if len(ds.Data) == 0 {
			continue
		}
		apiDatasets = append(apiDatasets, ChartAPIDataset{
			Name:  ds.Name,
			Data:  ds.Data,
			Color: ds.Color,
		})
	}

	// Checkpoints match set releases by card name; a non-Magic name matches none.
	resp := ChartAPIResponse{
		MaxLookbackDays: maxDays,
		AxisLabels:      axisLabels,
		Datasets:        apiDatasets,
		Checkpoints:     relevantCheckpoints(target.Name, earliest),
	}

	w.Header().Set("Content-Type", "application/json")
	// An empty chart (DB outage or warmup) must not be cached for an hour
	if len(apiDatasets) != 0 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	json.NewEncoder(w).Encode(resp)
}
