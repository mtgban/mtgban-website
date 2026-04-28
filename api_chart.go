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
		http.Error(w, "missing card UUID", http.StatusBadRequest)
		return
	}

	if PricesArchiveDB == nil {
		http.Error(w, "charts not available", http.StatusServiceUnavailable)
		return
	}

	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	sig := r.FormValue("sig")
	userTier := GetParamFromSig(sig, "UserTier")

	lb := lookbackForTier(userTier)
	maxDays := lb.Days()

	earliest, _ := PricesArchiveDB.GetEarliestDate(r.Context(), co.UUID, co.Foil, co.Etched, lb)

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
	datasets := getDatasets(uuid, co.Sealed, axisLabels, userTier)

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
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(resp)
}
