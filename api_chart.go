package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type ChartAPIResponse struct {
	AxisLabels []string          `json:"axisLabels"`
	Datasets   []ChartAPIDataset `json:"datasets"`
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

	if Config.TimeseriesConfig.Address == "" {
		http.Error(w, "charts not available", http.StatusServiceUnavailable)
		return
	}

	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	axisLabels := getDateAxisValues(uuid)
	datasets := getDatasets(uuid, co.Sealed, axisLabels)

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
		AxisLabels: axisLabels,
		Datasets:   apiDatasets,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(resp)
}
