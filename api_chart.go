package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ChartAPIResponse struct {
	MaxLookbackDays int `json:"maxLookbackDays"`
	// LoadedDays is the window this response actually covers, which is the
	// requested range clamped to the tier's ceiling. The page uses it to tell
	// whether a wider range needs fetching or is already in hand.
	LoadedDays  int               `json:"loadedDays"`
	AxisLabels  []string          `json:"axisLabels"`
	Datasets    []ChartAPIDataset `json:"datasets"`
	References  []string          `json:"references,omitempty"`
	Checkpoints []ChartCheckpoint `json:"checkpoints"`
}

type ChartAPIDataset struct {
	Name string `json:"name"`
	// CardID and Reference carry a roster chart's two axes of identity: which
	// card the line belongs to, and which price source it is drawn from. Empty
	// on a single-card chart, where the name says both.
	CardID    string       `json:"cardId,omitempty"`
	Reference string       `json:"reference,omitempty"`
	Data      []ChartPoint `json:"data"`
	Color     string       `json:"color"`
}

// chartAPIDatasets converts rendered datasets to their wire form, dropping any
// that carry no points at all.
func chartAPIDatasets(datasets []Dataset) []ChartAPIDataset {
	out := make([]ChartAPIDataset, 0, len(datasets))
	for _, ds := range datasets {
		if len(ds.Data) == 0 {
			continue
		}
		out = append(out, ChartAPIDataset{
			Name:      ds.Name,
			CardID:    ds.CardID,
			Reference: ds.Reference,
			Data:      ds.Data,
			Color:     ds.Color,
		})
	}
	return out
}

// writeChartAPIResponse sends a chart payload. An empty one is not cached for an
// hour the way a real one is: a window with nothing in it yet may have prices
// after the next snapshot.
func writeChartAPIResponse(w http.ResponseWriter, resp ChartAPIResponse) {
	w.Header().Set("Content-Type", "application/json")
	if len(resp.Datasets) != 0 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *site) ChartDataAPI(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
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

	chartDataAPILong(ds, w, r, uuid)
}

// chartDataAPILong serves the chart for any resolvable id (ban:, tcg:, scryfall:,
// mtgjson:, or a bare uuid/number), including non-Magic products, from the long
// tables.
//
// The id may also be a comma-separated roster, which is how the page widens a
// multi-card chart: it names the same ids the ?chart= url carries, and gets the
// (card × reference) datasets a roster renders, in the same shape the page
// built inline.
func chartDataAPILong(ds *datastore, w http.ResponseWriter, r *http.Request, rawID string) {
	ids, _ := parseChartIDs(ds.backend, rawID)
	if len(ids) == 0 {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	// Resolve on this goroutine, before anything is read concurrently: a
	// resolution can reach the variants table, and a roster naming the same
	// card twice should only ask once.
	resolved := make([]chartSeries, 0, len(ids))
	targets := chartTargetCache{}
	for _, id := range ids {
		target := targets.target(r.Context(), ds.backend, id)
		if target == nil {
			continue
		}
		resolved = append(resolved, chartSeries{CardID: id, Name: target.Name, target: target})
	}
	if len(resolved) == 0 {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	// How far back a chart may reach is a paid grant, and this route is mounted
	// under noSigning, so nothing upstream has checked the signature carrying
	// it: read it verified or not at all. The page asks with a cookie and no
	// ?sig=, so the query alone would cap every in-page fetch at the 30-day
	// fallback.
	sig := verifiedRequestSignature(r)
	lb, maxDays := chartWindow(sig, chartRangeParam(r))

	// One read per card, issued together: the series carries its own oldest
	// date, so the axis needs no query of its own.
	series := fetchRosterPrices(r.Context(), resolved, lb)

	// A card the archive did not answer for is an outage, not an empty chart.
	// A roster's answer replaces the chart it widens, so answering with the
	// other cards would drop that card's line unannounced: fail the lot.
	if readFailures(series) > 0 {
		errorResponse(w, http.StatusServiceUnavailable, "charts not available")
		return
	}

	// A roster is drawn as one whether or not its every id resolved, as the
	// page that asks for the wider window drew it.
	plot := plotSeries(ds, series, lb, len(ids) > 1)

	writeChartAPIResponse(w, ChartAPIResponse{
		MaxLookbackDays: maxDays,
		LoadedDays:      lb.Days(),
		AxisLabels:      plot.axis,
		Datasets:        chartAPIDatasets(plot.datasets),
		References:      plot.references,
		Checkpoints:     plot.checkpoints,
	})
}
