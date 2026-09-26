package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
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
// hour the way a real one is: the legacy read still reports an outage that way,
// and a window with nothing in it yet may have prices after the next snapshot.
func writeChartAPIResponse(w http.ResponseWriter, resp ChartAPIResponse) {
	w.Header().Set("Content-Type", "application/json")
	if len(resp.Datasets) != 0 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	json.NewEncoder(w).Encode(resp)
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

	co, err := backend().GetUUID(uuid)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	// How far back a chart may reach is a paid grant, and this route is mounted
	// under noSigning, so nothing upstream has checked the signature carrying
	// it: read it verified or not at all. Reading the query alone also left
	// every in-page fetch on the 30-day fallback, since the page asks for this
	// with a cookie and no ?sig=, capping a chart it would itself have drawn
	// in full.
	sig := verifiedRequestSignature(r)

	// Read only the window that was asked for. The axis used to be trimmed
	// after the fact, which left the archive scanning the whole entitlement
	// to answer a request for one month of it.
	lb, maxDays := chartWindow(sig, chartRangeParam(r))

	earliest, _ := earliestChartDate(r.Context(), co.UUID, co.Foil, co.Etched, lb)

	axisLabels := getDateAxisValues(earliest)
	datasets := getDatasets(r.Context(), uuid, co.Sealed, axisLabels, lb)

	writeChartAPIResponse(w, ChartAPIResponse{
		MaxLookbackDays: maxDays,
		LoadedDays:      lb.Days(),
		AxisLabels:      axisLabels,
		Datasets:        chartAPIDatasets(datasets),
		Checkpoints:     relevantCheckpoints(co.Name, earliest),
	})
}

// chartDataAPILong serves the chart for any resolvable id (ban:, tcg:, scryfall:,
// mtgjson:, or a bare uuid/number), including non-Magic products, from the long
// tables. Reached only when long-form reads are enabled.
//
// The id may also be a comma-separated roster, which is how the page widens a
// multi-card chart: it names the same ids the ?chart= url carries, and gets the
// (card × reference) datasets a roster renders, in the same shape the page
// built inline.
func chartDataAPILong(w http.ResponseWriter, r *http.Request, rawID string) {
	ids, _ := parseChartIDs(rawID)
	if len(ids) == 0 {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	// Resolve on this goroutine, before anything is read concurrently: a
	// resolution can reach the variants table, and a roster naming the same
	// card twice should only ask once.
	resolved := make([]chartSeries, 0, len(ids))
	seen := map[string]*chartTarget{}
	for _, id := range ids {
		target, asked := seen[id]
		if !asked {
			var err error
			if target, err = resolveChartTarget(r.Context(), id); err != nil {
				target = nil
			}
			seen[id] = target
		}
		if target == nil {
			continue
		}
		resolved = append(resolved, chartSeries{CardID: id, Name: target.Name, target: target})
	}
	if len(resolved) == 0 {
		errorResponse(w, http.StatusNotFound, "card not found")
		return
	}

	// Verified, and off the cookie the page actually sends: see ChartDataAPI.
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

	var earliest time.Time
	for _, s := range series {
		if e := earliestChartedDate(s.Prices, lb); !e.IsZero() && (earliest.IsZero() || e.Before(earliest)) {
			earliest = e
		}
	}
	axisLabels := getDateAxisValues(earliest)

	cards := make([]multiCardInput, len(series))
	for i, s := range series {
		cards[i] = multiCardInput{
			CardID:   s.CardID,
			Name:     s.Name,
			Datasets: chartDatasetsFrom(s.Prices, axisLabels),
		}
	}

	var datasets []Dataset
	var references []string
	if len(cards) > 1 {
		datasets, references = mergeMultiCardDatasets(cards)
	} else {
		datasets = cards[0].Datasets
		// A roster whose other ids failed to resolve still reaches a caller
		// that keys its lines by card, so the lone series keeps its identity
		// rather than arriving with an empty cardId.
		if len(ids) > 1 {
			for i := range datasets {
				datasets[i].CardID = cards[0].CardID
			}
		}
	}

	// Checkpoints match set releases by card name; a non-Magic name matches none.
	checkpoints := relevantCheckpoints(series[0].Name, earliest)
	if len(series) > 1 {
		names := make([]string, len(series))
		for i, s := range series {
			names[i] = s.Name
		}
		checkpoints = multiCardCheckpoints(names, earliest)
	}

	writeChartAPIResponse(w, ChartAPIResponse{
		MaxLookbackDays: maxDays,
		LoadedDays:      lb.Days(),
		AxisLabels:      axisLabels,
		Datasets:        chartAPIDatasets(datasets),
		References:      references,
		Checkpoints:     checkpoints,
	})
}
