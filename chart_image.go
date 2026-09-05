package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/chartimage"
	"github.com/mtgban/mtgban-website/internal/embed"
	"github.com/mtgban/mtgban-website/timeseries"
)

const (
	// ChartImageMaxDays is the window a rendered chart covers. The page lets a
	// signature ask for more, but this image answers an unfurl - nobody is
	// signed in behind one - and six months of daily prices is already more
	// points than the width has pixels for.
	ChartImageMaxDays = 183

	// ChartImageMaxSeries is how many lines are drawn before the rest are left
	// off. A roster of eight cards times every provider carrying them is a
	// legend nobody reads and a plot nobody can follow.
	ChartImageMaxSeries = 8
)

// ChartImageAPI renders the chart named by ?chart= as a PNG, which is the only
// form a link unfurl can show: the page draws its chart from JSON in a canvas,
// and the robots that unfurl links run no scripts.
func ChartImageAPI(w http.ResponseWriter, r *http.Request) {
	ids, _ := parseChartIDs(r.FormValue("chart"))
	if len(ids) == 0 {
		http.Error(w, "missing chart ids", http.StatusBadRequest)
		return
	}
	if PricesArchiveDB == nil {
		http.Error(w, "charts not available", http.StatusServiceUnavailable)
		return
	}

	days := ChartImageMaxDays
	raw := r.FormValue("range")
	if raw != "" {
		asked, err := strconv.Atoi(raw)
		if err == nil && asked > 0 && asked < days {
			days = asked
		}
	}

	labels, cards, _ := readChartRoster(r.Context(), ids, timeseries.Lookback(days), func(id string) *chartTarget {
		target, err := resolveChartTarget(r.Context(), id)
		if err != nil {
			return nil
		}
		return target
	})

	spec := chartImageSpec(labels, cards, days)

	// Rendered into memory first: a write that fails halfway leaves a broken
	// image behind a 200, and the page an unfurl falls back to is better than
	// half a picture.
	var buffer bytes.Buffer
	err := chartimage.Render(&buffer, spec)
	if err != nil {
		log.Println("chart image:", err)
		http.Error(w, "unable to render chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	// Same reasoning as the JSON the page reads: a day's prices do not change
	// again today, but an empty chart is a database that has not warmed up
	// yet and must not be remembered for an hour.
	if len(spec.Series) > 0 {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("Content-Length", strconv.Itoa(buffer.Len()))
	w.Write(buffer.Bytes())
}

// chartImageSpec turns what the archive returned into what the renderer draws.
func chartImageSpec(labels []string, cards []multiCardInput, days int) chartimage.Spec {
	spec := chartimage.Spec{
		Title:    chartImageTitle(cards),
		Subtitle: chartImageSubtitle(days),
	}

	datasets := chartImageDatasets(cards)
	if len(labels) == 0 || len(datasets) == 0 {
		return spec
	}

	// The axis is built newest first, because that is the order the archive is
	// walked in. A chart reads the other way.
	spec.Labels = make([]string, len(labels))
	for i, label := range labels {
		spec.Labels[len(labels)-1-i] = label
	}

	for _, dataset := range datasets {
		if len(spec.Series) >= ChartImageMaxSeries {
			break
		}
		series := chartimage.Series{
			Name:  dataset.Name,
			Color: dataset.Color,
			Data:  make([]float64, len(dataset.Data)),
		}
		for i, raw := range dataset.Data {
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				// A day with no price is a gap in the line, not a zero: the
				// archive writes those as the JavaScript the page feeds them
				// to would read.
				value = math.NaN()
			}
			series.Data[len(dataset.Data)-1-i] = value
		}
		if !anyValue(series.Data) {
			continue
		}
		spec.Series = append(spec.Series, series)
	}

	return spec
}

// chartImageDatasets flattens the roster the way the page does, so the image
// carries the same lines under the same names.
func chartImageDatasets(cards []multiCardInput) []Dataset {
	if len(cards) == 0 {
		return nil
	}
	if len(cards) == 1 {
		return cards[0].Datasets
	}
	datasets, _ := mergeMultiCardDatasets(cards)
	return datasets
}

func chartImageTitle(cards []multiCardInput) string {
	switch len(cards) {
	case 0:
		return "MTGBAN price chart"
	case 1:
		return cards[0].Name
	case 2:
		return cards[0].Name + " · " + cards[1].Name
	default:
		return fmt.Sprintf("%s and %d more", cards[0].Name, len(cards)-1)
	}
}

func chartImageSubtitle(days int) string {
	window := fmt.Sprintf("%d days", days)
	switch {
	case days >= 365:
		window = "year"
	case days >= 180:
		window = "6 months"
	case days >= 90:
		window = "3 months"
	case days >= 30:
		window = fmt.Sprintf("%d weeks", days/7)
	}
	return "Prices over the last " + strings.TrimPrefix(window, "1 ") + " · mtgban.com"
}

func anyValue(data []float64) bool {
	for _, value := range data {
		if !math.IsNaN(value) {
			return true
		}
	}
	return false
}

// chartImageURL is where the rendered graph for a roster lives.
func chartImageURL(chartParam string) string {
	return ServerURL + "/api/chart/image.png?chart=" + url.QueryEscape(chartParam)
}

// writeChartOEmbed answers the unfurl of a chart page with the chart itself.
//
// The title is read from the matcher rather than from the search that would
// otherwise have run: an unfurl asks what the page is about, and a card is
// what it is about whether or not a store happens to be selling one today.
func writeChartOEmbed(w http.ResponseWriter, ids []string, searchIDs map[string]string, chartParam string) {
	payload, err := json.Marshal(embed.Chart(
		chartRosterTitle(ids, searchIDs),
		chartImageURL(chartParam),
		chartimage.DefaultWidth, chartimage.DefaultHeight,
	))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`Internal Server Error`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

// chartRosterTitle names a chart by the cards it plots.
func chartRosterTitle(ids []string, searchIDs map[string]string) string {
	if len(ids) == 0 {
		return "MTGBAN price chart"
	}

	first := ids[0]
	searchID := searchIDs[first]
	if searchID != "" {
		co, err := mtgmatcher.GetUUID(searchID)
		if err == nil {
			first = co.Name
		}
	}

	if len(ids) == 1 {
		return first
	}
	return fmt.Sprintf("%s and %d more", first, len(ids)-1)
}
