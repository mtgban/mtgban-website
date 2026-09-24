package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// A chart renders its series inline in the HTML: one label per calendar day
// from the oldest charted date to today, and one value per label per provider,
// whether or not that provider quoted that day.
//
// These are not assertions, they are measurements: run with -v to print the
// table that sizes the payload against what the chart actually shows on load
// (the dateRange select defaults to 180 days for a single-card chart). The page
// now renders only that window and fetches wider ones through /api/chart, so
// the rows past 180 days are what a widened chart costs, not what every chart
// page costs.

// syntheticSeries builds a card's history: days of dates ending today, with
// every provider quoted on each day it has data. density is the fraction of
// days a provider is quoted on, spread evenly.
func syntheticSeries(days int, providers []int16, density float64) map[string]timeseries.ProviderPrices {
	out := make(map[string]timeseries.ProviderPrices, days)
	today := time.Now()
	step := 1
	if density > 0 && density < 1 {
		step = int(1 / density)
	}
	for i := range days {
		if i%step != 0 {
			continue
		}
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		pp := timeseries.ProviderPrices{}
		for _, p := range providers {
			pp[p] = 12.34
		}
		out[day] = pp
	}
	return out
}

// chartPayloadBytes is what the template writes for one card's chart: the
// label array plus each dataset's data array, marshalled the way html/template
// marshals a []string in a JS context.
func chartPayloadBytes(labels []string, datasets []Dataset) int {
	b, _ := json.Marshal(labels)
	total := len(b)
	for _, ds := range datasets {
		d, _ := json.Marshal(ds.Data)
		total += len(d)
	}
	return total
}

func TestChartPayloadSize(t *testing.T) {
	// The ten providers the Magic deployment charts, per its dataset config.
	providers := []int16{1, 2, 3, 4, 8, 9, 10, 11, 12, 13}
	buildProviderRegistryForTest(t, providers)

	// Every lookback the date-range select offers, against a card whose
	// history reaches back at least that far.
	lookbacks := []int{30, 90, 180, 365, 730, 1825, 3650}

	t.Log("days  providers  labels   payload     shown-at-180d  wasted")
	for _, days := range lookbacks {
		results := syntheticSeries(days, providers, 1)
		earliest := earliestChartedDate(results, timeseries.Lookback(days))
		labels := getDateAxisValues(earliest)
		datasets := chartDatasetsFrom(results, labels)
		total := chartPayloadBytes(labels, datasets)

		shown := 180
		if shown > len(labels) {
			shown = len(labels)
		}
		wasted := 100 * (1 - float64(shown)/float64(len(labels)))
		t.Logf("%4d  %9d  %6d  %8s  %13d  %5.1f%%",
			days, len(datasets), len(labels), humanBytes(total), shown, wasted)
	}
}

// TestChartPayloadDensity checks that sparse history costs less than dense
// history, which is only true since a gap became `null`. A provider quoted one
// day in ten still gets a full-length array, but its nine gaps are now four
// bytes each rather than the thirteen "Number.NaN" cost, so the sparser card -
// which is most of them, on a long window - is the cheaper one. It used to be
// the more expensive one.
func TestChartPayloadDensity(t *testing.T) {
	providers := []int16{1, 2, 3, 4, 8, 9, 10, 11, 12, 13}
	buildProviderRegistryForTest(t, providers)

	const days = 3650
	t.Log("density  payload")
	for _, density := range []float64{1, 0.5, 0.2, 0.1} {
		results := syntheticSeries(days, providers, density)
		earliest := earliestChartedDate(results, timeseries.Lookback(days))
		labels := getDateAxisValues(earliest)
		datasets := chartDatasetsFrom(results, labels)
		t.Logf("%6.0f%%  %8s", density*100, humanBytes(chartPayloadBytes(labels, datasets)))
	}
}

// TestChartPayloadMultiCard sizes a roster chart. Every card contributes one
// full-length array per provider it has data for, and the roster's default
// range is "All", so nothing here is trimmed on the client either.
func TestChartPayloadMultiCard(t *testing.T) {
	providers := []int16{1, 2, 3, 4, 8, 9, 10, 11, 12, 13}
	buildProviderRegistryForTest(t, providers)

	const days = 3650
	results := syntheticSeries(days, providers, 1)
	earliest := earliestChartedDate(results, timeseries.Lookback(days))
	labels := getDateAxisValues(earliest)

	t.Log("cards  datasets  payload")
	for _, n := range []int{1, 2, 5, 10} {
		cards := make([]multiCardInput, n)
		for i := range cards {
			cards[i] = multiCardInput{
				CardID:   fmt.Sprintf("card-%d", i),
				Name:     fmt.Sprintf("Card %d", i),
				Datasets: chartDatasetsFrom(results, labels),
			}
		}
		datasets, _ := mergeMultiCardDatasets(cards)
		t.Logf("%5d  %8d  %8s", n, len(datasets), humanBytes(chartPayloadBytes(labels, datasets)))
	}
}

// BenchmarkChartDatasets is the server-side cost of projecting a fetched
// series onto the axis - the work between the archive answering and the
// template running.
func BenchmarkChartDatasets(b *testing.B) {
	providers := []int16{1, 2, 3, 4, 8, 9, 10, 11, 12, 13}
	providerRegistry = nil
	for _, p := range providers {
		providerRegistry = append(providerRegistry, providerDisplay{
			Provider: p, Name: fmt.Sprintf("provider %d", p), Color: "rgb(0,0,0)",
		})
	}
	for _, days := range []int{180, 730, 3650} {
		results := syntheticSeries(days, providers, 1)
		earliest := earliestChartedDate(results, timeseries.Lookback(days))
		labels := getDateAxisValues(earliest)
		b.Run(fmt.Sprintf("%dd", days), func(b *testing.B) {
			for b.Loop() {
				datasets := chartDatasetsFrom(results, labels)
				chartPayloadBytes(labels, datasets)
			}
		})
	}
}

// buildProviderRegistryForTest points the package registry at a fixed provider
// list, so the measurement does not depend on a loaded config.
func buildProviderRegistryForTest(t *testing.T, providers []int16) {
	t.Helper()
	saved := providerRegistry
	t.Cleanup(func() { providerRegistry = saved })
	providerRegistry = nil
	for _, p := range providers {
		providerRegistry = append(providerRegistry, providerDisplay{
			Provider: p, Name: fmt.Sprintf("provider %d", p), Color: "rgb(0,0,0)",
		})
	}
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
