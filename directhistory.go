package main

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

// The window and the sample floor the fallback uses, set by the measurement
// in docs/direct-history.md. The window is 7 days: today and the six before it.
const (
	directWindowDays = 7
	directMinSamples = 1
)

// directHistory is the Direct price history the fallback reads: one
// windowed average per card, keyed by the datastore's per-finish uuid.
type directHistory struct {
	Window  int
	Since   time.Time
	Prices  map[string]float64
	Samples map[string]int
	Loaded  time.Time
}

var directHistoryPtr atomic.Pointer[directHistory]

var directHistoryLoading atomic.Bool

// directHistoryFor answers a card's windowed Direct average, when the
// archive holds enough of one.
func directHistoryFor(uuid string) (float64, bool) {
	h := directHistoryPtr.Load()
	if h == nil {
		return 0, false
	}
	price, ok := h.Prices[uuid]
	return price, ok
}

// foldDirectKey turns the archive's base uuid and finish flags back into the
// datastore's per-finish id, refusing a finish the printing is not sold in
// (MatchID falls back to another finish when the asked one is absent).
func foldDirectKey(b *mtgmatcher.Backend, key timeseries.AggregatePriceKey) (string, bool) {
	id, err := b.MatchID(key.MtgjsonUUID, key.IsFoil, key.IsEtched)
	if err != nil {
		return "", false
	}
	co, err := b.GetUUID(id)
	if err != nil || co.Foil != key.IsFoil || co.Etched != key.IsEtched {
		return "", false
	}
	return id, true
}

// buildDirectHistory folds the archive's averages onto datastore uuids,
// keeping the cards with at least minSamples observations.
func buildDirectHistory(b *mtgmatcher.Backend, averages map[timeseries.AggregatePriceKey]timeseries.WindowAverage, minSamples int) *directHistory {
	h := &directHistory{
		Window:  directWindowDays,
		Prices:  make(map[string]float64, len(averages)),
		Samples: make(map[string]int, len(averages)),
		Loaded:  time.Now(),
	}
	for key, avg := range averages {
		if avg.Samples < minSamples || avg.Average <= 0 {
			continue
		}
		uuid, ok := foldDirectKey(b, key)
		if !ok {
			continue
		}
		h.Prices[uuid] = avg.Average
		h.Samples[uuid] = avg.Samples
	}
	return h
}

// loadDirectHistory reads the trailing window of Direct prices from the
// archive and publishes it whole. A read error keeps the previous snapshot.
func (s *site) loadDirectHistory() {
	if PricesArchiveDB == nil {
		return
	}
	if !directHistoryLoading.CompareAndSwap(false, true) {
		return
	}
	defer directHistoryLoading.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	since := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(directWindowDays - 1))
	averages, err := PricesArchiveDB.GetWindowAveragesLong(ctx, timeseries.ProviderTCGDirectLow, since)
	if err != nil {
		log.Println("direct history:", err)
		backgroundJobs.Report(jobDirectHistory, directHistoryResult(directHistoryPtr.Load()), err.Error())
		return
	}
	h := buildDirectHistory(s.backend(), averages, directMinSamples)
	h.Since = since
	directHistoryPtr.Store(h)
	result := directHistoryResult(h)
	log.Println("direct history:", result)
	backgroundJobs.Report(jobDirectHistory, result, directHistoryProblem(h))
}

// directHistoryResult names a history's size for the dashboard; a failed read
// reports the snapshot it kept, "" when there is none.
func directHistoryResult(h *directHistory) string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("%d cards over %d days", len(h.Prices), directWindowDays)
}

// directHistoryProblem is what the dashboard flags about a loaded history.
func directHistoryProblem(h *directHistory) string {
	if len(h.Prices) == 0 {
		return "no Direct prices in the window"
	}
	return ""
}
