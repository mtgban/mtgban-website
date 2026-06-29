package main

import (
	"sort"
	"strconv"

	"github.com/mtgban/mtgban-website/timeseries"
)

// ScreenerMetric is a selectable price metric (dataset index plus label).
type ScreenerMetric struct {
	Index int
	Name  string
}

// screenerMetrics mirrors config.json timeseries_config.datasets. TCG Low first
// so it is the default landing metric.
var screenerMetrics = []ScreenerMetric{
	{2, "TCGplayer Low"},
	{3, "TCGplayer Market"},
	{0, "Card Kingdom Retail"},
	{1, "Card Kingdom Buylist"},
	{4, "Cardmarket Low"},
	{5, "Cardmarket Trend"},
	{6, "Star City Games Buylist"},
	{7, "ABU Games Buylist"},
	{9, "Cool Stuff Inc Buylist"},
	{8, "Sealed EV (TCG Low)"},
}

// ScreenerWindow is a selectable lookback in days.
type ScreenerWindow struct {
	Days  int
	Label string
}

var screenerWindows = []ScreenerWindow{
	{1, "1 day"},
	{7, "7 days"},
	{14, "14 days"},
	{30, "30 days"},
	{90, "90 days"},
}

func validMetric(index int) bool {
	for _, m := range screenerMetrics {
		if m.Index == index {
			return true
		}
	}
	return false
}

func validWindow(days int) bool {
	for _, w := range screenerWindows {
		if w.Days == days {
			return true
		}
	}
	return false
}

// ScreenerResult is one display row.
type ScreenerResult struct {
	UUID      string
	IsFoil    bool
	IsEtched  bool
	Current   float64
	Prior     float64
	PctChange float64 // fraction: 0.20 == +20%
	AbsChange float64
}

// FieldValue returns a field as a string for sorting and template rendering.
func (r ScreenerResult) FieldValue(name string) string {
	switch name {
	case "current":
		return strconv.FormatFloat(r.Current, 'f', -1, 64)
	case "prior":
		return strconv.FormatFloat(r.Prior, 'f', -1, 64)
	case "pct":
		return strconv.FormatFloat(r.PctChange, 'f', -1, 64)
	case "abs":
		return strconv.FormatFloat(r.AbsChange, 'f', -1, 64)
	default:
		return ""
	}
}

// screenerFilter holds the user-editable thresholds.
type screenerFilter struct {
	Metric   int
	Window   int
	Move     string  // up | down | either
	MinPrice float64 // dollar floor on current price
	MinPct   float64 // whole percent, e.g. 20
	MaxPct   float64 // optional sanity cap in whole percent, 0 == off
}

// filterScreenerRows computes change, applies the thresholds, and dedups by
// (uuid, foil, etched). Rows with a non-positive prior price are skipped.
func filterScreenerRows(rows []timeseries.MoverRow, f screenerFilter) []ScreenerResult {
	type key struct {
		uuid   string
		foil   bool
		etched bool
	}
	seen := map[key]bool{}
	var out []ScreenerResult
	for _, row := range rows {
		if row.Prior <= 0 || row.Current <= 0 {
			continue
		}
		if row.Current < f.MinPrice {
			continue
		}
		pct := (row.Current - row.Prior) / row.Prior
		pctWhole := pct * 100
		switch f.Move {
		case "down":
			if pctWhole > -f.MinPct {
				continue
			}
		case "either":
			if abs(pctWhole) < f.MinPct {
				continue
			}
		default: // up
			if pctWhole < f.MinPct {
				continue
			}
		}
		if f.MaxPct > 0 && abs(pctWhole) > f.MaxPct {
			continue
		}
		k := key{row.MtgjsonUUID, row.IsFoil, row.IsEtched}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ScreenerResult{
			UUID:      row.MtgjsonUUID,
			IsFoil:    row.IsFoil,
			IsEtched:  row.IsEtched,
			Current:   row.Current,
			Prior:     row.Prior,
			PctChange: pct,
			AbsChange: row.Current - row.Prior,
		})
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// sortScreenerRows sorts in place by a ScreenerResult field name and direction.
func sortScreenerRows(rows []ScreenerResult, field, dir string) {
	if field == "" {
		field = "pct"
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := strconv.ParseFloat(rows[i].FieldValue(field), 64)
		b, _ := strconv.ParseFloat(rows[j].FieldValue(field), 64)
		if dir == "asc" {
			return a < b
		}
		return a > b
	})
}
