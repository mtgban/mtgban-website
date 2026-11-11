package main

import (
	"net/http"
	"strconv"
)

// chartDataFacts describes a chart data fetch: its range ceiling and how many cards it draws.
func chartDataFacts(ids, days int) []fact {
	scope := "single"
	if ids > 1 {
		scope = "multi"
	}
	value := "other"
	switch days {
	case 30, 90, 180, 365, 730, 1825, 3650:
		value = strconv.Itoa(days)
	default:
		if days <= 0 {
			value = "all"
		}
	}
	return []fact{newFact(scope, "data.chart", value), newFact("", "data.chart_ids", smallCount(ids))}
}

// paletteList counts a fetch of one of the palette's lists, then serves it.
func paletteList(list string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observe(r, "palette.list", list)
		next(w, r)
	})
}

// paletteChip counts a fetch of a chip the palette locked, then serves it.
func paletteChip(kind string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observe(r, "palette.chip_fetch", kind)
		next(w, r)
	})
}
