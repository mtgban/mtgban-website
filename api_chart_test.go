package main

import (
	"net/http/httptest"
	"testing"
)

// A chart holds as much history as the reader's tier reaches, so no cache
// shared between readers may keep it.
func TestChartAPIResponseIsPrivate(t *testing.T) {
	rec := httptest.NewRecorder()
	writeChartAPIResponse(rec, ChartAPIResponse{Datasets: make([]ChartAPIDataset, 1)})
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age=3600" {
		t.Errorf("Cache-Control = %q, want private, max-age=3600", got)
	}
}
