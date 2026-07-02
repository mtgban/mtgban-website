// telemetry_test.go
package main

import (
	"net/http/httptest"
	"testing"
)

func TestRecordPageHitNilRecorderNoPanic(t *testing.T) {
	ObservabilityRecorder = nil // default, but be explicit
	req := httptest.NewRequest("GET", "/newspaper?page=spike_score", nil)
	recordPageHit(req) // must return without panic
}
