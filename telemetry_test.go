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

func TestResolveInstanceName(t *testing.T) {
	if got := resolveInstanceName("beta"); got != "beta" {
		t.Fatalf("configured name should win, got %q", got)
	}
	// Empty config falls back to hostname or "unknown"; either way non-empty.
	if got := resolveInstanceName(""); got == "" {
		t.Fatal("empty config must fall back to a non-empty value")
	}
}

func TestRecordablePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/newspaper", true},
		{"/search", true},
		{"/", true},
		{"/api/tcgplayer/lastsold/12345", false},
		{"/api/cardmarket/foo", false},
		{"/api/search/", false},
		{"/api/prices/", false},
	}
	for _, c := range cases {
		if got := recordablePath(c.path); got != c.want {
			t.Errorf("recordablePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
