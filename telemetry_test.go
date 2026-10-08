// telemetry_test.go
package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRecordPageHitNilRecorderNoPanic(t *testing.T) {
	ObservabilityRecorder = nil // default, but be explicit
	req := httptest.NewRequest("GET", "/newspaper?page=spike_score", nil)
	recordPageHit(req) // must return without panic
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

// A hit is labelled with the tier its checked signature names: a forged
// cookie counts as a visitor with none.
func TestPageHitLabelsTheCheckedTier(t *testing.T) {
	signingEnabled(t, false)
	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Legacy"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))
	fields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))

	for sig, want := range map[string]string{signed: "Legacy", forged: "Any"} {
		req := httptest.NewRequest(http.MethodGet, "/newspaper", nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		if got := pageHitEvent(req).Tier; got != want {
			t.Errorf("tier %q, want %q", got, want)
		}
	}
}
