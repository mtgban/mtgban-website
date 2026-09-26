package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rangeOption reads one option of the chart drawer's range select: its days,
// its attributes and its label.
var rangeOption = regexp.MustCompile(`<option value="(\d+)"([^>]*)>([^<]*)</option>`)

// Every mobile results page carries the chart drawer, and its range select
// locks the ranges past the viewer's tier. Only the chart page used to say
// what the tier reached, so on any other page every range past a month was
// locked, for every tier.
func TestMobileChartRangeFollowsTheTier(t *testing.T) {
	// DevMode so render reads templates from disk; SigCheck so the tier comes
	// from the signature rather than dev mode's ten years.
	withSigMode(t, true, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}

	for _, tc := range []struct {
		loopback string
		reach    int
	}{
		{"", 30}, // no grant reads as a month
		{"365", 365},
		{"3650", 3650},
	} {
		t.Run(fmt.Sprintf("%d days", tc.reach), func(t *testing.T) {
			params := map[string]string{}
			if tc.loopback != "" {
				params["SearchChartLoopback"] = tc.loopback
			}
			// A search that finds nothing still draws the results page, drawer
			// included, and needs no stores to do it.
			req := httptest.NewRequest(http.MethodGet, "/search?q=zzzznotacard", nil)
			req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: testSig(params)})
			rec := httptest.NewRecorder()
			Search(rec, req)

			page := rec.Body.String()
			start := strings.Index(page, `id="m-chart-range"`)
			if start < 0 {
				t.Fatalf("no chart range select on the page (%d bytes)", len(page))
			}
			end := strings.Index(page[start:], "</select>")
			if end < 0 {
				t.Fatal("the chart range select is never closed")
			}
			options := rangeOption.FindAllStringSubmatch(page[start:start+end], -1)
			if len(options) != 7 {
				t.Fatalf("found %d range options, want 7", len(options))
			}
			for _, option := range options {
				days, _ := strconv.Atoi(option[1])
				want := days > tc.reach
				if disabled := strings.Contains(option[2], "disabled"); disabled != want {
					t.Errorf("%d days: disabled=%v, want %v", days, disabled, want)
				}
				if locked := strings.Contains(option[3], "🔒"); locked != want {
					t.Errorf("%d days: label %q, locked want %v", days, option[3], want)
				}
			}
		})
	}
}
