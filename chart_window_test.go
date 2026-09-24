package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// A chart request reads the window it is going to draw, so the range asked for
// has to reach the query - but it is a public parameter, and the tier's
// ceiling is what decides how far back anyone may look.
func TestChartWindowClampsToTheTier(t *testing.T) {
	// DevMode without signature checking hands every request the maximum, which
	// would make every case below the same case.
	defer func(dev, sigcheck bool) { DevMode, SigCheck = dev, sigcheck }(DevMode, SigCheck)
	DevMode, SigCheck = false, true

	// No signature, so the lookback falls back to its 30-day default.
	for _, tc := range []struct {
		name     string
		want     int
		wantDays int
	}{
		{"a range inside the ceiling is honoured", 7, 7},
		{"a range at the ceiling is honoured", 30, 30},
		{"a wider range is cut to the ceiling", 3650, 30},
		{"no range asks for the ceiling", 0, 30},
		{"and so does a negative one", -1, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			window, maxDays := chartWindow("", tc.want)
			if window.Days() != tc.wantDays {
				t.Errorf("window = %d days, want %d", window.Days(), tc.wantDays)
			}
			if maxDays != 30 {
				t.Errorf("maxDays = %d, want 30", maxDays)
			}
		})
	}
}

// /api/chart/ is mounted under noSigning, so nothing upstream has checked the
// signature by the time the handler reads the lookback out of it. How far back
// a chart may reach is a paid grant, so an unsigned one buys nothing: the
// handler has to end up on the 30-day fallback rather than on the ten years the
// caller wrote for itself.
func TestChartLookbackIgnoresAnUnsignedGrant(t *testing.T) {
	defer func(dev, sigcheck bool) { DevMode, SigCheck = dev, sigcheck }(DevMode, SigCheck)
	DevMode, SigCheck = false, true

	// Complete enough to get past every check but the HMAC: unexpired, and
	// carrying a Signature field. Without those it would be turned away for
	// being malformed and the test would pass without proving anything.
	forged := base64.StdEncoding.EncodeToString([]byte(url.Values{
		"SearchChartLoopback": {"3650"},
		"UserTier":            {"Legacy"},
		"Expires":             {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		"Signature":           {"not-a-real-hmac"},
	}.Encode()))

	// The premise: this forgery does buy ten years if it is read unverified,
	// which is what both the query form and the cookie form used to do.
	if _, maxDays := chartWindow(getSignatureFromCookies(httptest.NewRequest(
		"GET", "/api/chart/ban:1?sig="+url.QueryEscape(forged), nil)), 0); maxDays != 3650 {
		t.Fatalf("the forged signature is not actually a forgery worth testing: it bought %d days unverified", maxDays)
	}

	// Named in the query, the way a link would carry it.
	r := httptest.NewRequest("GET", "/api/chart/ban:1?sig="+url.QueryEscape(forged), nil)
	if sig := verifiedRequestSignature(r); sig != "" {
		t.Errorf("a forged query signature was accepted: %q", sig)
	}
	if _, maxDays := chartWindow(verifiedRequestSignature(r), 0); maxDays != 30 {
		t.Errorf("a forged query signature bought %d days, want the 30-day fallback", maxDays)
	}

	// And in the cookie, the way the page's own fetch would carry it.
	r = httptest.NewRequest("GET", "/api/chart/ban:1", nil)
	r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: forged})
	if _, maxDays := chartWindow(verifiedRequestSignature(r), 0); maxDays != 30 {
		t.Errorf("a forged cookie signature bought %d days, want the 30-day fallback", maxDays)
	}
}

// The page renders the window the date-range select starts on, so what it
// renders and what the control says have to agree.
func TestDefaultChartRangeMatchesTheSelect(t *testing.T) {
	if defaultChartRange != 180 {
		t.Errorf("defaultChartRange = %d; the dateRange select in search.html starts on 180", defaultChartRange)
	}
}

// The page renders the range the viewer last chose, not the one the select
// happens to start on. Getting this wrong is not a correctness bug, it is a
// chart that draws twice on every load for anyone who ever widened one.
func TestChartInitialRangeFollowsTheViewersChoice(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie string
		value  string
		multi  bool
		want   int
	}{
		{"no cookie starts a single chart where its select does", "", "", false, defaultChartRange},
		{"no cookie starts a roster on All", "", "", true, 0},
		{"a saved range is what gets rendered", "SearchChartRange", "1825", false, 1825},
		{"a roster keeps its own saved range", "SearchChartMultiRange", "365", true, 365},
		{"All saved on a roster stays All", "SearchChartMultiRange", "0", true, 0},
		{"the single-card cookie does not steer a roster", "SearchChartRange", "30", true, 0},
		{"nonsense falls back", "SearchChartRange", "twelve", false, defaultChartRange},
		{"and so does a negative", "SearchChartRange", "-5", false, defaultChartRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/search?chart=ban:1", nil)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: tc.cookie, Value: tc.value})
			}
			if got := chartInitialRange(r, tc.multi); got != tc.want {
				t.Errorf("chartInitialRange = %d, want %d", got, tc.want)
			}
		})
	}
}

// Whatever the cookie says, it is still only a request: the tier decides.
func TestChartInitialRangeIsStillClampedToTheTier(t *testing.T) {
	defer func(dev, sigcheck bool) { DevMode, SigCheck = dev, sigcheck }(DevMode, SigCheck)
	DevMode, SigCheck = false, true

	r := httptest.NewRequest("GET", "/search?chart=ban:1", nil)
	r.AddCookie(&http.Cookie{Name: "SearchChartRange", Value: "3650"})

	window, maxDays := chartWindow("", chartInitialRange(r, false))
	if window.Days() != 30 || maxDays != 30 {
		t.Errorf("window=%d maxDays=%d, want both cut to the 30-day ceiling", window.Days(), maxDays)
	}
}

func TestChartRangeParam(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 0},
		{"?range=90", 90},
		{"?range=0", 0},
		{"?range=-5", 0},
		{"?range=notanumber", 0},
	} {
		r := httptest.NewRequest("GET", "/api/chart/x"+tc.query, nil)
		if got := chartRangeParam(r); got != tc.want {
			t.Errorf("chartRangeParam(%q) = %d, want %d", tc.query, got, tc.want)
		}
	}
}

// A day a provider did not quote has to reach the front-end as a hole in the
// line. It is also most of a long chart, so how it is spelled is most of the
// payload: `null` is what Chart.js reads as a gap, and is four bytes where the
// sentinel string this used to emit was thirteen.
func TestChartPointMarshalsGapsAsNull(t *testing.T) {
	data := []ChartPoint{
		{Price: 12.34, Known: true},
		{},
		{Price: 0, Known: true},
		{Price: 1234.5, Known: true},
	}
	got, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `[12.34,null,0,1234.5]`
	if string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

// The API is a typed response, so what it writes it has to be able to read.
// The quoted form is accepted too: responses carry an hour of cache, so one
// sent before gaps became null can still be read back during a deploy.
func TestChartPointRoundTrips(t *testing.T) {
	want := []ChartPoint{{Price: 12.34, Known: true}, {}, {Price: 0, Known: true}}
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got []ChartPoint
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("round trip gave %+v, want %+v", got, want)
	}

	var legacy []ChartPoint
	if err := json.Unmarshal([]byte(`["12.34","Number.NaN"]`), &legacy); err != nil {
		t.Fatalf("Unmarshal of the quoted form: %v", err)
	}
	if !slices.Equal(legacy, []ChartPoint{{Price: 12.34, Known: true}, {}}) {
		t.Errorf("the quoted form read back as %+v", legacy)
	}
}

// A price of zero is a price, not a gap: a buylist that stops paying for a card
// is a real observation, and drawing it as a hole would hide it.
func TestChartPointKeepsAZeroPrice(t *testing.T) {
	results := map[string]timeseries.ProviderPrices{
		"2026-09-24": {3: 0},
	}
	if got := priceAt(results, "2026-09-24", 3); !got.Known || got.Price != 0 {
		t.Errorf("priceAt = %+v, want a known 0", got)
	}
	if got := priceAt(results, "2026-09-24", 4); got.Known {
		t.Errorf("priceAt for an unquoted provider = %+v, want a gap", got)
	}
	if got := priceAt(results, "2026-09-23", 3); got.Known {
		t.Errorf("priceAt for an unquoted day = %+v, want a gap", got)
	}
}

// The API carries both of a roster line's identities, so the page can rebuild
// the same per-card, per-reference structure it renders inline. A dataset with
// no points at all is left out rather than sent empty.
func TestChartAPIDatasetsCarryRosterIdentity(t *testing.T) {
	out := chartAPIDatasets([]Dataset{
		{Name: "Card A", CardID: "ban:1", Reference: "TCG Low", Color: "red", Data: []ChartPoint{{Price: 1, Known: true}}},
		{Name: "Card B", CardID: "ban:2", Reference: "TCG Low", Color: "blue"},
		{Name: "Card A", CardID: "ban:1", Reference: "CK Buy", Color: "red", Data: []ChartPoint{{}}},
	})
	if len(out) != 2 {
		t.Fatalf("got %d datasets, want 2 (the one with no points is dropped)", len(out))
	}
	if out[0].CardID != "ban:1" || out[0].Reference != "TCG Low" {
		t.Errorf("first dataset = %+v, want cardId ban:1 / reference TCG Low", out[0])
	}
	if out[1].Reference != "CK Buy" {
		t.Errorf("second dataset reference = %q, want CK Buy", out[1].Reference)
	}
}

// Single-card charts say nothing about card or reference, so those fields stay
// out of the JSON rather than going over as empty strings.
func TestChartAPIDatasetOmitsRosterFieldsWhenUnset(t *testing.T) {
	out := chartAPIDatasets([]Dataset{
		{Name: "TCG Low", Color: "red", Data: []ChartPoint{{Price: 1, Known: true}}},
	})
	blob, err := json.Marshal(out[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"name":"TCG Low","data":[1],"color":"red"}`
	if string(blob) != want {
		t.Errorf("Marshal = %s, want %s", blob, want)
	}
}
