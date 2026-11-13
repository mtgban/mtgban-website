package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
	"golang.org/x/time/rate"
)

func TestClientMaySend(t *testing.T) {
	for _, c := range []struct {
		n    observability.Name
		want bool
	}{
		{observability.Name{Name: "ui.x", Family: observability.FamilyUI}, true},
		{observability.Name{Name: "state.set", Family: observability.FamilyState}, true},
		{observability.Name{Name: "state.reader", Family: observability.FamilyState}, true},
		{observability.Name{Name: "state.other", Family: observability.FamilyState}, false}, // a state name the snapshot does not send
		{observability.Name{Name: "state.set", Family: observability.FamilyServer}, false},
		{observability.Name{Name: "page.view", Family: observability.FamilyServer}, false},
		{observability.Name{Name: "stock.rows", Family: observability.FamilyStock}, false},
	} {
		if got := clientMaySend(c.n); got != c.want {
			t.Errorf("clientMaySend(%s, family %v) = %v, want %v", c.n.Name, c.n.Family, got, c.want)
		}
	}
	for _, n := range observability.All() {
		if n.Family == observability.FamilyState && !clientMaySend(n) {
			t.Errorf("%s is a state name the beacon refuses; only the snapshot's are registered", n.Name)
		}
	}
}

// loads is a body of n ui.load entries.
func loads(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(`{"n":"ui.load","s":"search","c":1},`, n), ",") + "]"
}

func TestDecodeBeacon(t *testing.T) {
	for _, c := range []struct {
		name, body string
		entries    int
		outcome    string
	}{
		{"one entry", `[{"n":"ui.load","s":"search","c":1}]`, 1, "ok"},
		{"keys from a newer script", `[{"n":"ui.load","s":"search","c":1,"l":12,"b":"abc"}]`, 1, "ok"},
		{"nested junk in an unknown key", `[{"n":"ui.load","s":"search","c":1,"x":[[[[{"y":[1,{"z":null}]}]]]]}]`, 1, "ok"},
		{"a duplicate key", `[{"n":"ui.nope","n":"ui.load","s":"search","c":1}]`, 1, "ok"},
		{"an empty array", `[]`, 0, "ok"},
		{"null", `null`, 0, "ok"},
		{"a hundred entries", loads(100), 100, "ok"},
		{"a hundred and one", loads(101), 0, "too_many"},
		{"not JSON", `q=bolt`, 0, "bad_body"},
		{"an object", `{"n":"ui.load","c":1}`, 0, "bad_body"},
		{"an empty body", ``, 0, "bad_body"},
		{"a number in the array", `[1]`, 0, "bad_body"},
		{"an array in the array", `[[{"n":"ui.load","s":"search","c":1}]]`, 0, "bad_body"},
		{"a count that is a string", `[{"n":"ui.load","s":"search","c":"1"}]`, 0, "bad_body"},
		{"a fractional count", `[{"n":"ui.load","s":"search","c":1.5}]`, 0, "bad_body"},
		{"a count past int64", `[{"n":"ui.load","s":"search","c":1e30}]`, 0, "bad_body"},
		{"a name that is a number", `[{"n":7,"s":"search","c":1}]`, 0, "bad_body"},
		{"trailing bytes", `[] []`, 0, "bad_body"},
		{"a cut-off array", `[{"n":"ui.load"`, 0, "bad_body"},
	} {
		entries, outcome := decodeBeacon([]byte(c.body))
		if outcome != c.outcome || len(entries) != c.entries {
			t.Errorf("%s: got (%d entries, %q), want (%d, %q)", c.name, len(entries), outcome, c.entries, c.outcome)
		}
	}
	entries, _ := decodeBeacon([]byte(`[{"n":"ui.x","s":"a","v":"b","c":7}]`))
	if e := entries[0]; e.N != "ui.x" || e.S != "a" || e.V != "b" || e.C != 7 {
		t.Errorf("fields read as %+v", e)
	}
}

func TestCheckEntry(t *testing.T) {
	v := observability.Validators{
		Page:  func(s string) bool { return s == "search" },
		Route: func(s string) bool { return s == "search" },
	}
	long := strings.Repeat("a", 41)
	for _, c := range []struct {
		name         string
		e            beaconEntry
		scope, value string
		n            int64
		reason       string
	}{
		{"one load", beaconEntry{N: "ui.load", S: "search", C: 1}, "search", "", 1, ""},
		{"the top count", beaconEntry{N: "ui.load", S: "search", C: 50}, "search", "", 50, ""},
		{"a count over the cap is stored as the cap", beaconEntry{N: "ui.load", S: "search", C: 5000}, "search", "", 50, ""},
		{"a huge count is stored as the cap", beaconEntry{N: "ui.load", S: "search", C: 1 << 62}, "search", "", 50, ""},
		{"an unknown page folds to other", beaconEntry{N: "ui.load", S: "/wp-login.php", C: 1}, "other", "", 1, ""},
		{"no count", beaconEntry{N: "ui.load", S: "search"}, "", "", 0, "count"},
		{"a negative count", beaconEntry{N: "ui.load", S: "search", C: -3}, "", "", 0, "count"},
		{"the most negative count", beaconEntry{N: "ui.load", S: "search", C: -1 << 63}, "", "", 0, "count"},
		{"a name the registry lacks", beaconEntry{N: "ui.nope", C: 1}, "", "", 0, "unknown"},
		{"an unknown name with a bad count", beaconEntry{N: "ui.nope"}, "", "", 0, "unknown"},
		{"no name", beaconEntry{S: "search", C: 1}, "", "", 0, "unknown"},
		{"a name in capitals", beaconEntry{N: "UI.LOAD", S: "search", C: 1}, "", "", 0, "unknown"},
		{"a name with a trailing space", beaconEntry{N: "ui.load ", S: "search", C: 1}, "", "", 0, "unknown"},
		{"a name with a NUL", beaconEntry{N: "ui.load\x00", S: "search", C: 1}, "", "", 0, "unknown"},
		{"a name over 40 characters", beaconEntry{N: "ui." + long, C: 1}, "", "", 0, "unknown"},
		{"a name with a non-ASCII letter", beaconEntry{N: "ui.loаd", S: "search", C: 1}, "", "", 0, "unknown"},
		{"a value where none is allowed", beaconEntry{N: "ui.load", S: "search", V: "<script>", C: 1}, "", "", 0, "value"},
		{"a load with no page", beaconEntry{N: "ui.load", C: 1}, "", "", 0, "value"},
		{"a page over 40 characters", beaconEntry{N: "ui.load", S: long, C: 1}, "", "", 0, "value"},
		{"a page with a newline", beaconEntry{N: "ui.load", S: "search\n", C: 1}, "", "", 0, "value"},
		{"a value over 40 characters", beaconEntry{N: "ui.load", S: "search", V: long, C: 1}, "", "", 0, "value"},
		{"a bad page with a bad count", beaconEntry{N: "ui.load", S: long, C: -1}, "", "", 0, "value"},
	} {
		scope, value, n, reason := checkEntry(c.e, v)
		if scope != c.scope || value != c.value || n != c.n || reason != c.reason {
			t.Errorf("%s: got (%q, %q, %d, %q), want (%q, %q, %d, %q)", c.name, scope, value, n, reason, c.scope, c.value, c.n, c.reason)
		}
	}
}

// A browser can never write a server fact, a stored-state count or the counter's own rows.
func TestCheckEntryRefusesEveryFamilyButTheClients(t *testing.T) {
	v := metricValidators(nil)
	for _, e := range []beaconEntry{
		{N: "http.status", S: "search", V: "2xx", C: 1},
		{N: "page.view", V: "search", C: 1},
		{N: "ratelimit.reject", V: "metrics", C: 1},
		{N: "auth.login", V: "ok", C: 1},
		{N: "search.mode", S: "search", V: "default", C: 1},
		{N: "job.run", S: "fold", V: "ok", C: 1},
		{N: "stock.rows", C: 1},
		{N: "stock.pref", V: "x", C: 1},
		{N: "metrics.flush", C: 1},
		{N: "metrics.rejected", C: 1},
		{N: "metrics.dropped", C: 1},
		{N: "metrics.flush_fail", C: 1},
		{N: "metrics.beacon", V: "ok", C: 1},
		{N: "metrics.client", V: "accepted", C: 1},
		{N: "http.status", S: "search", V: "2xx"}, // a bad count still reads as the family
	} {
		if _, _, _, reason := checkEntry(e, v); reason != "family" {
			t.Errorf("%s: reason %q, want family", e.N, reason)
		}
	}
	for _, n := range observability.All() {
		_, _, _, reason := checkEntry(beaconEntry{N: n.Name, C: 1}, v)
		if refused := reason == "family"; refused == clientMaySend(n) {
			t.Errorf("%s: reason %q for family %v", n.Name, reason, n.Family)
		}
	}
}

// withOpenBeaconLimiter lets every beacon through for the rest of the test.
func withOpenBeaconLimiter(t *testing.T) {
	t.Helper()
	saved := metricsLimiter
	t.Cleanup(func() { metricsLimiter = saved })
	metricsLimiter = ratelimit.NewLimiter(rate.Inf, 1)
}

// beacon is a same-origin beacon from one fixed public address.
func beacon(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/metrics", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.RemoteAddr = "198.51.100.7:40000"
	return r
}

// postBeacon serves r and returns its status.
func postBeacon(t *testing.T, r *http.Request) int {
	t.Helper()
	w := httptest.NewRecorder()
	testSite.MetricsAPI(w, r)
	return w.Code
}

func TestMetricsAPIStoresWhatTheRegistryAllows(t *testing.T) {
	signingEnabled(t, false)
	installAccess(t, `{"Any": {}, "Legacy": {}}`, `[]`)
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	sig := signedAs(t, url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Legacy"}}, time.Now().Add(time.Hour))
	// The tier and device keys in the body are ignored: dimensions come from the request.
	r := beacon(`[{"n":"ui.load","s":"search","c":3,"tier":"Admin","device":"desktop"},` +
		`{"n":"http.status","s":"search","v":"2xx","c":1},{"n":"ui.nope","c":1}]`)
	r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
	r.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	if code := postBeacon(t, r); code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", code)
	}
	got := rows.rows()
	want := observability.Row{
		Dims:  observability.Dims{Instance: "test", Tier: "Legacy", Device: "mobile", Signed: true},
		Scope: "search", Name: "ui.load", N: 3,
	}
	if loaded := find(got, "ui.load"); len(loaded) != 1 || loaded[0] != want {
		t.Errorf("ui.load rows = %+v, want [%+v]", loaded, want)
	}
	wantNoRow(t, got, "http.status")
	wantNoRow(t, got, "page.view")
	wantRow(t, got, "", "metrics.client", "accepted", 1)
	wantRow(t, got, "", "metrics.client", "family", 1)
	wantRow(t, got, "", "metrics.client", "unknown", 1)
	wantRow(t, got, "", "metrics.beacon", "ok", 1)
	wantRow(t, got, "", "metrics.rejected", "", 2)
	for _, row := range find(got, "metrics.client") {
		if row.Tier != "Legacy" || row.Device != "mobile" || !row.Signed {
			t.Errorf("metrics.client row %+v does not carry the request's dimensions", row)
		}
	}
}

// No family but the client's is ever stored, whatever the body claims.
func TestMetricsAPIRefusesEveryOtherFamily(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	entries := []string{
		`{"n":"http.status","s":"api.metrics","v":"2xx","c":37}`,
		`{"n":"page.view","v":"search","c":37}`,
		`{"n":"ratelimit.reject","v":"metrics","c":37}`,
		`{"n":"job.run","s":"fold","v":"ok","c":37}`,
		`{"n":"stock.rows","c":37}`,
		`{"n":"metrics.flush","c":37}`,
		`{"n":"metrics.rejected","c":37}`,
		`{"n":"metrics.dropped","c":37}`,
		`{"n":"metrics.beacon","v":"ok","c":37}`,
		`{"n":"metrics.client","v":"accepted","c":37}`,
	}
	if code := postBeacon(t, beacon("["+strings.Join(entries, ",")+"]")); code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", code)
	}
	got := rows.rows()
	for _, row := range got {
		if row.N == 37 {
			t.Errorf("a row was stored as a client sent it: %+v", row)
		}
	}
	for _, name := range []string{"http.status", "page.view", "ratelimit.reject", "job.run", "stock.rows"} {
		wantNoRow(t, got, name)
	}
	wantRow(t, got, "", "metrics.client", "family", int64(len(entries)))
	wantRow(t, got, "", "metrics.rejected", "", int64(len(entries)))
	wantRow(t, got, "", "metrics.beacon", "ok", 1)
	if client := find(got, "metrics.client"); len(client) != 1 {
		t.Errorf("metrics.client rows = %+v, want only the family one", client)
	}
}

func TestMetricsAPIRefusals(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	get := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	get.RemoteAddr = "198.51.100.7:40000"
	crossSite := beacon(loads(1))
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	sameSite := beacon(loads(1))
	sameSite.Header.Set("Sec-Fetch-Site", "same-site")
	foreignOrigin := beacon(loads(1))
	foreignOrigin.Header.Del("Sec-Fetch-Site")
	foreignOrigin.Header.Set("Origin", "https://evil.example")
	siblingOrigin := beacon(loads(1))
	siblingOrigin.Header.Del("Sec-Fetch-Site")
	siblingOrigin.Header.Set("Origin", "https://lorcana."+siblingOrigin.Host)
	noAddress := beacon(loads(1))
	noAddress.RemoteAddr = "nonsense"
	for name, c := range map[string]struct {
		r    *http.Request
		want int
	}{
		"GET": {get, 405}, "cross-site": {crossSite, 403}, "same-site": {sameSite, 403},
		"another origin": {foreignOrigin, 403}, "a sibling site's origin": {siblingOrigin, 403},
		"no address": {noAddress, 400},
	} {
		if code := postBeacon(t, c.r); code != c.want {
			t.Errorf("%s: status %d, want %d", name, code, c.want)
		}
	}
	got := rows.rows()
	for _, name := range []string{"ui.load", "metrics.beacon", "metrics.client", "metrics.rejected", "ratelimit.reject"} {
		wantNoRow(t, got, name)
	}
}

func TestMetricsAPIAnswers204ToABadBody(t *testing.T) {
	withOpenBeaconLimiter(t)
	entry := `{"n":"ui.load","s":"search","c":1}`
	t.Run("bad bodies", func(t *testing.T) {
		rows := withFeatureCounter(t)
		over := "[" + entry + strings.Repeat(" ", metricsMaxBody-len(entry)-1) + "]"
		if len(over) != metricsMaxBody+1 {
			t.Fatalf("the oversized body is %d bytes", len(over))
		}
		for _, body := range []string{over, "not json", loads(101)} {
			if code := postBeacon(t, beacon(body)); code != http.StatusNoContent {
				t.Errorf("status %d for a %d-byte body, want 204", code, len(body))
			}
		}
		got := rows.rows()
		wantRow(t, got, "", "metrics.beacon", "bad_body", 2)
		wantRow(t, got, "", "metrics.beacon", "too_many", 1)
		wantNoRow(t, got, "ui.load")
		wantNoRow(t, got, "metrics.client")
	})
	t.Run("a body at the cap", func(t *testing.T) {
		rows := withFeatureCounter(t)
		body := "[" + entry + strings.Repeat(" ", metricsMaxBody-len(entry)-2) + "]"
		if len(body) != metricsMaxBody {
			t.Fatalf("the body is %d bytes", len(body))
		}
		if code := postBeacon(t, beacon(body)); code != http.StatusNoContent {
			t.Errorf("status %d, want 204", code)
		}
		got := rows.rows()
		wantRow(t, got, "search", "ui.load", "", 1)
		wantRow(t, got, "", "metrics.beacon", "ok", 1)
	})
}

func TestMetricsAPILimitsEachClient(t *testing.T) {
	saved := metricsLimiter
	t.Cleanup(func() { metricsLimiter = saved })
	metricsLimiter = ratelimit.NewLimiter(rate.Every(time.Hour), 20)
	rows := withFeatureCounter(t)
	t.Setenv("BAN_CLIENT_IP_HEADER", "DO-Connecting-IP")
	post := func(client string) int {
		r := viaAppPlatform("/api/metrics", "", client)
		r.Method = http.MethodPost
		r.Body = io.NopCloser(strings.NewReader(`[]`))
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		return postBeacon(t, r)
	}
	for i := range 20 {
		if code := post("203.0.113.50"); code != http.StatusNoContent {
			t.Fatalf("request %d of the burst: status %d", i+1, code)
		}
	}
	if code := post("203.0.113.50"); code != http.StatusTooManyRequests {
		t.Errorf("the 21st request: status %d, want 429", code)
	}
	if code := post("203.0.113.51"); code != http.StatusNoContent {
		t.Errorf("another client behind the same ingress: status %d, want 204", code)
	}
	got := rows.rows()
	wantRow(t, got, "", "ratelimit.reject", "metrics", 1)
	wantRow(t, got, "", "metrics.beacon", "ok", 21)
}

func TestMetricsAPIWithNoCounter(t *testing.T) {
	withOpenBeaconLimiter(t)
	saved := FeatureCounter
	t.Cleanup(func() { FeatureCounter = saved })
	FeatureCounter = nil
	if code := postBeacon(t, beacon(loads(1))); code != http.StatusNoContent {
		t.Errorf("status %d, want 204", code)
	}
}

// The script posts text/plain, which noSigning's FormValue leaves unread.
func TestMetricsAPIBehindNoSigning(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	w := httptest.NewRecorder()
	noSigning(http.HandlerFunc(testSite.MetricsAPI)).ServeHTTP(w, beacon(loads(1)))
	if w.Code != http.StatusNoContent {
		t.Errorf("status %d, want 204", w.Code)
	}
	wantRow(t, rows.rows(), "search", "ui.load", "", 1)
}

// A store a client names is checked against the stores this instance loaded.
func TestBeaconValidatorsReadTheLoadedStores(t *testing.T) {
	setTestVendors(t, buylistOf("CK", 1, time.Now()))
	v := beaconValidators(testSite)
	if !v.Store("CK") {
		t.Error("a loaded vendor's shorthand is refused")
	}
	if v.Store("NOPE") || v.Store("<script>") {
		t.Error("a shorthand nothing loaded is accepted")
	}
	if v.Page == nil || v.Route == nil {
		t.Error("the page and route checks are missing")
	}
}

func TestMetricsRouteHasALabel(t *testing.T) {
	if got := routeLabel("/api/metrics", "/api/metrics"); got != "api.metrics" {
		t.Errorf("routeLabel = %q, want api.metrics", got)
	}
	// Exact, so a later /api/metrics/... path is a pattern of its own.
	if _, ok := routeLabels["/api/metrics/"]; ok {
		t.Error("/api/metrics/ is a subtree pattern: it would take every path under it")
	}
}

// An older browser's sendBeacon sends neither Sec-Fetch-Site nor Origin.
func TestMetricsAPIAcceptsABeaconWithNoOriginHeaders(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	r := beacon(loads(1))
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Del("Origin")
	if code := postBeacon(t, r); code != http.StatusNoContent {
		t.Errorf("status %d, want 204", code)
	}
	wantRow(t, rows.rows(), "search", "ui.load", "", 1)
}

// A post adds at most the per-entry cap to a key, however often the body repeats it.
func TestMetricsAPICountsAKeyOncePerPost(t *testing.T) {
	withOpenBeaconLimiter(t)
	t.Run("a hundred copies", func(t *testing.T) {
		rows := withFeatureCounter(t)
		if code := postBeacon(t, beacon(loads(100))); code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", code)
		}
		got := rows.rows()
		wantRow(t, got, "search", "ui.load", "", metricsMaxCount)
		wantRow(t, got, "", "metrics.client", "accepted", metricsMaxCount)
		wantRow(t, got, "", "metrics.client", "count", 100-metricsMaxCount)
		wantRow(t, got, "", "metrics.rejected", "", 100-metricsMaxCount)
	})
	t.Run("repeats that pass the cap", func(t *testing.T) {
		rows := withFeatureCounter(t)
		body := `[{"n":"ui.load","s":"search","c":30},{"n":"ui.load","s":"search","c":30},` +
			`{"n":"ui.load","s":"search","c":1},{"n":"ui.load","s":"/a","c":40},{"n":"ui.load","s":"/b","c":40}]`
		if code := postBeacon(t, beacon(body)); code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", code)
		}
		got := rows.rows()
		wantRow(t, got, "search", "ui.load", "", metricsMaxCount)
		wantRow(t, got, "other", "ui.load", "", metricsMaxCount) // two pages folded to one key
		wantRow(t, got, "", "metrics.client", "accepted", 4)
		wantRow(t, got, "", "metrics.client", "count", 1)
	})
	t.Run("another post starts afresh", func(t *testing.T) {
		rows := withFeatureCounter(t)
		for range 2 {
			postBeacon(t, beacon(loads(2)))
		}
		wantRow(t, rows.rows(), "search", "ui.load", "", 4)
	})
}

func TestMetricsSettingsIsCacheableJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	MetricsSettings(rec, httptest.NewRequest(http.MethodGet, "/api/metrics/settings.json?hash=abc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=86400" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a public answer sets a cookie")
	}
	if !bytes.Equal(rec.Body.Bytes(), observability.SettingsJSON()) {
		t.Error("the body is not the registry")
	}
}

// With no hash, as an unstamped build asks, the registry is not cached for a day.
func TestMetricsSettingsWithNoHashIsNotCached(t *testing.T) {
	for _, url := range []string{"/api/metrics/settings.json", "/api/metrics/settings.json?hash="} {
		rec := httptest.NewRecorder()
		MetricsSettings(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if got := rec.Header().Get("Cache-Control"); rec.Code != http.StatusOK || got != "no-cache" {
			t.Errorf("%s: status %d, Cache-Control %q", url, rec.Code, got)
		}
	}
}

func TestMetricsSettingsRefusesAPost(t *testing.T) {
	rec := httptest.NewRecorder()
	MetricsSettings(rec, httptest.NewRequest(http.MethodPost, "/api/metrics/settings.json", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// The snapshot's two names are stored; a setting value that is not the registry's is refused.
func TestMetricsAPITakesASnapshot(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	body := `[{"n":"state.reader","s":"upload","c":1},` +
		`{"n":"state.set","s":"UploadSorting","v":"highprice","c":1},` +
		`{"n":"state.set","s":"gdocURL","v":"https://example.com/x","c":1},` +
		`{"n":"state.set","s":"enabledSellers","v":"set","c":1},` +
		`{"n":"state.set","s":"NoSuchSetting","v":"on","c":1}]`
	if code := postBeacon(t, beacon(body)); code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", code)
	}
	got := rows.rows()
	wantRow(t, got, "upload", "state.reader", "", 1)
	wantRow(t, got, "UploadSorting", "state.set", "highprice", 1)
	if set := find(got, "state.set"); len(set) != 1 {
		t.Errorf("state.set rows = %+v, want only UploadSorting's", set)
	}
	for _, row := range got {
		if row.Scope == "enabledSellers" {
			t.Errorf("a cookie every upload writes was stored: %+v", row)
		}
	}
	wantRow(t, got, "", "metrics.client", "accepted", 2)
	wantRow(t, got, "", "metrics.client", "value", 3)
	wantRow(t, got, "", "metrics.rejected", "", 3)
	wantRow(t, got, "", "metrics.beacon", "ok", 1)
}

// fakeErrorStore keeps every error row upserted; refuse says how many of each call it refuses.
type fakeErrorStore struct {
	mu      sync.Mutex
	written []observability.ErrorRow
	refuse  int
}

func (f *fakeErrorStore) UpsertErrors(_ context.Context, _ string, rows []observability.ErrorRow) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, rows...)
	return min(f.refuse, len(rows)), nil
}

// snapshot is a copy of the rows written so far.
func (f *fakeErrorStore) snapshot() []observability.ErrorRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.written)
}

// fakeErrors is the error buffer a test installed and its store.
type fakeErrors struct {
	t      *testing.T
	buffer *observability.ErrorBuffer
	store  *fakeErrorStore
	once   sync.Once
}

// withFeatureErrors installs an error buffer over a fake store as FeatureErrors, its
// refusals counted through rejectChecked, testBuild as this binary's; call it after withFeatureCounter.
func withFeatureErrors(t *testing.T) *fakeErrors {
	t.Helper()
	withBuildCommit(t, testBuild)
	prev := FeatureErrors
	t.Cleanup(func() { FeatureErrors = prev })
	now := time.Date(2026, 11, 11, 12, 0, 30, 0, time.UTC)
	f := &fakeErrors{t: t, store: &fakeErrorStore{}}
	f.buffer = observability.NewErrorBuffer(f.store, "test", func() time.Time { return now }, rejectChecked)
	FeatureErrors = f.buffer
	return f
}

// rows closes the buffer on its first call and returns every row it wrote.
func (f *fakeErrors) rows() []observability.ErrorRow {
	f.once.Do(func() {
		if err := f.buffer.Close(context.Background()); err != nil {
			f.t.Errorf("closing the error buffer: %v", err)
		}
	})
	return f.store.snapshot()
}

// testBuild is a build hash as BuildCommit holds one.
var testBuild = strings.Repeat("0f", 20)

func TestErrorRow(t *testing.T) {
	sha, foreign := testBuild, strings.Repeat("ab", 20)
	withBuildCommit(t, sha)
	n := func(i int) *int { return &i }
	cases := []struct {
		scope  string
		line   *int
		build  string
		wantL  int
		reason string
	}{
		{"navbar.js", n(42), sha, 42, ""},
		{"navbar.js", nil, sha, 0, ""},
		{"navbar.js", n(42), sha + "-1731300000000000000", 42, ""},
		{"navbar.js", n(observability.MaxErrorLine), sha, observability.MaxErrorLine, ""},
		{"inline", n(913), sha, 0, ""}, // an inline line is the page's, not the build's
		{"other", n(1), sha, 0, ""},
		{"navbar.js", n(-1), sha, 0, "value"},
		{"navbar.js", n(observability.MaxErrorLine + 1), sha, 0, "value"},
		{"other", n(-1), sha, 0, "value"},
		{"navbar.js", n(42), "", 0, "value"},
		{"navbar.js", n(42), "-1731300000000000000", 0, "value"}, // dev with no commit
		{"navbar.js", n(42), "<script>", 0, "value"},
		{"navbar.js", n(42), strings.ToUpper(sha), 0, "value"},
		{"navbar.js", n(42), foreign, 0, "build"}, // well formed, but not this binary's
		{"navbar.js", n(42), foreign + "-1731300000000000000", 0, "build"},
	}
	for i, c := range cases {
		l, b, reason := errorRow(c.scope, c.line, c.build)
		if reason != c.reason || l != c.wantL || (reason == "" && b != sha) || (reason != "" && b != "") {
			t.Errorf("case %d: got (%d, %q, %q)", i, l, b, reason)
		}
	}

	// An unstamped binary keeps no row for any build.
	BuildCommit = ""
	for _, build := range []string{sha, foreign, "-1731300000000000000"} {
		if _, _, reason := errorRow("navbar.js", n(42), build); reason == "" {
			t.Errorf("unstamped: %q was kept", build)
		}
	}
}

// errorEntry is one ui.js.error entry on navbar.js.
func errorEntry(class string, c, line int, build string) string {
	return fmt.Sprintf(`{"n":"ui.js.error","s":"navbar.js","v":%q,"c":%d,"l":%d,"b":%q}`, class, c, line, build)
}

func TestMetricsAPIStoresAnErrorRow(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	r := beacon("[" + errorEntry("TypeError", 2, 42, testBuild) + "]")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if code := postBeacon(t, r); code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", code)
	}
	got := errs.rows()
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 2)
	wantNoRow(t, counts, "metrics.rejected")
	day := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	want := observability.ErrorRow{Day: day, Device: "desktop", Build: testBuild, Script: "navbar.js", Line: 42, Class: "TypeError", N: 2}
	if len(got) != 1 || got[0] != want {
		t.Errorf("error rows = %+v, want [%+v]", got, want)
	}
}

// Dev renders <sha>-<nanos>; the row keeps the sha.
func TestMetricsAPIStoresADevBuildAsItsCommit(t *testing.T) {
	withOpenBeaconLimiter(t)
	withFeatureCounter(t)
	errs := withFeatureErrors(t)
	postBeacon(t, beacon("["+errorEntry("TypeError", 1, 42, testBuild+"-1731300000000000000")+"]"))
	if got := errs.rows(); len(got) != 1 || got[0].Build != testBuild {
		t.Errorf("error rows = %+v, want one under the bare commit", got)
	}
}

func TestMetricsAPIKeepsTheCountWhenTheRowIsBad(t *testing.T) {
	withOpenBeaconLimiter(t)
	for _, entry := range []string{
		errorEntry("TypeError", 1, 42, "nope"),
		errorEntry("TypeError", 1, 42, ""),
		errorEntry("TypeError", 1, -4, testBuild),
		errorEntry("TypeError", 1, observability.MaxErrorLine+1, testBuild),
		`{"n":"ui.js.error","s":"navbar.js","v":"TypeError","c":1}`, // no line or build
	} {
		rows := withFeatureCounter(t)
		errs := withFeatureErrors(t)
		postBeacon(t, beacon("["+entry+"]"))
		if got := errs.rows(); len(got) != 0 {
			t.Errorf("%s: error rows = %+v, want none", entry, got)
		}
		counts := rows.rows()
		wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 1)
		wantRow(t, counts, "", "metrics.client", "accepted", 1)
		wantRow(t, counts, "", "metrics.rejected", "", 1)
	}
}

func TestMetricsAPIRefusesLineAndBuildOnOtherNames(t *testing.T) {
	withOpenBeaconLimiter(t)
	for _, entry := range []string{
		`{"n":"ui.load","s":"search","c":1,"l":3,"b":"` + testBuild + `"}`,
		`{"n":"ui.load","s":"search","c":1,"l":3}`,
		`{"n":"ui.load","s":"search","c":1,"l":0}`,
		`{"n":"ui.load","s":"search","c":1,"b":"` + testBuild + `"}`,
	} {
		rows := withFeatureCounter(t)
		errs := withFeatureErrors(t)
		postBeacon(t, beacon("["+entry+"]"))
		if got := errs.rows(); len(got) != 0 {
			t.Errorf("%s: error rows = %+v, want none", entry, got)
		}
		counts := rows.rows()
		wantNoRow(t, counts, "ui.load")
		wantRow(t, counts, "", "metrics.client", "value", 1)
		wantRow(t, counts, "", "metrics.rejected", "", 1)
	}
}

// What an old cached script sends, with neither field, is counted as before.
func TestMetricsAPIAcceptsEntriesWithNoLineOrBuild(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	withFeatureErrors(t)
	postBeacon(t, beacon(`[{"n":"ui.load","s":"search","c":2}]`))
	counts := rows.rows()
	wantRow(t, counts, "search", "ui.load", "", 2)
	wantNoRow(t, counts, "metrics.rejected")
}

func TestMetricsAPINeverStoresAMessage(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	postBeacon(t, beacon("["+errorEntry("x is not a function", 1, 1, testBuild)+","+
		`{"n":"ui.js.error","s":"https://evil.example/a.js?q=1","v":"TypeError","c":1,"l":1,"b":"`+testBuild+`"}]`))
	if got := errs.rows(); len(got) != 0 {
		t.Errorf("error rows = %+v, want none", got)
	}
	counts := rows.rows()
	wantNoRow(t, counts, "ui.js.error")
	wantRow(t, counts, "", "metrics.rejected", "", 2)
}

func TestMetricsAPISkipsErrorRowsFromBots(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	r := beacon("[" + errorEntry("TypeError", 1, 42, testBuild) + "]")
	r.Header.Set("User-Agent", "Googlebot/2.1")
	postBeacon(t, r)
	if got := errs.rows(); len(got) != 0 {
		t.Errorf("error rows = %+v, want none from a bot", got)
	}
	counts := rows.rows()
	if got := find(counts, "ui.js.error"); len(got) != 1 || !got[0].Bot || got[0].N != 1 {
		t.Errorf("ui.js.error rows = %+v, want one counted as a bot", got)
	}
	wantNoRow(t, counts, "metrics.rejected")
}

func TestMetricsAPIWithNoErrorBuffer(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	withBuildCommit(t, testBuild)
	prev := FeatureErrors
	t.Cleanup(func() { FeatureErrors = prev })
	FeatureErrors = nil
	if code := postBeacon(t, beacon("["+errorEntry("TypeError", 1, 42, testBuild)+"]")); code != http.StatusNoContent {
		t.Errorf("status %d, want 204", code)
	}
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 1)
	wantNoRow(t, counts, "metrics.rejected")
}

// Each line is its own key: two lines at the cap are both stored in full; another build's row is refused.
func TestMetricsAPIKeysAnErrorByLineAndBuild(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	other := strings.Repeat("ab", 20)
	postBeacon(t, beacon("["+errorEntry("TypeError", 50, 42, testBuild)+","+errorEntry("TypeError", 50, 43, testBuild)+","+
		errorEntry("TypeError", 50, 42, other)+","+errorEntry("TypeError", 50, 42, testBuild)+"]"))
	got := errs.rows()
	if len(got) != 2 {
		t.Fatalf("error rows = %+v, want two", got)
	}
	for _, row := range got {
		if row.N != metricsMaxCount {
			t.Errorf("row %+v, want N %d", row, metricsMaxCount)
		}
	}
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 3*metricsMaxCount)
	wantRow(t, counts, "", "metrics.client", "count", 1) // the repeat of the first key
	wantRow(t, counts, "", "metrics.rejected", "", 2)    // the repeat, and the other build's row
}

// A row for another build is refused; its count is kept.
func TestMetricsAPIRefusesARowForAnotherBuild(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	postBeacon(t, beacon("["+errorEntry("TypeError", 1, 42, strings.Repeat("ab", 20))+"]"))
	if got := errs.rows(); len(got) != 0 {
		t.Errorf("error rows = %+v, want none", got)
	}
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 1)
	wantRow(t, counts, "", "metrics.client", "accepted", 1)
	wantRow(t, counts, "", "metrics.rejected", "", 1)
}

// A post adds at most metricsMaxErrorEntries error entries; the rest are refused as count.
func TestMetricsAPICapsErrorEntriesPerPost(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	var entries []string
	for i := range metricsMaxErrorEntries + 5 {
		entries = append(entries, errorEntry("TypeError", 1, i+1, testBuild))
	}
	entries = append(entries, `{"n":"ui.load","s":"search","c":1}`)
	postBeacon(t, beacon("["+strings.Join(entries, ",")+"]"))
	if got := errs.rows(); len(got) != metricsMaxErrorEntries {
		t.Errorf("%d error rows, want %d", len(got), metricsMaxErrorEntries)
	}
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", metricsMaxErrorEntries)
	wantRow(t, counts, "search", "ui.load", "", 1)
	wantRow(t, counts, "", "metrics.client", "count", 5)
	wantRow(t, counts, "", "metrics.client", "accepted", metricsMaxErrorEntries+1)
	wantRow(t, counts, "", "metrics.rejected", "", 5)
}

// A row the store refuses is counted as rejected; its count stays accepted.
func TestMetricsAPICountsARowTheStoreRefuses(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	errs.store.refuse = 1
	postBeacon(t, beacon("["+errorEntry("TypeError", 1, 42, testBuild)+"]"))
	errs.rows()
	counts := rows.rows()
	wantRow(t, counts, "navbar.js", "ui.js.error", "TypeError", 1)
	wantRow(t, counts, "", "metrics.client", "accepted", 1)
	wantRow(t, counts, "", "metrics.rejected", "", 1)
}

// The error buffer closes before the counter, so its refusals reach the counter's last flush.
func TestShutdownClosesTheErrorsBeforeTheCounter(t *testing.T) {
	withOpenBeaconLimiter(t)
	rows := withFeatureCounter(t)
	errs := withFeatureErrors(t)
	errs.store.refuse = 1
	postBeacon(t, beacon("["+errorEntry("TypeError", 1, 42, testBuild)+"]"))
	prev := discordCleanup
	t.Cleanup(func() { discordCleanup = prev })
	discordCleanup = func() {}
	(&site{}).shutdownTelemetry(context.Background())
	if got := errs.store.snapshot(); len(got) != 1 {
		t.Errorf("error rows written by the shutdown = %+v, want one", got)
	}
	wantRow(t, rows.store.snapshot(), "", "metrics.rejected", "", 1)
}
