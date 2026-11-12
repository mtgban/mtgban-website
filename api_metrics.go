package main

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"

	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

const (
	metricsMaxBody    = 8 << 10 // bytes
	metricsMaxEntries = 100
	metricsMaxCount   = 50
	metricsMaxString  = 40
)

// beaconEntry is one count on the wire.
type beaconEntry struct {
	N string `json:"n"`
	S string `json:"s"`
	V string `json:"v"`
	C int    `json:"c"`
}

// clientStateNames are the state names a browser sends: the settings snapshot.
var clientStateNames = []string{"state.set", "state.reader"}

// clientMaySend reports whether a browser may send this name: the ui family and the snapshot's two.
func clientMaySend(n observability.Name) bool {
	return n.Family == observability.FamilyUI || (n.Family == observability.FamilyState && slices.Contains(clientStateNames, n.Name))
}

// clientString reports whether s is short printable ASCII, as every registry string is.
func clientString(s string) bool {
	if len(s) > metricsMaxString {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// decodeBeacon reads a body into its entries and says how it read:
// ok, bad_body or too_many.
func decodeBeacon(body []byte) (entries []beaconEntry, outcome string) {
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, "bad_body"
	}
	if len(entries) > metricsMaxEntries {
		return nil, "too_many"
	}
	return entries, "ok"
}

// checkEntry returns what to store for one entry, or why it is refused.
// An empty reason means it is stored.
func checkEntry(e beaconEntry, v observability.Validators) (scope, value string, n int64, reason string) {
	if !clientString(e.N) {
		return "", "", 0, "unknown"
	}
	name, ok := observability.Lookup(e.N)
	if !ok {
		return "", "", 0, "unknown"
	}
	if !clientMaySend(name) {
		return "", "", 0, "family"
	}
	if !clientString(e.S) || !clientString(e.V) {
		return "", "", 0, "value"
	}
	scope, value, ok = name.Check(e.S, e.V, v)
	if !ok {
		return "", "", 0, "value"
	}
	if e.C < 1 {
		return "", "", 0, "count"
	}
	return scope, value, int64(min(e.C, metricsMaxCount)), ""
}

// metricsLimiter throttles beacons per client; the burst covers a restored window of tabs.
var metricsLimiter = ratelimit.NewLimiter(1, 20)

// MetricsAPI stores a page script's counts; past the door checks it always answers 204.
func (s *site) MetricsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if crossSitePost(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ip, err := apiLimitAddress(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !metricsLimiter.Allow(ip.String()) {
		observe(r, "ratelimit.reject", "metrics")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	defer w.WriteHeader(http.StatusNoContent)
	if FeatureCounter == nil {
		return
	}
	var entries []beaconEntry
	outcome := "bad_body"
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, metricsMaxBody))
	if err == nil {
		entries, outcome = decodeBeacon(body)
	}
	v := beaconValidators(s)
	d := metricDims(r)
	added := make(map[beaconKey]int64, len(entries))
	for _, e := range entries {
		countEntry(r, d, v, added, e)
	}
	observe(r, "metrics.beacon", outcome)
}

// MetricsSettings serves the settings registry the snapshot reads; the page asks with ?hash=<build>.
func MetricsSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(observability.SettingsJSON())
}

// beaconValidators checks a beacon against the stores loaded right now.
func beaconValidators(s *site) observability.Validators {
	return metricValidators(s.prices())
}

// beaconKey is one stored key; a post adds at most metricsMaxCount to each.
// The per-post identity is scope, name and value; an entry kind differing by another field must extend it.
type beaconKey struct{ scope, name, value string }

// countEntry stores one entry or counts why it was refused; added is this post's sums by key.
func countEntry(r *http.Request, d observability.Dims, v observability.Validators, added map[beaconKey]int64, e beaconEntry) {
	scope, value, n, reason := checkEntry(e, v)
	k := beaconKey{scope: scope, name: e.N, value: value}
	if reason == "" && added[k] >= metricsMaxCount {
		reason = "count"
	}
	if reason != "" {
		rejectChecked()
		observe(r, "metrics.client", reason)
		return
	}
	n = min(n, metricsMaxCount-added[k])
	added[k] += n
	addChecked(d, scope, e.N, value, n)
	observe(r, "metrics.client", "accepted")
}
