// telemetry_test.go
package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
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
		{"/api/v2/all.json", false},
		{"/search/decklist/tcgplayer/12345", false},
		{"/search/export/retail/foo.csv", false},
		{"/search/raw/12345", false},
		{"/data/prices/", false},
		{"/data/chart/ban:1", false},
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
		req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
		if got := pageHitEvent(req).Tier; got != want {
			t.Errorf("tier %q, want %q", got, want)
		}
	}
}

func TestIsPageView(t *testing.T) {
	cases := []struct {
		dest, purpose string
		want          bool
	}{
		{"", "", true}, // header absent: old browser, bot
		{"document", "", true},
		{"iframe", "", true},
		{"empty", "", false}, // fetch() and XHR
		{"image", "", false},
		{"script", "", false},
		{"document", "prefetch", false},
		{"document", "prefetch;prerender", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/search?q=bolt", nil)
		if c.dest != "" {
			req.Header.Set("Sec-Fetch-Dest", c.dest)
		}
		if c.purpose != "" {
			req.Header.Set("Sec-Purpose", c.purpose)
		}
		if got := isPageView(req); got != c.want {
			t.Errorf("dest %q purpose %q: got %v, want %v", c.dest, c.purpose, got, c.want)
		}
	}
}

func TestShouldRecordHit(t *testing.T) {
	page := httptest.NewRequest(http.MethodGet, "/search?q=bolt", nil)
	page.Header.Set("Sec-Fetch-Dest", "document")
	fetch := httptest.NewRequest(http.MethodGet, "/search?q=bolt", nil)
	fetch.Header.Set("Sec-Fetch-Dest", "empty")
	export := httptest.NewRequest(http.MethodGet, "/search/export/retail/x.csv", nil)
	if !shouldRecordHit(page) || shouldRecordHit(fetch) || shouldRecordHit(export) {
		t.Fatal("page counts; a fetch to the same URL and an excluded prefix do not")
	}
}

func TestPageLabelIsBounded(t *testing.T) {
	cases := []struct{ path, page, want string }{
		{"/", "", "home"},
		{"/newspaper", "", "newspaper/index"},
		{"/newspaper", "syp", "newspaper/syp"},
		{"/newspaper", "nonsense", "newspaper/other"},
		{"/search", "", "search"},
		{"/sealed", "", "sealed"},
		{"/upload/handoff", "", "upload/handoff"},
		{"/changelog", "", "changelog"},
		{"/user", "", "user"},
		{"/guide", "", "guide"},
		{"/privacy", "", "privacy"},
		{"/offline", "", "offline"},
		{"/debug/pprof/heap", "", "other"},
		{"/debug/" + strings.Repeat("x", 300), "", "other"},
		{"/wp-login.php", "", "other"},
		{"/guide/", "", "other"},
		{"/Guide", "", "other"},
		{"/newspaper/", "", "other"},
		{"/changelog", "2", "changelog"},
		{"/search", "junk", "search"},
	}
	for _, c := range cases {
		if got := pageLabel(c.path, c.page); got != c.want {
			t.Errorf("pageLabel(%q, %q) = %q, want %q", c.path, c.page, got, c.want)
		}
	}
}

// labelRequest is the path and ?page= a label was made from.
func labelRequest(label string) (path, page string) {
	if label == "home" {
		return "/", ""
	}
	base, sub, cut := strings.Cut(label, "/")
	if !cut || observability.Subviews(base) == nil {
		return "/" + label, "" // search/shared, alerts/confirm: a path of two segments
	}
	if sub == "index" {
		return "/" + base, ""
	}
	return "/" + base, sub // "other" is itself an unknown ?page= value
}

func TestPageLabelsRoundTrip(t *testing.T) {
	labels := pageLabels()
	if !slices.IsSorted(labels) || len(slices.Compact(slices.Clone(labels))) != len(labels) {
		t.Errorf("pageLabels is sorted with no duplicates: %v", labels)
	}
	if slices.Contains(labels, "other") {
		t.Error(`"other" is not a page label`)
	}
	for _, label := range labels {
		path, page := labelRequest(label)
		if got := pageLabel(path, page); got != label {
			t.Errorf("pageLabel(%q, %q) = %q, want %q", path, page, got, label)
		}
	}
	for _, want := range []string{
		"home", "guide", "upload/handoff", "search", "sealed", "search/shared",
		"newspaper/index", "newspaper/syp", "newspaper/other",
		"sleepers/index", "sleepers/hotlist", "sleepers/other",
	} {
		if !slices.Contains(labels, want) {
			t.Errorf("pageLabels lacks %q", want)
		}
	}
	for _, c := range []struct{ path, page string }{{"/newspaper", "syp"}, {"/sleepers", ""}, {"/screener", ""}} {
		if got := pageLabel(c.path, c.page); !slices.Contains(labels, got) {
			t.Errorf("pageLabel(%q, %q) = %q, which pageLabels does not list", c.path, c.page, got)
		}
	}
}

// countHits swaps recordHit for a counter of the paths it is called with.
func countHits(t *testing.T) *[]string {
	t.Helper()
	var hits []string
	old := recordHit
	recordHit = func(r *http.Request) { hits = append(hits, r.URL.Path) }
	t.Cleanup(func() { recordHit = old })
	return &hits
}

func TestPublicPageRecordsOnce(t *testing.T) {
	hits := countHits(t)

	h := publicPage(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/guide", nil)
	req.Header.Set("Sec-Fetch-Dest", "document")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(*hits) != 1 || (*hits)[0] != "/guide" {
		t.Fatalf("hits = %v, want one for /guide", *hits)
	}
}

// publicPage records only a GET of a known page that is not the chart modal
// and was not answered with a redirect.
func TestPublicPageRecordsOnlyViews(t *testing.T) {
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	cases := []struct {
		name, method, target, dest string
		handler                    http.Handler
		want                       int
	}{
		{"plain get", http.MethodGet, "/guide", "document", plain, 1},
		{"empty handler", http.MethodGet, "/guide", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), 1},
		{"post", http.MethodPost, "/guide", "document", plain, 0},
		{"head", http.MethodHead, "/guide", "document", plain, 0},
		{"redirect", http.MethodGet, "/", "document", redirect, 0},
		{"chart modal", http.MethodGet, "/?chart=x&modal=1", "iframe", plain, 0},
		{"chart without modal", http.MethodGet, "/?chart=x", "iframe", plain, 1},
		{"unknown path", http.MethodGet, "/wp-login.php", "document", plain, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := countHits(t)
			req := httptest.NewRequest(c.method, c.target, nil)
			if c.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", c.dest)
			}
			publicPage(c.handler).ServeHTTP(httptest.NewRecorder(), req)
			if len(*hits) != c.want {
				t.Errorf("hits = %v, want %d", *hits, c.want)
			}
		})
	}
}

// The wrapper publicPage adds keeps the response body whole.
func TestPublicPageKeepsTheBody(t *testing.T) {
	countHits(t)
	h := publicPage(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, strings.NewReader("body"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/guide", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "body" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// signing records an open page itself; noSigning must not record again.
func TestNoSigningDoesNotRecord(t *testing.T) {
	calls := 0
	old := recordHit
	recordHit = func(*http.Request) { calls++ }
	t.Cleanup(func() { recordHit = old })

	h := noSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if calls != 0 {
		t.Fatalf("noSigning recorded %d hits, want 0", calls)
	}
}
