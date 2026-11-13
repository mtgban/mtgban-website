// telemetry.go
package main

import (
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/mtgban-website/observability"
)

// observabilityInstance is this deployment's instance label, set from config at
// startup. Empty means instance_name is unset and telemetry is disabled.
var observabilityInstance string

// recordablePath reports whether a request path should produce a telemetry
// event. The API, the scripts' /data/ and the downloads under /search/ are
// excluded: some are signed like pages but carry high-cardinality ids that
// must not enter the usage tables.
func recordablePath(urlPath string) bool {
	for _, prefix := range []string{"/api/", "/data/", "/search/"} {
		if strings.HasPrefix(urlPath, prefix) {
			return false
		}
	}
	return true
}

// isPageView reports whether r loads a page: Sec-Fetch-Dest absent, document or iframe.
func isPageView(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Sec-Purpose"), "prefetch") {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "", "document", "iframe":
		return true
	}
	return false
}

// shouldRecordHit reports whether r is a recordable path and a real page view.
func shouldRecordHit(r *http.Request) bool {
	return recordablePath(r.URL.Path) && isPageView(r)
}

// recordPageHit emits one telemetry event and one page.view count for a served
// gated request. Each is a no-op when disabled, and neither blocks the request.
func recordPageHit(r *http.Request) {
	if !shouldRecordHit(r) {
		return
	}
	if label := pageLabel(r.URL.Path, r.FormValue("page")); label != "other" {
		observe(r, "page.view", label)
	}
	if ObservabilityRecorder == nil {
		return
	}
	ObservabilityRecorder.Record(pageHitEvent(r))
}

// recordHit is swapped by tests, so a test that swaps it must not run in parallel.
var recordHit = recordPageHit

// publicPage serves an open page and records it if publicView says so.
func publicPage(next http.Handler) http.Handler {
	return noSigning(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w := &startedWriter{ResponseWriter: rw}
		next.ServeHTTP(w, r)
		if publicView(r, w.status) {
			recordHit(r)
		}
	}))
}

// publicView reports whether r was a GET of a known page, not a redirect or the chart modal.
func publicView(r *http.Request, status int) bool {
	if r.Method != http.MethodGet || status/100 == 3 || r.URL.Query().Get("modal") == "1" {
		return false
	}
	return pageLabel(r.URL.Path, r.FormValue("page")) != "other"
}

// pageHitEvent is the telemetry event for r, labelled off its checked
// signature.
func pageHitEvent(r *http.Request) observability.Event {
	sig := verifiedRequestSignature(r)
	device := "desktop"
	if isMobileRequest(r) {
		device = "mobile"
	}
	tier := GetParamFromSig(sig, "UserTier")
	if tier == "" {
		tier = "Any"
	}
	return observability.Event{
		Path:     pageLabel(r.URL.Path, r.FormValue("page")),
		Tier:     tier,
		Device:   device,
		Visitor:  observability.HashVisitor(GetParamFromSig(sig, "UserEmail")),
		IsBot:    observability.IsBot(r.UserAgent()),
		Instance: observabilityInstance,
	}
}

// publicPagePaths are the fixed public paths pageLabel knows beside "/" and the nav registry.
var publicPagePaths = map[string]bool{
	"/changelog": true, "/user": true, "/guide": true, "/privacy": true,
	"/offline": true, "/upload/handoff": true,
}

// pageLabel is path as a label from a bounded set, or "other" for an unknown path.
func pageLabel(path, page string) string {
	known := path == "/" || publicPagePaths[path]
	for _, nav := range ExtraNavs {
		if known {
			break
		}
		_, known = nav.pageAt(path)
	}
	if !known {
		return "other"
	}
	return observability.NormalizePath(strings.Trim(path, "/"), page)
}

// pageLabels is every label pageLabel can return but "other", sorted; some are never stored yet.
func pageLabels() []string {
	paths := []string{"/"}
	for p := range publicPagePaths {
		paths = append(paths, p)
	}
	for _, nav := range ExtraNavs {
		paths = append(paths, nav.Link)
		for _, sub := range nav.SubPages {
			link, _, _ := strings.Cut(sub.Link, "?")
			paths = append(paths, link)
		}
	}
	var labels []string
	for _, p := range paths {
		base := strings.Trim(p, "/")
		labels = append(labels, observability.NormalizePath(base, ""))
		if subs := observability.Subviews(base); subs != nil {
			for _, sub := range subs {
				labels = append(labels, base+"/"+sub)
			}
			labels = append(labels, base+"/other")
		}
	}
	slices.Sort(labels)
	return slices.Compact(labels)
}
