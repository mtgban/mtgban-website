// telemetry.go
package main

import (
	"net/http"
	"strings"

	"github.com/mtgban/mtgban-website/observability"
)

// recordablePath reports whether a request path should produce a telemetry
// event. API routes are excluded: some are wired through enforceSigning but
// carry high-cardinality ids that must not enter the usage tables.
func recordablePath(urlPath string) bool {
	return !strings.HasPrefix(urlPath, "/api/")
}

// recordPageHit emits one telemetry event for a served gated request. It is a
// no-op when telemetry is disabled and never blocks the request.
func recordPageHit(r *http.Request) {
	if ObservabilityRecorder == nil {
		return
	}
	if !recordablePath(r.URL.Path) {
		return
	}
	sig := getSignatureFromCookies(r)
	if qs := r.FormValue("sig"); qs != "" {
		sig = qs
	}
	device := "desktop"
	if isMobileRequest(r) {
		device = "mobile"
	}
	tier := GetParamFromSig(sig, "UserTier")
	if tier == "" {
		tier = "Any"
	}
	ObservabilityRecorder.Record(observability.Event{
		Path:    observability.NormalizePath(strings.Trim(r.URL.Path, "/"), r.FormValue("page")),
		Tier:    tier,
		Device:  device,
		Visitor: observability.HashVisitor(GetParamFromSig(sig, "UserEmail")),
		IsBot:   observability.IsBot(r.UserAgent()),
	})
}
