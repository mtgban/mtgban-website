// telemetry.go
package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/mtgban/mtgban-website/observability"
)

// observabilityInstance is this deployment's instance label, resolved once at
// startup and stamped on every recorded event.
var observabilityInstance string

// resolveInstanceName returns the configured instance name, else the OS
// hostname, else "unknown". Never empty.
func resolveInstanceName(configured string) string {
	if configured != "" {
		return configured
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

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
		Path:     observability.NormalizePath(strings.Trim(r.URL.Path, "/"), r.FormValue("page")),
		Tier:     tier,
		Device:   device,
		Visitor:  observability.HashVisitor(GetParamFromSig(sig, "UserEmail")),
		IsBot:    observability.IsBot(r.UserAgent()),
		Instance: observabilityInstance,
	})
}
