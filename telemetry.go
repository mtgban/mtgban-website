// telemetry.go
package main

import (
	"net/http"
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

// recordPageHit emits one telemetry event for a served gated request. It is a
// no-op when telemetry is disabled and never blocks the request.
func recordPageHit(r *http.Request) {
	if ObservabilityRecorder == nil {
		return
	}
	if !recordablePath(r.URL.Path) {
		return
	}
	ObservabilityRecorder.Record(pageHitEvent(r))
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
		Path:     observability.NormalizePath(strings.Trim(r.URL.Path, "/"), r.FormValue("page")),
		Tier:     tier,
		Device:   device,
		Visitor:  observability.HashVisitor(GetParamFromSig(sig, "UserEmail")),
		IsBot:    observability.IsBot(r.UserAgent()),
		Instance: observabilityInstance,
	}
}
