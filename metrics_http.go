package main

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// routeLabels maps each pattern registered in routes.go to its route label;
// nav pages, "/" and "/data/" are labelled in routeLabel.
var routeLabels = map[string]string{
	"/css/": "static", "/img/": "static", "/js/": "static", "/openapi/": "static",
	"/favicon.ico": "static", "/robots.txt": "static", "/sw.js": "static",

	"/go/":    "go",
	"/http:/": "redirect", "/https:/": "redirect", "/card/": "redirect", "/sealed/": "redirect",
	"/random": "redirect", "/randomsealed": "redirect", "/discord": "redirect", "/monroecards": "redirect",

	"/changelog": "changelog", "/user": "user", "/guide": "guide", "/privacy": "privacy",
	"/offline": "offline", "/upload/handoff": "upload/handoff", "/toggle-mobile": "toggle-mobile",

	"/search/oembed":               "search.oembed",
	"/search/decklist/tcgplayer/":  "search.decklist",
	"/search/decklist/cardmarket/": "search.decklist",
	"/search/export/":              "search.export",
	"/search/raw/":                 "search.raw",

	"/api/suggest":           "api.suggest",
	"/api/settings/modal":    "api.settings",
	"/api/userstate/":        "api.userstate",
	"/api/upload/share":      "api.upload_share",
	"/api/popular/vote":      "api.popular",
	"/api/metrics":           "api.metrics",
	"/api/alerts/":           "api.alerts",
	"/api/opensearch.xml":    "api.opensearch",
	"/api/offline/":          "api.offline",
	"/api-plans/stores.json": "api-plans.stores",

	"/api/palette/card/": "api.palette", "/api/palette/sealed/": "api.palette",
	"/api/palette/sets.json": "api.palette", "/api/palette/stores.json": "api.palette",
	"/api/palette/promos.json": "api.palette", "/api/palette/finishes.json": "api.palette",
	"/api/palette/rarities.json": "api.palette", "/api/palette/colors.json": "api.palette",

	"/alerts/mail-events": "webhook", "/webhook/patreon": "webhook",
	"/auth":    "auth",
	"/healthz": "healthz",
}

// The price API patterns take their label from the function the gateway shares.
func init() {
	for _, pattern := range []string{
		"/api/mtgban/search/", "/api/mtgban/", "/api/v2/search/", "/api/v2/history/",
		"/api/v2/newspaper/", "/api/v2/", "/api/load/", "/api/load/datastore",
	} {
		routeLabels[pattern] = observability.APIFamily(pattern)
	}
}

// routeLabel is the bounded label of a request matched to pattern ("" when
// unmatched) at path.
func routeLabel(pattern, path string) string {
	switch {
	case strings.HasPrefix(path, "/debug"):
		return "debug"
	case pattern == "/":
		if path == "/" {
			return "home"
		}
		return "other"
	case pattern == "/data/":
		switch {
		case strings.HasPrefix(path, "/data/chart/"):
			return "data.chart"
		case strings.HasPrefix(path, "/data/prices/"):
			return "data.prices"
		}
		return "data"
	}
	if label, ok := routeLabels[pattern]; ok {
		return label
	}
	return navRouteLabel(pattern)
}

// navRouteLabel labels a nav page or sub-page by its link, or "other".
func navRouteLabel(pattern string) string {
	link, _, _ := strings.Cut(pattern, "?")
	for _, nav := range ExtraNavs {
		if nav.SettingsTab != "" && link == nav.Link+"/settings-values" {
			return "settings.values"
		}
		if _, ok := nav.pageAt(link); ok {
			return strings.Trim(link, "/")
		}
	}
	return "other"
}

// routeLabelSet is every label routeLabel can return but "other", built on first use.
var routeLabelSet = sync.OnceValue(func() map[string]bool {
	set := map[string]bool{
		"home": true, "debug": true, "data": true, "data.chart": true, "data.prices": true,
		"settings.values": true,
	}
	for _, label := range routeLabels {
		set[label] = true
	}
	for _, nav := range ExtraNavs {
		set[navRouteLabel(nav.Link)] = true
		for _, sub := range nav.SubPages {
			set[navRouteLabel(sub.Link)] = true
		}
	}
	delete(set, "other")
	return set
})

// durationBucket buckets d for http.duration; each edge opens the bucket above it.
func durationBucket(d time.Duration) string {
	switch {
	case d < 50*time.Millisecond:
		return "<50ms"
	case d < 200*time.Millisecond:
		return "<200ms"
	case d < time.Second:
		return "<1s"
	case d < 5*time.Second:
		return "<5s"
	}
	return "5s+"
}

// statusWrapper counts every request's status class and duration under its
// route label, with the dimensions the handler left in the request's holder.
func statusWrapper(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FeatureCounter == nil {
			next.ServeHTTP(w, r)
			return
		}
		_, pattern := mux.Handler(r)
		scope := routeLabel(pattern, r.URL.Path)
		r = withDimsHolder(r)
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		returned := false
		// No recover: a panic is counted as a 5xx and goes on unchanged.
		defer func() {
			elapsed := time.Since(start)
			status := sw.status
			switch {
			case !returned:
				status = http.StatusInternalServerError
			case status == 0:
				status = http.StatusOK
			}
			observeScoped(r, scope, "http.status", strconv.Itoa(status/100)+"xx")
			observeScoped(r, scope, "http.duration", durationBucket(elapsed))
		}()
		next.ServeHTTP(sw, r)
		returned = true
	})
}

// statusWriter keeps the first final status a response was given.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.remember(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.remember(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

// ReadFrom keeps the underlying writer's own copy, sendfile on a file.
func (w *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	w.remember(http.StatusOK)
	return io.Copy(w.ResponseWriter, src)
}

// remember keeps code unless a status is kept already or code is informational.
func (w *statusWriter) remember(code int) {
	if w.status == 0 && code >= 200 {
		w.status = code
	}
}

// Unwrap lets http.ResponseController reach the writer's Flush and the like.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
