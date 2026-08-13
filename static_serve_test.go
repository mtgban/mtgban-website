package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The static routes hand out files from three directories plus two fixed
// names. Each tree is served through an http.Dir rooted at itself, so what a
// request can reach is bounded by that root rather than by a check on the path
// that a later, broader route could widen past.
func TestStaticServing(t *testing.T) {
	mux := http.NewServeMux()
	for _, root := range staticRoots {
		mux.Handle("/"+root+"/", staticTree(root))
	}
	mux.HandleFunc("/robots.txt", staticFile("robots.txt"))
	mux.HandleFunc("/favicon.ico", staticFile("img/favicon/favicon.ico"))

	for _, tc := range []struct {
		name, path, wantBody string
	}{
		{"a file in a served tree", "/css/main.css", "{"},
		{"a file in a nested directory", "/img/setsymbol/default.svg", "<svg"},
		{"a fixed file", "/robots.txt", ""},
		// The browser asks for this one unprompted on any page that does not
		// link an icon of its own.
		{"the bare favicon browsers ask for", "/favicon.ico", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("GET %s body %.60q, want it to contain %q", tc.path, rec.Body.String(), tc.wantBody)
			}
			if rec.Header().Get("Cache-Control") == "" {
				t.Errorf("GET %s served without a Cache-Control header", tc.path)
			}
		})
	}

	// Nothing outside a served tree comes back with a body, whichever way the
	// path is spelled. A 3xx here is the mux normalizing the path before it
	// routes; what matters is that the destination is not served either, so no
	// file content ever leaves.
	for _, tc := range []struct{ name, path string }{
		{"climbing out with ..", "/css/../upload.go"},
		{"climbing out, encoded", "/css/%2e%2e/upload.go"},
		{"climbing out, deeper", "/css/../../../../etc/passwd"},
		{"an absolute path", "/css//etc/passwd"},
		{"a directory in a served tree", "/css/"},
		{"a nested directory", "/img/setsymbol/"},
		{"a file that isn't there", "/css/nope.css"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code == http.StatusOK {
				t.Fatalf("GET %s = 200, want it refused (body %.80q)", tc.path, rec.Body.String())
			}
			if body := rec.Body.String(); strings.Contains(body, "package main") || strings.Contains(body, "root:") {
				t.Errorf("GET %s leaked file content: %.80q", tc.path, body)
			}
			// A redirect must not land on something this mux serves.
			if loc := rec.Header().Get("Location"); loc != "" {
				follow := httptest.NewRecorder()
				mux.ServeHTTP(follow, httptest.NewRequest(http.MethodGet, loc, nil))
				if follow.Code == http.StatusOK {
					t.Errorf("GET %s redirected to %s, which is served", tc.path, loc)
				}
			}
		})
	}
}
