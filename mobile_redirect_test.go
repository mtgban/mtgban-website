package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The toggle takes where to go back to from the query string, so it is the one
// place a stranger's link can choose a destination. Anything that leaves this
// site has to come back as "/" instead.
func TestToggleMobileOnlyGoesBackIntoThisSite(t *testing.T) {
	for _, tt := range []struct {
		name     string
		redirect string
		want     string
	}{
		{"a page here", "/search?q=bolt", "/search?q=bolt"},
		{"the root", "/", "/"},
		{"nothing asked for", "", "/"},
		{"protocol relative", "//evil.test/x", "/"},
		{"backslash authority", "/\\evil.test/x", "/"},
		{"backslash pair", "/\\/evil.test", "/"},
		{"absolute", "https://evil.test/x", "/"},
		{"scheme", "javascript:alert(1)", "/"},
		{"bare host", "evil.test", "/"},
		{"tab smuggled in", "/\t/evil.test", "/"},
		{"newline smuggled in", "/\n/evil.test", "/"},
		{"carriage return", "/\r/evil.test", "/"},
		{"backslash pair doubled", "/\\\\evil.test", "/"},
		{"scheme in caps", "JavaScript:alert(1)", "/"},
		{"a fragment only", "#top", "/"},
		{"path with a query and fragment", "/search?q=a+b#x", "/search?q=a+b#x"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/toggle-mobile", nil)
			q := req.URL.Query()
			q.Set("redirect", tt.redirect)
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			toggleMobileView(rec, req)

			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("redirect=%q sent the reader to %q, want %q", tt.redirect, got, tt.want)
			}
		})
	}
}

// The same escapes again, written the way a link would carry them: FormValue
// decodes before any of this runs, so a percent-encoded tab or backslash has
// to be refused by the check rather than by the encoding hiding it.
func TestToggleMobileDecodesBeforeItDecides(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query string
		want  string
	}{
		{"encoded tab", "redirect=%2F%09%2Fevil.test", "/"},
		{"encoded backslash", "redirect=%2F%5Cevil.test", "/"},
		{"encoded newline", "redirect=%2F%0A%2Fevil.test", "/"},
		{"encoded double slash", "redirect=%2F%2Fevil.test", "/"},
		{"an ordinary page", "redirect=%2Fsearch%3Fq%3Dbolt", "/search?q=bolt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/toggle-mobile?"+tt.query, nil)
			rec := httptest.NewRecorder()
			toggleMobileView(rec, req)
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("%s sent the reader to %q, want %q", tt.query, got, tt.want)
			}
		})
	}
}
