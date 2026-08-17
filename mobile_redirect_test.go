package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// A redirect parameter must never leave the site. The backslash cases are the
// ones a leading-slash test lets through: a browser reads "/\evil.com" the way
// it reads "//evil.com".
//
// The control characters are the other spelling of the same trick, and they
// rest on url.Parse refusing them rather than on anything written here, so they
// are pinned: a browser drops a tab, newline or carriage return before parsing,
// which turns "/\t/evil.com" into "//evil.com" on its way off site.
func TestIsLocalRedirect(t *testing.T) {
	for _, tt := range []struct {
		target string
		want   bool
	}{
		{"/", true},
		{"/search", true},
		{"/search?q=a/b", true},
		{"", false},
		{"//evil.com", false},
		{`/\evil.com`, false},
		{`/\\evil.com`, false},
		{"https://evil.com", false},
		{"javascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{`\\evil.com`, false},
		{"evil.com", false},
		{"/\t/evil.com", false},
		{"/\n//evil.com", false},
		{"/\r//evil.com", false},
	} {
		if got := isLocalRedirect(tt.target); got != tt.want {
			t.Errorf("isLocalRedirect(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

// The predicate never sees the query as it was written: the handler decodes it
// first, so "%5C" is already a backslash and "%09" already a tab by then. Read
// the Location header the browser would act on, rather than trusting that the
// two steps compose.
func TestToggleMobileViewRedirect(t *testing.T) {
	for _, tt := range []struct {
		redirect string
		want     string
	}{
		{"/search?q=a", "/search?q=a"},
		{"", "/"},
		{`/\evil.com`, "/"},
		{"//evil.com", "/"},
		{"https://evil.com", "/"},
		{"javascript:alert(1)", "/"},
		{"/\t/evil.com", "/"},
		{"/\n//evil.com", "/"},
		{"/\r//evil.com", "/"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/toggle-mobile?redirect="+url.QueryEscape(tt.redirect), nil)
		toggleMobileView(w, r)

		got := w.Header().Get("Location")
		if got != tt.want {
			t.Errorf("redirect %q sent the visitor to %q, want %q", tt.redirect, got, tt.want)
		}
	}
}
