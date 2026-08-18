package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The state parameter is whatever the link that opened the login wrote, and the
// session cookie is set before it is read, so a redirect anywhere but this very
// site has to land on the homepage instead. The state also arrives percent
// decoded, which is where "%5C" turns back into the backslash a browser reads
// as a slash.
func TestRedirectAfterAuth(t *testing.T) {
	saved := ServerURL
	t.Cleanup(func() { ServerURL = saved })
	ServerURL = "https://www.mtgban.com"

	const home = "https://www.mtgban.com"

	for _, tt := range []struct {
		name  string
		state string
		want  string
	}{
		{"same page", "https://www.mtgban.com/search?q=lotus", "https://www.mtgban.com/search?q=lotus"},
		{"same host root", home, home},
		{"bare domain", "https://mtgban.com/search?q=lotus", "https://mtgban.com/search?q=lotus"},
		{"sibling subdomain", "https://beta.mtgban.com/arbit", "https://beta.mtgban.com/arbit"},
		{"explicit default port", "https://www.mtgban.com:443/search?q=lotus", "https://www.mtgban.com:443/search?q=lotus"},
		{"uppercase sibling", "https://BETA.MTGBAN.COM/arbit", "https://BETA.MTGBAN.COM/arbit"},
		{"empty", "", home},
		{"logout", "https://www.mtgban.com/?errmsg=logout", home},
		{"other host", "https://evil.com/", home},
		{"host suffix", "https://www.mtgban.com.evil.com/", home},
		{"domain suffix", "https://mtgban.com.evil.com/", home},
		{"domain prefix", "https://notmtgban.com/", home},
		{"scheme downgrade", "http://www.mtgban.com/", home},
		{"userinfo", "https://www.mtgban.com@evil.com/", home},
		{"protocol relative", "//evil.com/", home},
		{"backslash", `/\evil.com`, home},
		{"double backslash", `\\evil.com`, home},
		{"scheme and backslashes", `https:\\evil.com`, home},
		{"javascript", "javascript:alert(document.cookie)", home},
		{"data", "data:text/html,<script>alert(1)</script>", home},
		{"control character", "/\t//evil.com", home},
		{"relative path", "/search", home},
	} {
		w := httptest.NewRecorder()
		// The client id rides along after a semicolon, the way the login links
		// in the templates spell it
		r := httptest.NewRequest(http.MethodGet, "/auth?code=code&state="+url.QueryEscape(tt.state+";web"), nil)
		redirectAfterAuth(w, r)

		got := w.Header().Get("Location")
		if got != tt.want {
			t.Errorf("%s: state %q redirected to %q, want %q", tt.name, tt.state, got, tt.want)
		}
	}
}

// A proxy is free to name the default port in X-Forwarded-Host, which latches
// it into ServerURL, but no browser writes it in window.location.href. The
// visitor still has to get back to the page they logged in from.
func TestRedirectAfterAuthWithDefaultPort(t *testing.T) {
	saved := ServerURL
	t.Cleanup(func() { ServerURL = saved })
	ServerURL = "https://www.mtgban.com:443"

	for _, tt := range []struct {
		name  string
		state string
		want  string
	}{
		{"portless same host", "https://www.mtgban.com/search?q=lotus", "https://www.mtgban.com/search?q=lotus"},
		{"portless sibling", "https://beta.mtgban.com/arbit", "https://beta.mtgban.com/arbit"},
		{"other host", "https://evil.com/", ServerURL},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth?code=code&state="+url.QueryEscape(tt.state+";web"), nil)
		redirectAfterAuth(w, r)

		got := w.Header().Get("Location")
		if got != tt.want {
			t.Errorf("%s: state %q redirected to %q, want %q", tt.name, tt.state, got, tt.want)
		}
	}
}

// A dev session lives on a host-only cookie, so nothing but that host is ours,
// and the port the dev server happens to run on is no part of the answer.
func TestRedirectAfterAuthLocalhost(t *testing.T) {
	saved := ServerURL
	t.Cleanup(func() { ServerURL = saved })
	ServerURL = "http://localhost:8080"

	for _, tt := range []struct {
		name  string
		state string
		want  string
	}{
		{"same host", "http://localhost:8080/search?q=lotus", "http://localhost:8080/search?q=lotus"},
		{"other host", "http://evil.com/", ServerURL},
		{"production host", "https://www.mtgban.com/", ServerURL},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth?code=code&state="+url.QueryEscape(tt.state+";web"), nil)
		redirectAfterAuth(w, r)

		got := w.Header().Get("Location")
		if got != tt.want {
			t.Errorf("%s: state %q redirected to %q, want %q", tt.name, tt.state, got, tt.want)
		}
	}
}

// Without a ServerURL there is no origin to be part of, and a relative target
// would otherwise match the empty scheme and host an unset one parses to. The
// empty fallback reaches the browser as the site root, which is where
// http.Redirect resolves it against the request.
func TestRedirectAfterAuthWithoutServerURL(t *testing.T) {
	saved := ServerURL
	t.Cleanup(func() { ServerURL = saved })
	ServerURL = ""

	for _, state := range []string{`/\evil.com`, "//evil.com/", "https://evil.com/"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth?code=code&state="+url.QueryEscape(state), nil)
		redirectAfterAuth(w, r)

		got := w.Header().Get("Location")
		if got != "/" {
			t.Errorf("state %q redirected to %q, want the site root", state, got)
		}
	}
}
