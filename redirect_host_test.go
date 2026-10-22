package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request line in absolute form names a host of the client's choosing; the
// redirect stays on this site whatever it names.
func TestRedirectsIgnoreRequestHost(t *testing.T) {
	for _, c := range []struct {
		target string
		handle func(http.ResponseWriter, *http.Request)
		want   string
	}{
		{"http://evil.example/card/", testSite.CardRedirect, "/search"},
	} {
		rec := httptest.NewRecorder()
		c.handle(rec, httptest.NewRequest(http.MethodGet, c.target, nil))
		if got := rec.Header().Get("Location"); got != c.want {
			t.Errorf("%s: Location %q, want %q", c.target, got, c.want)
		}
	}
}
