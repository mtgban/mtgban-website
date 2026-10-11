package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A static file requested with the running build's hash never changes at
// that URL, so it may be cached for 30 days; any other hash, no hash, or
// dev mode (where the hash never names a real deploy) keeps the one-day
// value.
func TestStaticCacheControlFollowsTheHash(t *testing.T) {
	savedDev, savedCommit := DevMode, BuildCommit
	DevMode = false
	BuildCommit = "9e551ed0"
	t.Cleanup(func() { DevMode, BuildCommit = savedDev, savedCommit })

	for _, c := range []struct {
		url  string
		want string
	}{
		{"/css/main.css?hash=9e551ed0", "public, max-age=2592000, immutable"},
		{"/css/main.css?hash=deadbeef", "public, max-age=86400"},
		{"/js/utils.js?hash=", "public, max-age=86400"},
		{"/img/logo/ban-round.png", "public, max-age=86400"},
	} {
		req := httptest.NewRequest(http.MethodGet, c.url, nil)
		if got := staticCacheControl(req); got != c.want {
			t.Errorf("%s: Cache-Control %q, want %q", c.url, got, c.want)
		}
	}
}

func TestServeFileSendsTheCacheHeader(t *testing.T) {
	savedDev, savedCommit := DevMode, BuildCommit
	DevMode = false
	BuildCommit = "abc"
	t.Cleanup(func() { DevMode, BuildCommit = savedDev, savedCommit })

	req := httptest.NewRequest(http.MethodGet, "/js/utils.js?hash=abc", nil)
	rec := httptest.NewRecorder()
	ServeFile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=2592000, immutable" {
		t.Errorf("Cache-Control %q", got)
	}
}
