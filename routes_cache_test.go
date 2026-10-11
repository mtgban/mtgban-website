package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A static file requested with the running build's hash never changes at
// that URL, so it may be cached for 30 days. Another hash revalidates every
// time: during a rolling deploy an old instance can answer for the new hash.
// No hash keeps the one-day value; dev mode, or a build that names no
// commit, keeps nothing, so a local edit shows on the next load.
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
		{"/css/main.css?hash=deadbeef", "no-cache"},
		{"/js/utils.js?hash=", "public, max-age=86400"},
		{"/img/logo/ban-round.png", "public, max-age=86400"},
	} {
		req := httptest.NewRequest(http.MethodGet, c.url, nil)
		if got := staticCacheControl(req); got != c.want {
			t.Errorf("%s: Cache-Control %q, want %q", c.url, got, c.want)
		}
	}

	for _, c := range []struct {
		name   string
		dev    bool
		commit string
	}{
		{"dev mode", true, "9e551ed0"},
		{"no commit", false, ""},
	} {
		DevMode, BuildCommit = c.dev, c.commit
		for _, u := range []string{"/css/main.css?hash=9e551ed0", "/css/main.css?hash=", "/img/logo/ban-round.png"} {
			req := httptest.NewRequest(http.MethodGet, u, nil)
			if got := staticCacheControl(req); got != "no-store" {
				t.Errorf("%s, %s: Cache-Control %q, want no-store", c.name, u, got)
			}
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

// The pages, the settings modal and the worker build their asset URLs from
// one hash, and the worker goes to the network first wherever the server
// sends static files no-store.
func TestAssetHashReachesPagesAndWorker(t *testing.T) {
	savedDev, savedCommit := DevMode, BuildCommit
	t.Cleanup(func() { DevMode, BuildCommit = savedDev, savedCommit })

	// dev names whether the worker goes to the network first: in dev, and in a
	// build without a commit, whose files the server sends no-store as well.
	for _, c := range []struct {
		dev    bool
		commit string
	}{{false, "abc"}, {true, "abc"}, {false, ""}} {
		DevMode, BuildCommit = c.dev, c.commit
		dev := c.dev || c.commit == ""
		want := assetHash()
		req := httptest.NewRequest(http.MethodGet, "/search", nil)

		if got := genPageNav(testSite, req, "Offline", "").Hash; got != want {
			t.Errorf("dev %v: page hash %q, want %q", dev, got, want)
		}
		if got := settingsModalData(testSite, req).Hash; got != want {
			t.Errorf("dev %v: settings modal hash %q, want %q", dev, got, want)
		}

		rec := httptest.NewRecorder()
		ServeServiceWorker(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
		body := rec.Body.String()
		if !strings.HasPrefix(body, "self.__BUILD = '"+want+"';\n") {
			t.Errorf("dev %v: worker does not open with build %q", dev, want)
		}
		if strings.Contains(body, "self.__DEV = true;") != dev {
			t.Errorf("dev %v: worker sets __DEV %v", dev, !dev)
		}
	}

	// A dev restart moves every asset URL past what a browser kept, even two
	// restarts within one second.
	DevMode, BuildCommit = true, "abc"
	if got, want := assetHash(), "abc-"+strconv.FormatInt(StartTime.UnixNano(), 10); got != want {
		t.Errorf("dev asset hash %q, want the commit plus the start in nanoseconds, %q", got, want)
	}
}
