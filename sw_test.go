package main

import (
	"io"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The offline shell renders base.html with the shared navbar, so every script
// and stylesheet they pull has to be precached or the shell breaks offline.
func TestServiceWorkerPrecachesShellAssets(t *testing.T) {
	sw, err := os.ReadFile("sw.js")
	if err != nil {
		t.Fatal(err)
	}
	assetRE := regexp.MustCompile(`(?:src|href)="(/(?:js|css)/[^"?]+)`)
	for _, tmpl := range []string{"templates/base.html", "templates/partials/navbar.html"} {
		body, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range assetRE.FindAllStringSubmatch(string(body), -1) {
			if !strings.Contains(string(sw), "'"+m[1]+"?hash=") {
				t.Errorf("%s: %s is missing from the service worker precache list", tmpl, m[1])
			}
		}
	}
}

func TestServeServiceWorker(t *testing.T) {
	r := httptest.NewRequest("GET", "/sw.js", nil)
	w := httptest.NewRecorder()
	ServeServiceWorker(w, r)
	res := w.Result()

	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, want text/javascript", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "self.__BUILD = '") {
		n := len(body)
		if n > 40 {
			n = 40
		}
		t.Errorf("body does not start with the build injection: %q", string(body[:n]))
	}
	if !strings.Contains(string(body), "mtgban-shell-") {
		t.Error("body does not contain the shell cache prefix (sw.js not appended)")
	}
}
