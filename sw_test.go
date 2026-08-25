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

// The other direction of the check above: an entry naming a file that is no
// longer there fails the install (a precache fetch that is not ok throws), and
// a failed install takes offline mode down with it - silently, since nothing
// server side ever reads this list.
func TestServiceWorkerPrecachesExistingFiles(t *testing.T) {
	sw, err := os.ReadFile("sw.js")
	if err != nil {
		t.Fatal(err)
	}
	urlRE := regexp.MustCompile(`'(/(?:js|css|img)/[^'?]+)`)
	matches := urlRE.FindAllStringSubmatch(string(sw), -1)
	if len(matches) == 0 {
		t.Fatal("no asset entries found; did the precache list change shape?")
	}
	for _, m := range matches {
		if _, err := os.Stat(strings.TrimPrefix(m[1], "/")); err != nil {
			t.Errorf("precached %s does not exist: %v", m[1], err)
		}
	}
}

// The precached shell outlives the session that installed it - it is what a
// failed navigation falls back to for whoever is at the browser later - and
// /offline renders the navbar, which names the signed-in account. So the
// precache fetch must not carry the installer's cookies.
func TestServiceWorkerPrecachesAnonymously(t *testing.T) {
	sw, err := os.ReadFile("sw.js")
	if err != nil {
		t.Fatal(err)
	}
	// From the shell loop only: the CDN helpers above it fetch the same shape,
	// cross-origin, where cookies never travel anyway.
	body := string(sw)
	loop := strings.Index(body, "SHELL_URLS.map(")
	if loop < 0 {
		t.Fatal("no SHELL_URLS loop found; did the install handler change shape?")
	}
	fetchRE := regexp.MustCompile(`fetch\(new Request\(url, \{([^}]*)\}\)\)`)
	m := fetchRE.FindStringSubmatch(body[loop:])
	if m == nil {
		t.Fatal("no precache fetch found; did the install handler change shape?")
	}
	if !strings.Contains(m[1], "credentials: 'omit'") {
		t.Errorf("precache fetch options are {%s}, want credentials: 'omit'", m[1])
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
