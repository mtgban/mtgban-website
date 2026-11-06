package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSearchLoadsTheRowReaderBeforeFavorites pins the script order both
// layouts rely on: favorites.js and backpack.js read rows through
// window.CardRow.
func TestSearchLoadsTheRowReaderBeforeFavorites(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		page := renderPage(t, "search.html", mobile, PageVars{UserNav: &NavElem{Short: "b"}})
		reader := strings.Index(page, `src="/js/card-row.js?`)
		for _, script := range []string{"favorites.js", "backpack.js"} {
			at := strings.Index(page, `src="/js/`+script+`?`)
			if reader < 0 || at < 0 || reader > at {
				t.Errorf("mobile=%v: card-row at %d, %s at %d", mobile, reader, script, at)
			}
		}
	}
}

// TestSearchCarriesTheBackpack pins what search hands the backpack in both
// layouts.
func TestSearchCarriesTheBackpack(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		page := renderPage(t, "search.html", mobile, PageVars{UserNav: &NavElem{Short: "b"}})
		for _, want := range []string{`id="nav-backpack"`, `id="nav-backpack-count"`, `/js/backpack.js?`, `/css/backpack.css?`} {
			if !strings.Contains(page, want) {
				t.Errorf("mobile=%v: page is missing %s", mobile, want)
			}
		}
		if !strings.Contains(page, `aria-controls="backpack-panel" aria-expanded="false">`) {
			t.Errorf("mobile=%v: the navbar button is not visible as served", mobile)
		}
	}
	for _, mobile := range []bool{false, true} {
		for _, can := range []bool{false, true} {
			pv := PageVars{UserNav: &NavElem{Short: "b"}, CanUpload: can}
			page := renderPage(t, "search.html", mobile, pv)
			want := `window.BAN_BACKPACK = {canUpload: ` + strconv.FormatBool(can) + `};`
			gate := strings.Index(page, want)
			if gate < 0 || gate > strings.Index(page, `src="/js/backpack.js?`) {
				t.Errorf("mobile=%v: %s is missing or after backpack.js", mobile, want)
			}
		}
	}
	for tmpl, wants := range map[string][]string{
		"templates/search.html":        {`class="pack-btn"`},
		"templates/mobile/search.html": {`m-pack-btn pack-btn`, `m-actions-pack`},
	} {
		src, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range append(wants, `addToBackpack(this)`, `takeFromBackpack(this)`) {
			if !strings.Contains(string(src), want) {
				t.Errorf("%s is missing %s", tmpl, want)
			}
		}
	}
}

// TestEveryPageWithANavbarLoadsTheBackpack sweeps each page's sources in both
// layouts: the button is served visible, its script and sheet load once, and
// so does each script it needs, since a sync script running twice would sync
// twice. NoBackpack leaves them out at render, for the shell test below.
func TestEveryPageWithANavbarLoadsTheBackpack(t *testing.T) {
	pages, err := filepath.Glob("templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range pages {
		for _, mobile := range []bool{false, true} {
			name := filepath.Base(path)
			if strings.HasPrefix(name, "base") {
				continue // the layouts themselves, not pages
			}
			baseName, files := renderTemplateFiles(name, mobile)
			if strings.HasSuffix(baseName, "base-landing.html") {
				continue // draws no navbar
			}
			var src strings.Builder
			for _, file := range files {
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				src.Write(body)
			}
			for _, want := range []string{
				`src="/js/list-storage.js?`, `src="/js/user-state.js?`, `src="/js/confirm-dialog.js?`,
				`src="/js/backpack.js?`, `href="/css/backpack.css?`, `id="nav-backpack"`,
			} {
				if got := strings.Count(src.String(), want); got != 1 {
					t.Errorf("%s (mobile=%v): %s appears %d times, want 1", name, mobile, want, got)
				}
			}
			if strings.Contains(src.String(), `aria-expanded="false" hidden`) {
				t.Errorf("%s (mobile=%v): the navbar button is hidden as served", name, mobile)
			}
		}
	}
}

// TestPagesSayWhetherTheBackpackMaySendToUpload reads the grant the navbar
// reads, on any page rather than search's alone.
func TestPagesSayWhetherTheBackpackMaySendToUpload(t *testing.T) {
	oldCheck := SigCheck
	SigCheck = true
	t.Cleanup(func() { SigCheck = oldCheck })

	for _, tc := range []struct {
		name string
		sig  string
		want bool
	}{
		{"signed out", "", false},
		{"without the grant", testSig(map[string]string{"Search": "true"}), false},
		{"with the grant", testSig(map[string]string{"Upload": "true"}), true},
	} {
		r := httptest.NewRequest(http.MethodGet, "/guide", nil)
		if got := genPageNav(testSite, r, "Guide", tc.sig).CanUpload; got != tc.want {
			t.Errorf("%s: CanUpload = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestOfflineShellHasNoBackpack pins the page the service worker precaches
// without cookies, in both layouts: a backpack edited on it would not sync.
func TestOfflineShellHasNoBackpack(t *testing.T) {
	oldDev := DevMode
	DevMode = true
	t.Cleanup(func() { DevMode = oldDev })

	for _, mobile := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/offline", nil)
		if mobile {
			r.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		}
		page := httptest.NewRecorder()
		testSite.OfflinePage(page, r)
		body := page.Body.String()
		if !strings.Contains(body, "offline-page") || strings.Contains(body, `class="light-theme mobile`) != mobile {
			t.Fatalf("mobile=%v: the offline shell did not render in that layout", mobile)
		}
		for _, gone := range []string{`id="nav-backpack"`, `/js/backpack.js?`, `/css/backpack.css?`, `/js/user-state.js?`, `/js/list-storage.js?`, `/js/confirm-dialog.js?`, `window.BAN_BACKPACK = `} {
			if strings.Contains(body, gone) {
				t.Errorf("mobile=%v: the offline shell carries %s", mobile, gone)
			}
		}
	}
}

// TestUploadHandsTheBackpackItsResults pins what backpack.js reads on Upload:
// the ids a hashes POST priced, and null on a page without results.
func TestUploadHandsTheBackpackItsResults(t *testing.T) {
	rows := []UploadEntry{{CardID: "a"}, {CardID: "b"}}
	for _, tc := range []struct {
		name string
		pv   PageVars
		want string
	}{
		{"the bare form", PageVars{}, `priced: null`},
		{"a POST that failed", PageVars{WarningMessage: "No card list arrived with that request"}, `priced: null`},
		{"a file's results", PageVars{UploadVars: UploadVars{UploadEntries: rows}}, `priced: null`},
		{"the backpack's results", PageVars{CardHashes: []string{"a", "b"}, UploadVars: UploadVars{UploadEntries: rows}}, `priced: ["a","b"]`},
	} {
		tc.pv.UserNav = &NavElem{Short: "b"}
		tc.pv.Metadata = map[string]GenericCard{"a": {}, "b": {}}
		page := renderPage(t, "upload.html", false, tc.pv)
		want := `window.BAN_BACKPACK = {canUpload: true, ` + tc.want + `};`
		gate := strings.Index(page, want)
		if gate < 0 || gate > strings.Index(page, `src="/js/backpack.js?`) {
			t.Errorf("%s: %s is missing or after backpack.js", tc.name, want)
		}
		if !strings.Contains(page, `/css/backpack.css?`) {
			t.Errorf("%s: the page does not load backpack.css", tc.name)
		}
	}
}
