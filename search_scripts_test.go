package main

import (
	"os"
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

// TestSearchCarriesTheBackpack pins the buttons both layouts render and the
// navbar's hidden badge the script unhides.
func TestSearchCarriesTheBackpack(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		page := renderPage(t, "search.html", mobile, PageVars{UserNav: &NavElem{Short: "b"}})
		for _, want := range []string{`id="nav-backpack"`, `id="nav-backpack-count"`, `/js/backpack.js?`, `/css/backpack.css?`} {
			if !strings.Contains(page, want) {
				t.Errorf("mobile=%v: page is missing %s", mobile, want)
			}
		}
		if !strings.Contains(page, `aria-controls="backpack-panel" aria-expanded="false" hidden`) {
			t.Errorf("mobile=%v: the navbar button is not hidden by default", mobile)
		}
	}
	for _, mobile := range []bool{false, true} {
		for _, can := range []bool{false, true} {
			pv := PageVars{UserNav: &NavElem{Short: "b"}, SearchVars: SearchVars{CanUpload: can}}
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
