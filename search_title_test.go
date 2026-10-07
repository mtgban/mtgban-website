package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The search page names itself for what it shows. Where two names apply the
// order decides: a chart of sealed products is a chart, the chart picker is
// the page it opens on, and a page that stops at the length check or loses
// its roster to a locked reader keeps its plain name.
func TestSearchPageTitles(t *testing.T) {
	skipWithoutDatastore(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	uuids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(uuids) == 0 {
		t.Skip("no Counterspell")
	}
	chart := "chart=" + uuids[0]
	long := "q=" + strings.Repeat("x", MaxSearchQueryLen+1)

	for _, c := range []struct {
		page   string
		locked bool
		want   string
	}{
		{"/search", false, "BAN Search"},
		{"/search?q=Counterspell", false, "BAN Search"},
		{"/sealed", false, "BAN Sealed Search"},
		{"/sealed?q=Counterspell", false, "BAN Sealed Search"},
		{"/sets", false, "BAN Editions"},
		{"/sets?sort=name", false, "BAN Editions"},
		{"/sets?q=Counterspell", false, "BAN Search"},
		{"/search?" + chart, false, "BAN Chart"},
		{"/sealed?" + chart, false, "BAN Chart"},
		{"/sets?" + chart, false, "BAN Chart"},
		{"/search?" + chart + "&q=Counterspell", false, "BAN Search"},
		{"/sealed?" + chart + "&q=Counterspell", false, "BAN Sealed Search"},
		{"/search?" + chart + "&modal=1", false, "BAN Search"},
		{"/sealed?" + chart + "&modal=1", false, "BAN Sealed Search"},
		{"/sets?" + chart + "&modal=1", false, "BAN Editions"},
		{"/sets?chart=zzz", false, "BAN Search"},
		{"/search?" + chart, true, "BAN Search"},
		{"/sealed?" + chart, true, "BAN Sealed Search"},
		{"/sets?" + chart, true, "BAN Search"},
		{"/search?" + long, false, "BAN Search"},
		{"/sealed?" + long, false, "BAN Search"},
		{"/sets?" + long, false, "BAN Search"},
	} {
		withSigMode(t, true, c.locked)
		w := httptest.NewRecorder()
		testSite.Search(w, httptest.NewRequest(http.MethodGet, c.page, nil))

		_, title, _ := strings.Cut(w.Body.String(), "<title>")
		title, _, _ = strings.Cut(title, "</title>")
		title, _, _ = strings.Cut(title, ": ")
		if title != c.want {
			t.Errorf("%.60s (locked %v): title %q, want %q", c.page, c.locked, title, c.want)
		}
	}
}
