package main

import (
	"strings"
	"testing"
)

// The "chart the top results" button leads to a page only a logged-in user can
// see rendered: charts are gated server-side. It once keyed on PatreonLogin,
// which is set when the login button is needed - so it showed itself to exactly
// the visitors whose chart would come back empty, and hid from everyone else.
func TestChartButtonFollowsTheChart(t *testing.T) {
	pv := PageVars{
		BetaNav:      &NavElem{Short: "b"},
		AllKeys:      []string{"a", "b"},
		SearchQuery:  "query",
		PatreonLogin: true,
	}

	pv.DisableChart = true
	if strings.Contains(renderPage(t, "search.html", false, pv), "Chart the top") {
		t.Error("a page that cannot chart offered to chart the top results")
	}

	pv.DisableChart = false
	pv.PatreonLogin = false
	if !strings.Contains(renderPage(t, "search.html", false, pv), "Chart the top") {
		t.Error("a page that can chart hid the button from a logged-in user")
	}
}
