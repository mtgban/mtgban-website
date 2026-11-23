package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// ckSignalPageVars is one card with Card Kingdom's NM and SP offers and
// another store's NM offer at CK's P90, with CK's signal set to state.
func ckSignalPageVars(state string) PageVars {
	const cardID = "ck-signal-card"
	return PageVars{
		SearchVars: SearchVars{
			CondKeys:     []mtgban.Condition{"NM", "SP"},
			AllKeys:      []string{cardID},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{cardID: {
				"NM": {
					{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 10, Ratio: 50, URL: "https://example.test"},
					{ScraperName: "Other Store", Shorthand: "OS", Price: 9, URL: "https://example.test"},
				},
				"SP": {{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 9.5, URL: "https://example.test"}},
			}},
		},
		Metadata: map[string]GenericCard{cardID: {
			Name: "Some Card", Edition: "Some Set", GoodBuylist: 9, HighestBuylist: 12, HotlistStore: "CK",
			CKSignal: state, CKSignalTip: "the odds", CKFacts: "CK stock 0 · out 9 days",
		}},
	}
}

// renderDesktopSearch renders the desktop results block with the server's
// templates, so the buylist rows run rather than only parse.
func renderDesktopSearch(t *testing.T, pageVars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("search.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing search.html: %v", err)
	}
	var b bytes.Buffer
	err = tmpl.ExecuteTemplate(&b, "search-results", pageVars)
	if err != nil {
		t.Fatalf("rendering search-results: %v", err)
	}
	return b.String()
}

// Only CK's NM offer follows CK's signal; another store at CK's P90 stays
// green, and CK's SP offer is never colored. The phone draws the same table.
func TestSearchBuylistFollowsCKSignal(t *testing.T) {
	for _, tc := range []struct {
		state              string
		best, wait, marker int
	}{
		{state: "sell", best: 2},
		{state: "wait", best: 1, wait: 1, marker: 1},
		{state: "", best: 1},
	} {
		for name, page := range map[string]string{
			"desktop": renderDesktopSearch(t, ckSignalPageVars(tc.state)),
			"mobile":  renderMobileSearch(t, ckSignalPageVars(tc.state)),
		} {
			for _, check := range []struct {
				class string
				want  int
			}{
				{" price-best", tc.best},
				{" price-wait", tc.wait},
				{`class="ck-wait"`, tc.marker},
				{`class="bl-pill bl-pill-high"`, 1},
			} {
				got := strings.Count(page, check.class)
				if got != check.want {
					t.Errorf("%s, signal %q: %q appears %d times, want %d", name, tc.state, check.class, got, check.want)
				}
			}
			if !strings.Contains(page, "CK stock 0 · out 9 days") {
				t.Errorf("%s, signal %q: tooltip lacks CK's facts", name, tc.state)
			}
		}
	}
}
