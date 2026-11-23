package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// renderMobileSearch renders the mobile results block with the templates the
// server parses, so the panels are exercised rather than only parsed. The
// block rather than the whole page: the base dispatches to it, and everything
// around it is chrome this has nothing to say about.
func renderMobileSearch(t *testing.T, pageVars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("search.html", true)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing mobile search.html: %v", err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "m-search-results", pageVars); err != nil {
		t.Fatalf("rendering m-search-results: %v", err)
	}
	return b.String()
}

// sealedPageVars is one sealed product with the index rows the collapse
// produces - market references, then the simulated values - and offers on
// both sides of it.
func sealedPageVars(cardIDs ...string) PageVars {
	vars := PageVars{
		SearchVars: SearchVars{
			CondKeys:     []mtgban.Condition{"INDEX", "NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{},
		},
		Metadata: map[string]GenericCard{},
	}
	for _, cardID := range cardIDs {
		vars.AllKeys = append(vars.AllKeys, cardID)
		vars.Metadata[cardID] = GenericCard{Name: "A Booster Box", Edition: "Foundations", Sealed: true}
		vars.FoundSellers[cardID] = map[mtgban.Condition][]SearchEntry{
			"INDEX": {
				{ScraperName: "TCG (Low / Market)", Price: 402.10, URL: "https://example.test"},
				{ScraperName: "TCG Low EV", Price: 406.83, IsEV: true},
				{ScraperName: "CT Zero EV", Price: 538.53, IsEV: true},
			},
			"NM": {{ScraperName: "TCGplayer", Price: 908.99, URL: "https://example.test"}},
		}
		vars.FoundVendors[cardID] = map[mtgban.Condition][]SearchEntry{
			"NM": {{ScraperName: "Card Kingdom", Price: 780.00, URL: "https://example.test"}},
		}
	}
	return vars
}

// A phone's lists are the desktop table: each pane holds the shared column,
// under the pane's own heading, with the sealed sections the desktop names.
func TestMobileListsAreTheDesktopTable(t *testing.T) {
	out := renderMobileSearch(t, sealedPageVars("sealed-1"))

	for markup, want := range map[string]int{
		`<div class="result-col">`:                     1 * 2,
		`<div class="m-pane-head">`:                    2,
		`<div class="price-cond-header">Sell to</div>`: 1,
	} {
		if got := strings.Count(out, markup); got != want {
			t.Errorf("got %d %q, want %d", got, markup, want)
		}
	}

	// The offers' header falls after the simulated index rows and before
	// the first listing, as on desktop.
	ev := strings.LastIndex(out, "CT Zero EV")
	header := strings.Index(out, "Purchase from</div>")
	offer := strings.Index(out, "TCGplayer")
	if ev < 0 || header < 0 || offer < 0 || !(ev < header && header < offer) {
		t.Errorf("want the index rows, then Purchase from, then the offers: ev=%d header=%d offer=%d", ev, header, offer)
	}
}

// A card with orders on record gets a Sales list after its buyers, or
// before them where the reader's Buyers column opens on Sales, with the edge
// button leading to whichever comes first; a sealed product gets none.
func TestMobileSalesList(t *testing.T) {
	for _, c := range []struct {
		mode   string
		sealed bool
		order  []string
	}{
		{"buylist", false, []string{`id="sellers-c"`, `id="buyers-c"`, `id="sales-c"`}},
		{"sales", false, []string{`id="sellers-c"`, `id="sales-c"`, `id="buyers-c"`}},
		{"sales", true, []string{`id="sellers-c"`, `id="buyers-c"`}},
	} {
		vars := sealedPageVars("c")
		card := vars.Metadata["c"]
		card.Sealed = c.sealed
		vars.Metadata["c"] = card
		vars.BuyersMode = c.mode
		vars.HasSales = map[string]bool{"c": true}
		out := renderMobileSearch(t, vars)

		at := -1
		for _, want := range c.order {
			i := strings.Index(out, want)
			if i < at {
				t.Errorf("mode %s, sealed %v: %s out of order (want %v)", c.mode, c.sealed, want, c.order)
			}
			at = i
		}
		if !c.sealed && !strings.Contains(out, `<div class="sales-pane" data-card="c" data-pending>`) {
			t.Errorf("mode %s: the Sales list has no pane to fill", c.mode)
		}
		if c.sealed && strings.Contains(out, `id="sales-c"`) {
			t.Error("a sealed product has a Sales list")
		}
		first := `data-pane="buyers-c"`
		if c.mode == "sales" && !c.sealed {
			first = `data-pane="sales-c"`
		}
		if !strings.Contains(out, first) {
			t.Errorf("mode %s, sealed %v: no edge button with %s", c.mode, c.sealed, first)
		}
	}
}
