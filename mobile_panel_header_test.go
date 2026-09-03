package main

import (
	"bytes"
	"strings"
	"testing"

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
// both sides of it. The layout decides whether the card is expanded, and so
// whether there is a tab bar naming the panels.
func sealedPageVars(layout string, cardIDs ...string) PageVars {
	vars := PageVars{
		MobileSearchLayout: layout,
		CondKeys:           []string{"INDEX", "NM"},
		Metadata:           map[string]GenericCard{},
		FoundSellers:       map[string]map[string][]SearchEntry{},
		FoundVendors:       map[string]map[string][]SearchEntry{},
	}
	for _, cardID := range cardIDs {
		vars.AllKeys = append(vars.AllKeys, cardID)
		vars.Metadata[cardID] = GenericCard{Name: "A Booster Box", Edition: "Foundations", Sealed: true}
		vars.FoundSellers[cardID] = map[string][]SearchEntry{
			"INDEX": {
				{ScraperName: "TCG (Low / Market)", Price: 402.10, URL: "https://example.test"},
				{ScraperName: "TCG Low EV", Price: 406.83, IsEV: true},
				{ScraperName: "CT Zero EV", Price: 538.53, IsEV: true},
			},
			"NM": {{ScraperName: "TCGplayer", Price: 908.99, URL: "https://example.test"}},
		}
		vars.FoundVendors[cardID] = map[string][]SearchEntry{
			"NM": {{ScraperName: "Card Kingdom", Price: 780.00, URL: "https://example.test"}},
		}
	}
	return vars
}

// Expanded, the tab bar is not drawn, so the panels carry the names the
// desktop column headers use - and the simulated values stop running into the
// offers, because the offers now say where they begin.
func TestMobileExpandedPanelsAreNamed(t *testing.T) {
	out := renderMobileSearch(t, sealedPageVars("", "sealed-1"))

	if strings.Contains(out, `class="m-tabs"`) {
		t.Fatal("the tab bar is drawn on an expanded card, so the headers are redundant")
	}
	for _, name := range []string{"Sellers", "Buyers"} {
		if got := strings.Count(out, `<div class="m-panel-header">`+name+`</div>`); got != 1 {
			t.Errorf("got %d %q headers, want exactly 1", got, name)
		}
	}

	// The header heads the offers rather than the panel: the index rows are
	// references, and on a sealed product the last of them are simulations, so
	// the word has to land between those and the rows that are real listings.
	reference := strings.Index(out, "TCG (Low / Market)")
	ev := strings.LastIndex(out, "CT Zero EV")
	header := strings.Index(out, `<div class="m-panel-header">Sellers</div>`)
	offer := strings.Index(out, "TCGplayer")
	if reference < 0 || ev < 0 || header < 0 || offer < 0 {
		t.Fatalf("missing markup: reference=%d ev=%d header=%d offer=%d",
			reference, ev, header, offer)
	}
	if !(reference < ev && ev < header && header < offer) {
		t.Errorf("the Sellers header should fall after the simulated rows and before "+
			"the offers: reference=%d ev=%d header=%d offer=%d",
			reference, ev, header, offer)
	}
}

// The header names the offers, so a card with nothing but reference rows does
// not get one - there is no section for it to open.
func TestMobileReferenceOnlyCardHasNoHeader(t *testing.T) {
	vars := sealedPageVars("", "sealed-1")
	delete(vars.FoundSellers["sealed-1"], "NM")
	delete(vars.FoundVendors, "sealed-1")

	out := renderMobileSearch(t, vars)
	if strings.Contains(out, "m-panel-header") {
		t.Error("a card with only reference rows got a header over nothing")
	}
}

// In the compact layout the tab bar names the panels, so a header would say
// it twice.
func TestMobileCompactLayoutKeepsTheTabs(t *testing.T) {
	out := renderMobileSearch(t, sealedPageVars("compact", "sealed-1"))

	if !strings.Contains(out, `class="m-tabs"`) {
		t.Fatal("the tab bar is missing on a collapsed card")
	}
	if strings.Contains(out, "m-panel-header") {
		t.Error("a collapsed card got a panel header as well as its tab")
	}
}
