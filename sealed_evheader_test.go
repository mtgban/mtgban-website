package main

import (
	"strings"
	"testing"
)

// sealedPage is one sealed product carrying the given INDEX rows.
func sealedPage(entries []SearchEntry) PageVars {
	const id = "prod"
	return PageVars{
		BetaNav: &NavElem{Short: "b"},
		// Non-empty, or the page renders its landing instead of results.
		SearchQuery:  "a sealed thing",
		AllKeys:      []string{id},
		CondKeys:     []string{"INDEX"},
		Metadata:     map[string]GenericCard{id: {Name: "A Sealed Thing", Sealed: true, SetCode: "TST"}},
		FoundSellers: map[string]map[string][]SearchEntry{id: {"INDEX": entries}},
		FoundVendors: map[string]map[string][]SearchEntry{},
	}
}

// The EV/Median/StdDev columns are filled by the expected-value rows alone. A
// product with index rows but no EV - most of Yu-Gi-Oh's sealed - was getting
// the header anyway, over three columns of "n/a".
func TestSealedEVHeaderFollowsItsRows(t *testing.T) {
	const header = "price-index-header"

	withEV := renderPage(t, "search.html", false, sealedPage([]SearchEntry{
		{ScraperName: "EV 12345", Shorthand: "TCGLowEV", Price: 4.20, IsEV: true},
	}))
	if !strings.Contains(withEV, header) {
		t.Error("a product with EV rows lost its header")
	}

	withoutEV := renderPage(t, "search.html", false, sealedPage([]SearchEntry{
		{ScraperName: "TCGplayer", Shorthand: "TCGSealed", Price: 9.99},
	}))
	if strings.Contains(withoutEV, header) {
		t.Error("a product with no EV rows still names the EV columns")
	}
	// Only the header goes; the row it does have is still priced.
	if !strings.Contains(withoutEV, "TCGplayer") {
		t.Error("hiding the header also hid the prices")
	}

	if none := renderPage(t, "search.html", false, sealedPage(nil)); strings.Contains(none, header) {
		t.Error("a product with no index rows at all names the EV columns")
	}
}

// The flag the header follows is set by the collapse, not by the caller.
func TestCollapseSealedEVMarksItsRows(t *testing.T) {
	rows, seen := collapseSealedEV([]SearchEntry{
		// A base entry and its " Sim" sibling, paired on the product id in
		// the second word, which is the shape the collapse documents.
		{ScraperName: "EV 12345", Shorthand: "TCGLowEV", Price: 4.20},
		{ScraperName: "EV 12345 Sim", Shorthand: "TCGLowSim", Price: 4.00},
		{ScraperName: "TCGplayer", Shorthand: "TCGSealed", Price: 9.99},
	}, []string{"TCGLowEV", "TCGLowSim"})

	if !seen || len(rows) != 1 {
		t.Fatalf("collapsed to %d rows (seen=%v), want 1", len(rows), seen)
	}
	if !rows[0].IsEV {
		t.Error("the collapsed row is not marked as expected-value")
	}
	if rows[0].Price != 4.20 || rows[0].Secondary != 4.00 {
		t.Errorf("collapsed row = %v/%v, want the EV price and the sim median", rows[0].Price, rows[0].Secondary)
	}
}
