package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// renderArbit runs the arbit page the way the server does, so the summary is
// exercised rather than only parsed.
func renderArbit(t *testing.T, pageVars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("arbit.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing arbit.html: %v", err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, baseName, pageVars); err != nil {
		t.Fatalf("rendering arbit.html: %v", err)
	}
	return b.String()
}

// arbitPageVars is two stores' worth of results, the second one better, so the
// summary has something to gather and an order to get wrong.
func arbitPageVars() PageVars {
	entry := func(id string, sell, buy, diff, spread float64) mtgban.ArbitEntry {
		return mtgban.ArbitEntry{
			CardID:         id,
			InventoryEntry: mtgban.InventoryEntry{Price: sell, Conditions: "NM", Quantity: 1},
			BuylistEntry:   mtgban.BuylistEntry{BuyPrice: buy},
			Difference:     diff,
			Spread:         spread,
		}
	}
	return PageVars{
		ScraperShort: "SRC",
		// base.html dereferences it on every page.
		BetaNav: &NavElem{Short: "beta"},
		Arb: []Arbitrage{
			{Name: "Store One", Key: "ONE", Arbit: []mtgban.ArbitEntry{
				entry("card-a", 10, 14, 4, 40),
				entry("card-b", 20, 21, 1, 5),
			}},
			{Name: "Store Two", Key: "TWO", Arbit: []mtgban.ArbitEntry{
				entry("card-c", 5, 30, 25, 500),
			}},
		},
		Metadata: map[string]GenericCard{
			"card-a": {Name: "Card A", Edition: "Edition A", SetCode: "AAA"},
			"card-b": {Name: "Card B", Edition: "Edition B", SetCode: "BBB"},
			"card-c": {Name: "Card C", Edition: "Edition C", SetCode: "CCC"},
		},
	}
}

func TestArbitBestOfTable(t *testing.T) {
	page := renderArbit(t, arbitPageVars())

	if !strings.Contains(page, "Best of each store") {
		t.Fatal("the summary table is missing from the page")
	}

	summary := page[strings.Index(page, "arb-best-table"):]
	summary = summary[:strings.Index(summary, "</table>")]

	// One row per store, each holding that store's top entry - not its second.
	for _, want := range []string{"Store One", "Card A", "Store Two", "Card C"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary is missing %q", want)
		}
	}
	if strings.Contains(summary, "Card B") {
		t.Error("summary carries Store One's second entry, not just its best")
	}

	// The numbers come from the entry, not from somewhere else on the page.
	for _, want := range []string{"$ 30.00", "500.00 %", "$ 25.00"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary is missing %q from Store Two's best entry", want)
		}
	}

	// It sits above the sections it summarises.
	if strings.Index(page, "arb-best-table") > strings.Index(page, `id="Store One"`) {
		t.Error("the summary renders below the per-store sections")
	}
}

// Global mode compares one index against itself, so there is nothing to gather
// across stores; a single store has no "best of" worth a table of its own.
func TestArbitBestOfIsScoped(t *testing.T) {
	global := arbitPageVars()
	global.GlobalMode = true
	if strings.Contains(renderArbit(t, global), "Best of each store") {
		t.Error("the summary renders in global mode")
	}

	reverse := arbitPageVars()
	reverse.ReverseMode = true
	if !strings.Contains(renderArbit(t, reverse), "Best of each store") {
		t.Error("the summary is missing in reverse mode")
	}

	lone := arbitPageVars()
	lone.Arb = lone.Arb[:1]
	if strings.Contains(renderArbit(t, lone), "Best of each store") {
		t.Error("the summary renders for a single store")
	}
}

// A store whose table carries no arbit columns has no best to name.
func TestArbitBestOfSkipsStoresWithoutArbit(t *testing.T) {
	page := arbitPageVars()
	page.Arb[0].HasNoArbit = true
	rendered := renderArbit(t, page)

	summary := rendered[strings.Index(rendered, "arb-best-table"):]
	summary = summary[:strings.Index(summary, "</table>")]

	if strings.Contains(summary, "Store One") {
		t.Error("summary names a store with no arbit columns")
	}
	if !strings.Contains(summary, "Store Two") {
		t.Error("summary dropped the store that does have them")
	}
}
