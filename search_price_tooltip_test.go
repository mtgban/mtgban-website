package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A retail price shows one tooltip: the market warning where it has one, or
// else what it costs in store credit. js/tooltips.js draws a title where the
// warning's own box goes, so a price with both would stack two boxes.
func TestRetailPriceCarriesOneTooltip(t *testing.T) {
	// No TCGMarket price, so every Direct price of a dollar or more looks off.
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	var none []mtgban.Seller
	sellersPtr.Store(&none)

	const id = "card"
	out := renderPage(t, "search.html", false, PageVars{
		BetaNav:     &NavElem{Short: "b"},
		SearchQuery: "a card",
		SearchRan:   true,
		AllKeys:     []string{id},
		CondKeys:    []string{"NM"},
		Metadata:    map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
		FoundSellers: map[string]map[string][]SearchEntry{
			id: {"NM": {
				{ScraperName: "TCG Direct", Shorthand: "TCGDirect", Price: 5, Credit: 4},
				{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 3.85},
			}},
		},
		FoundVendors: map[string]map[string][]SearchEntry{id: {}},
	})

	if !strings.Contains(out, `data-tooltip="Price looks off - TCG Market is missing"`) {
		t.Fatal("the Direct price does not look off")
	}
	if strings.Contains(out, "paid with credit: $ 4.00") {
		t.Error("the price that looks off carries its credit title as well")
	}
	if !strings.Contains(out, `title="Equivalent price if paid with credit: $ 3.85"`) {
		t.Error("a price that looks fine lost its credit title")
	}
}
