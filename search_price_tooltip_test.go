package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A retail price shows one tooltip: the market warning where it has one, or
// else what it costs in store credit.
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
		SearchVars: SearchVars{
			SearchRan: true,
			AllKeys:   []string{id},
			CondKeys:  []mtgban.Condition{"NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{
				id: {"NM": {
					{ScraperName: "TCG Direct", Shorthand: "TCGDirect", Price: 5, Credit: 4},
					{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 3.85},
				}},
			},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{id: {}},
		},
		Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
	})

	if !strings.Contains(out, `title="Price looks off: TCG Market has no price for it.
This price: $ 5.00
TCG Market: none" data-tip="**Price looks off**: TCG Market has no price for it.
|This price|$ 5.00
|TCG Market|none"`) {
		t.Fatal("the Direct price does not look off")
	}
	if strings.Contains(out, "paid with credit: $ 4.00") {
		t.Error("the price that looks off carries its credit title as well")
	}
	if !strings.Contains(out, `title="Equivalent price if paid with credit: $ 3.85"`) {
		t.Error("a price that looks fine lost its credit title")
	}
}

// TestDirectPriceWarning tables a flagged price beside TCG Market's, and
// says so where TCG Market has none.
func TestDirectPriceWarning(t *testing.T) {
	for _, tc := range []struct {
		price, market float64
		want          string
	}{
		{23934.02, 483.56, "**Price looks off**: over twice TCG Market.\n|This price|$ 23934.02\n|TCG Market|$ 483.56"},
		{5, 0, "**Price looks off**: TCG Market has no price for it.\n|This price|$ 5.00\n|TCG Market|none"},
	} {
		if got := directPriceWarning(tc.price, tc.market); got != tc.want {
			t.Errorf("%.2f against %.2f:\n%s\nwant:\n%s", tc.price, tc.market, got, tc.want)
		}
	}
}
