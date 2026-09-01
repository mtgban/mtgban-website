package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// reversePageVars is one reverse-mode table whose second entry the page has
// been told not to trust, so the badge has one row to land on and one to
// leave alone.
func reversePageVars() PageVars {
	entry := func(id string, sell, buy float64) mtgban.ArbitEntry {
		return mtgban.ArbitEntry{
			CardID:         id,
			InventoryEntry: mtgban.InventoryEntry{Price: sell, Conditions: "NM", Quantity: 1},
			BuylistEntry:   mtgban.BuylistEntry{BuyPrice: buy},
			Difference:     buy - sell,
			Spread:         100 * (buy - sell) / sell,
		}
	}
	return PageVars{
		ScraperShort: "TCGDirectNet",
		ReverseMode:  true,
		BetaNav:      &NavElem{Short: "beta"},
		Arb: []Arbitrage{
			{Name: "Store One", Key: "ONE", Arbit: []mtgban.ArbitEntry{
				entry("card-a", 10, 14),
				entry("card-b", 20, 23934.02),
			}, SussyList: map[string]float64{"card-b": 483.56}},
		},
		Metadata: map[string]GenericCard{
			"card-a": {Name: "Card A", Edition: "Edition A", SetCode: "AAA"},
			"card-b": {Name: "Card B", Edition: "Edition B", SetCode: "BBB"},
		},
	}
}

// TestReverseSussyBadge pins the warning to the column reverse actually shows.
// The buy price is the one TCG Direct (net) derives from a Direct listing, and
// it is the only price on a reverse row that a bad listing can inflate, but
// the badge used to render only beside a reference price that no reverse page
// ever fills in.
func TestReverseSussyBadge(t *testing.T) {
	page := renderArbit(t, reversePageVars())

	row := page[strings.Index(page, `data-arb-id="card-b"`):]
	row = row[:strings.Index(row, "</tr>")]
	if !strings.Contains(row, "$ 23934.02") {
		t.Fatal("the buy price is missing from the row")
	}
	if !strings.Contains(row, "TCG Market is $483.56") {
		t.Error("the suspect buy price carries no warning")
	}

	clean := page[strings.Index(page, `data-arb-id="card-a"`):]
	clean = clean[:strings.Index(clean, "</tr>")]
	if strings.Contains(clean, "TCG Market is") {
		t.Error("a price the market backs up was flagged anyway")
	}
}
