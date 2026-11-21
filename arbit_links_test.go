package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Global names a store beside each of its two prices, so each price is the
// link to buy there; Arbitrage keeps its Buy and Sell buttons.
func TestGlobalPricesAreTheBuyLinks(t *testing.T) {
	row := mtgban.ArbitEntry{
		CardID:         "card-a",
		Quantity:       1,
		InventoryEntry: mtgban.InventoryEntry{Price: 54.99, URL: "https://store.example/a", Quantity: 1},
		ReferenceEntry: mtgban.InventoryEntry{Price: 320.10, URL: "https://index.example/a"},
	}
	global := renderArbit(t, PageVars{
		ScraperShort: "CK",
		StoreNames:   map[string]string{"CK": "Card Kingdom"},
		ArbitVars:    ArbitVars{GlobalMode: true},
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "MKM Trend", Key: "MKMTrend", Arbit: []mtgban.ArbitEntry{row}}},
	})
	for _, want := range []string{
		`<a class="arb-price-link buy" href="https://store.example/a" target="_blank" rel="nofollow" title="Buy at Card Kingdom">$ 54.99</a>`,
		`<a class="arb-price-link buy ref" href="https://index.example/a" target="_blank" rel="nofollow" title="Buy at MKM Trend">`,
	} {
		if !strings.Contains(global, want) {
			t.Errorf("global: no %s", want)
		}
	}
	if strings.Contains(global, `class="arb-qlink`) || strings.Contains(global, ">Links</th>") {
		t.Error("global: the Buy buttons and their column are still there")
	}

	// A sealed source swaps the two names: the row's own price is the
	// section's store, and a sealed product's reference price stays unlinked.
	sealed := renderArbit(t, PageVars{
		ScraperShort: "CKSealed",
		StoreNames:   map[string]string{"CKSealed": "Card Kingdom"},
		Metadata:     cardMetadata{"card-a": {UUID: "card-a", Sealed: true}},
		ArbitVars:    ArbitVars{GlobalMode: true, SealedSource: true},
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "ABU Games", Key: "ABUSealed", Arbit: []mtgban.ArbitEntry{row}}},
	})
	if want := `<a class="arb-price-link buy" href="https://store.example/a" target="_blank" rel="nofollow" title="Buy at ABU Games">$ 54.99</a>`; !strings.Contains(sealed, want) {
		t.Errorf("global sealed: no %s", want)
	}
	if strings.Contains(sealed, "arb-price-link buy ref") {
		t.Error("global sealed: the reference price became a link")
	}

	row.BuylistEntry = mtgban.BuylistEntry{BuyPrice: 60, URL: "https://buylist.example/a"}
	row.ReferenceEntry = mtgban.InventoryEntry{}
	arbit := renderArbit(t, PageVars{
		ScraperShort: "CK",
		StoreNames:   map[string]string{"CK": "Card Kingdom"},
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "Store", Key: "SCG", Arbit: []mtgban.ArbitEntry{row}}},
	})
	for _, want := range []string{`class="arb-qlink buy" href="https://store.example/a"`, `class="arb-qlink sell" href="https://buylist.example/a"`, ">Links</th>"} {
		if !strings.Contains(arbit, want) {
			t.Errorf("arbitrage: no %s", want)
		}
	}
	if strings.Contains(arbit, "arb-price-link") {
		t.Error("arbitrage: a price became a link")
	}
}
