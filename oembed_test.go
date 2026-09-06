package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// A preview lists several printings, each under its own heading. Handing them
// all one price list quotes the first card's numbers under every other card's
// name - a Tempest common priced as a 30th Anniversary one.
func TestPreviewQuotesEachCardWithItsOwnPrices(t *testing.T) {
	ids, _ := mtgmatcher.SearchEquals("Counterspell")
	if len(ids) < 2 {
		t.Skip("no datastore loaded")
	}

	prices := map[string]float64{ids[0]: 1.11, ids[1]: 22.22}
	out := embedService.Generate(ids[:2], func(cardID string) []embed.Entry {
		return []embed.Entry{{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: prices[cardID]}}
	})

	for _, want := range []string{"$1.11", "$22.22"} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("preview never quoted %s:\n%s", want, out.HTML)
		}
	}
}
