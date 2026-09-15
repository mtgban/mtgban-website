package main

import "testing"

// A row whose unit isn't a dollar offer - an average count of copies, or a
// store's want-count - has nothing an embed's price columns can show.
func TestSearchEntries2embedDropsNonOfferRows(t *testing.T) {
	out := searchEntries2embed([]SearchEntry{
		{ScraperName: "TCGplayer", Price: 1.50},
		{ScraperName: "Avg Copies", Price: 0.92, PriceUnit: PriceUnitExpectedCount},
	})
	if len(out) != 1 || out[0].ScraperName != "TCGplayer" {
		t.Errorf("got %+v, want only the priced row", out)
	}
}

// Nil in, nil out: an embed with nothing to say builds no entries at all.
func TestSearchEntries2embedNilOnNoResults(t *testing.T) {
	if got := searchEntries2embed(nil); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}
