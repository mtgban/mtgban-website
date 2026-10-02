package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// A row whose unit isn't a dollar offer - an average count of copies, or a
// store's want-count - has nothing an embed's price columns can show.
func TestSearchEntries2embedDropsNonOfferRows(t *testing.T) {
	out := searchEntries2embed([]SearchEntry{
		{ScraperName: "TCGplayer", Price: 1.50},
		{ScraperName: "Avg Copies", Price: 0.92, PriceUnit: PriceUnitExpectedCount},
	}, nil)
	if len(out) != 1 || out[0].ScraperName != "TCGplayer" {
		t.Errorf("got %+v, want only the priced row", out)
	}
}

// Nil in, nil out: an embed with nothing to say builds no entries at all.
func TestSearchEntries2embedNilOnNoResults(t *testing.T) {
	if got := searchEntries2embed(nil, nil); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// A grade travels beside the store name, so shortening the name to fit its
// column cannot cut it off.
func TestEmbedSellerEntriesGrade(t *testing.T) {
	out := EmbedSellerEntries(map[string]map[mtgban.Condition][]SearchEntry{
		"abcd": {
			"NM": {{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 10}},
			"SP": {
				{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 8},
				{ScraperName: "TCGplayer Direct", Shorthand: "TCGDirect", Price: 9},
			},
		},
	}, "abcd", false)
	want := []embed.Entry{
		{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 10},
		{ScraperName: "TCGplayer Direct", Shorthand: "TCGDirect", Price: 9, Grade: "SP"},
	}
	if !slices.Equal(out, want) {
		t.Errorf("got %+v, want %+v", out, want)
	}
}
