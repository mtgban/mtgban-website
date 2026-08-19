package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The bot narrows results to US stores so it does not offer a reader a shop
// they cannot buy from. An index scraper is a price reference rather than a
// shop, so the same reason does not apply to it — and Cardmarket's, which are
// the ones flagged EU, are the prices that went missing when it did.
func TestDiscordRegionFilterKeepsIndexScrapers(t *testing.T) {
	empty := mtgban.InventoryRecord{}
	seller := func(name, shorthand, flag string, index bool) mtgban.Seller {
		return mtgban.NewSellerFromInventory(empty, mtgban.ScraperInfo{
			Name:         name,
			Shorthand:    shorthand,
			CountryFlag:  flag,
			MetadataOnly: index,
		})
	}

	for _, tc := range []struct {
		name     string
		scraper  mtgban.Seller
		wantSkip bool
	}{
		{"a US shop stays", seller("Card Kingdom", "CK", "", false), false},
		{"a US index stays", seller("TCG Low", "TCGLow", "", true), false},
		{"an EU shop is dropped", seller("Magic Madhouse", "MM", "EU", false), true},
		{"an EU index stays", seller("Cardmarket Low", "MKMLow", "EU", true), false},
		{"a JP index stays", seller("Hareruya", "HAR", "JP", true), false},
	} {
		// Mirrors the filter messageCreate appends.
		got := shouldSkipStoreNG(tc.scraper, []FilterStoreElem{{
			Name:         "region",
			Values:       []string{"us"},
			IncludeIndex: true,
		}})
		if got != tc.wantSkip {
			t.Errorf("%s: skip=%v, want %v", tc.name, got, tc.wantSkip)
		}
	}
}
