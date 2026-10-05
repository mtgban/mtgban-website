package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestMKMIDModeReadsTheShelves keys the price API's Cardmarket ids on the
// product the Cardmarket shelves price a card under, which covers every
// card they price, and keeps the datastore's id for the cards they do not.
func TestMKMIDModeReadsTheShelves(t *testing.T) {
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	trend := mtgban.InventoryRecord{}
	trend.Add("uuid-priced", &mtgban.InventoryEntry{OriginalID: "265854", Price: 1})
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(trend, mtgban.ScraperInfo{
		Shorthand: "MKMTrend", MetadataOnly: true,
	})}
	sellersPtr.Store(&sellers)

	card := func(uuid, mcmID string) *mtgmatcher.CardObject {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Identifiers: map[string]string{}}}
		if mcmID != "" {
			co.Identifiers["mcmId"] = mcmID
		}
		return co
	}

	for _, tc := range []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"priced, no datastore id", card("uuid-priced", ""), "265854"},
		{"priced, datastore disagrees", card("uuid-priced", "111111"), "265854"},
		{"its foil, not priced on its own", card("uuid-priced_f", ""), "265854"},
		{"not priced, datastore id", card("uuid-other", "700001"), "700001"},
		{"not priced, datastore id is another card's", card("uuid-other", "265854"), ""},
		{"neither", card("uuid-other", ""), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := getIDFromMode(nil, "mkm", tc.co); got != tc.want {
				t.Errorf("getIDFromMode(mkm, %s) = %q, want %q", tc.co.UUID, got, tc.want)
			}
		})
	}
}
