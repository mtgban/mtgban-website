package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// rarityBackend builds a backend for the game holding one card per uuid at
// the rarity given, ranked by order as a loader ranks its game's.
func rarityBackend(game mtgmatcher.Game, order []string, cards map[string]string) *mtgmatcher.Backend {
	b := &mtgmatcher.Backend{Game: game, UUIDs: map[string]*mtgmatcher.CardObject{}}
	for uuid, rarity := range cards {
		co := &mtgmatcher.CardObject{}
		co.UUID = uuid
		co.Rarity = rarity
		b.UUIDs[uuid] = co
		b.AllUUIDs = append(b.AllUUIDs, uuid)
	}
	slices.Sort(b.AllUUIDs)
	b.Rarities = mtgmatcher.RarityNames(order)
	b.IndexRarities()
	return b
}

// rarityKept parses the query the way the search does and lists the cards
// its filters keep.
func rarityKept(b *mtgmatcher.Backend, query string) []string {
	config := parseSearchOptionsNG(b, query, nil, nil, nil)
	var kept []string
	for _, uuid := range b.AllUUIDs {
		skip := shouldSkipCardNG(b, uuid, config.CardFilters)
		if !skip {
			kept = append(kept, uuid)
		}
	}
	return kept
}

// Every game reads r: as its rarities are listed, one lower-case word or the
// letter they begin, and ranks r> and r< by its own order.
func TestRarityFilterReadsEachGamesOrder(t *testing.T) {
	magic := rarityBackend(mtgmatcher.GameMagic,
		[]string{"oversize", "special", "mythic", "rare", "uncommon", "common", "token"},
		map[string]string{"bolt": "common", "jace": "mythic", "lotus": "rare", "goblin": "token", "pack": "product"})
	gundam := rarityBackend("gundam",
		[]string{"Promo", "LR+", "Legend Rare", "Rare", "Uncommon", "Common"},
		map[string]string{"lr": "Legend Rare", "lrplus": "LR+", "rare": "Rare", "common": "Common"})
	lorcana := rarityBackend("lorcana",
		[]string{"Special", "Promo", "Quest", "Iconic", "Enchanted", "Epic", "Legendary", "Super Rare", "Rare", "Uncommon", "Common", "None"},
		map[string]string{"sp": "special", "en": "enchanted", "ep": "epic", "sr": "superrare", "ra": "rare", "co": "common"})
	onepiece := rarityBackend("onepiece",
		[]string{"Promo", "Treasure Rare", "Secret Rare", "Leader", "Super Rare", "Rare", "Uncommon", "Common", "DON!!", "None"},
		map[string]string{"sec": "secretrare", "sr": "superrare", "c": "common"})

	tests := []struct {
		b     *mtgmatcher.Backend
		query string
		want  []string
	}{
		{magic, "r:m", []string{"jace"}},
		{magic, "r:mythic", []string{"jace"}},
		{magic, "r>rare", []string{"jace"}},
		{magic, "r<rare", []string{"bolt", "goblin", "pack"}},
		{magic, "r:product", []string{"pack"}},

		{gundam, "r:legendrare", []string{"lr"}},
		{gundam, "r:LegendRare", []string{"lr"}},
		{gundam, "r:lr+", []string{"lrplus"}},
		{gundam, "r>rare", []string{"lr", "lrplus"}},
		{gundam, "r<rare", []string{"common"}},
		{gundam, "-r:common", []string{"lr", "lrplus", "rare"}},
		{gundam, "r:c", []string{"common"}},
		{gundam, "r:l", []string{"lr", "lrplus"}},

		{lorcana, "r:s", []string{"sp", "sr"}},
		{lorcana, "r>s", []string{"en", "ep", "sp"}},
		{lorcana, "r<s", []string{"co", "en", "ep", "ra", "sr"}},
		{lorcana, "r>e", []string{"en", "sp"}},
		{lorcana, "r<e", []string{"co", "ep", "ra", "sr"}},
		{lorcana, "r>superrare", []string{"en", "ep", "sp"}},
		{lorcana, "r>rare,special", []string{"en", "ep", "sp", "sr"}},
		{lorcana, "-r>s", []string{"co", "ra", "sr"}},

		{onepiece, "r:superrare", []string{"sr"}},
		{onepiece, "r:c", []string{"c"}},
		{onepiece, "r>superrare", []string{"sec"}},
	}
	for _, test := range tests {
		got := rarityKept(test.b, test.query)
		if !slices.Equal(got, test.want) {
			t.Errorf("%s %q kept %v, want %v", test.b.Game, test.query, got, test.want)
		}
	}
}
