package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The custom buylist rule prices nothing from the Collectors' Editions, 30A or
// the World Championship Decks, and still prices everything else.
func TestCustomBuylistSkipsSets(t *testing.T) {
	cardID := firstPlainCard(t)
	skipped := map[string]string{}
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) && skipped[co.SetCode] == "" {
			skipped[co.SetCode] = id
		}
	}
	for _, code := range customBuylistSkipSets {
		if skipped[code] == "" {
			t.Errorf("no %s card in the datastore", code)
		}
	}

	rule := EntryRule{SkipSets: customBuylistSkipSets, Rate: 0.5}
	for code, id := range skipped {
		out := map[string]map[string]*BanPrice{}
		processEntry(backend(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", id, "CUSTOM", false, false, false, rule)
		if len(out) != 0 {
			t.Errorf("%s card %s priced by the custom buylist", code, id)
		}
	}

	out := map[string]map[string]*BanPrice{}
	processEntry(backend(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", cardID, "CUSTOM", false, false, false, rule)
	if out[cardID]["CUSTOM"] == nil {
		t.Errorf("plain card %s not priced by the custom buylist", cardID)
	}
}
