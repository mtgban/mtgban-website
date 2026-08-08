package moxfield

import (
	"encoding/json"
	"testing"
)

// A deck entry aggregates all copies of a card under one representative
// printing; the real per-copy breakdown arrives in printingData and must
// expand to one item per printing (the source of "the uploader lumps my
// land variations together").
func TestPrepareDecklistExpandsPrintings(t *testing.T) {
	blob := `{"name":"Galaxy Lands","boards":{"mainboard":{"count":8,"cards":{
		"aaa":{"quantity":7,"finish":"nonFoil","card":{"scryfall_id":"scry-island","name":"Island"},
			"printingData":[
				{"quantity":2,"finish":"nonFoil","set":"unf","cn":"236"},
				{"quantity":2,"finish":"foil","set":"unf","cn":"236"},
				{"quantity":2,"finish":"foil","set":"unf","cn":"487"},
				{"quantity":1,"finish":"foil","set":"unf","cn":"492"}]},
		"bbb":{"quantity":1,"finish":"foil","card":{"scryfall_id":"scry-swamp","name":"Swamp"}}
	}}}}`

	var deck Deck
	if err := json.Unmarshal([]byte(blob), &deck); err != nil {
		t.Fatal(err)
	}
	if deck.Name != "Galaxy Lands" {
		t.Errorf("deck name = %q, want Galaxy Lands", deck.Name)
	}

	items := prepareDecklist(&deck, 100)
	if len(items) != 5 {
		t.Fatalf("items = %d, want 5 (4 printings + 1 without breakdown)", len(items))
	}

	var galaxy, nonfoil, fallback *Item
	for i := range items {
		switch {
		case items[i].Number == "487":
			galaxy = &items[i]
		case items[i].Number == "236" && !items[i].IsFoil:
			nonfoil = &items[i]
		case items[i].ScryfallID == "scry-swamp":
			fallback = &items[i]
		}
	}

	if galaxy == nil || galaxy.Name != "Island" || galaxy.SetCode != "unf" ||
		!galaxy.IsFoil || galaxy.Quantity != 2 || galaxy.ScryfallID != "" {
		t.Errorf("galaxy printing item wrong: %+v", galaxy)
	}
	if nonfoil == nil || nonfoil.Quantity != 2 {
		t.Errorf("nonfoil printing item wrong: %+v", nonfoil)
	}
	if fallback == nil || !fallback.IsFoil || fallback.Quantity != 1 {
		t.Errorf("entry without printingData should fall back to the representative printing: %+v", fallback)
	}
}
