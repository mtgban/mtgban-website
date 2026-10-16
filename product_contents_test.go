package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

func TestRankDeckCards(t *testing.T) {
	prices := map[string]float64{"a": 1, "b": 20, "c": 0, "d": 20}
	price := func(id string) float64 { return prices[id] }

	got := rankDeckCards([]string{"a", "b", "c", "d", "b", "a"}, price)
	// Priciest first; b and d tie and keep the deck's order; unpriced c last;
	// each card once.
	if want := []string{"b", "d", "a", "c"}; !slices.Equal(got, want) {
		t.Fatalf("ranked %v, want %v", got, want)
	}

	none := rankDeckCards([]string{"x", "y", "z"}, func(string) float64 { return 0 })
	if want := []string{"x", "y", "z"}; !slices.Equal(none, want) {
		t.Fatalf("unpriced deck reordered to %v", none)
	}
	if rankDeckCards(nil, price) != nil {
		t.Fatal("nil deck gave lines")
	}
}

func TestLimitContents(t *testing.T) {
	lines := []ContentLine{{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"}, {Name: "5"}, {Name: "6"}, {Name: "7"}}
	kept, more := limitContents(lines, 5)
	if len(kept) != 5 || kept[4].Name != "5" || more != 2 {
		t.Fatalf("kept %d more %d", len(kept), more)
	}
	kept, more = limitContents(lines[:3], 5)
	if len(kept) != 3 || more != 0 {
		t.Fatalf("short list: kept %d more %d", len(kept), more)
	}
	kept, more = limitContents(nil, 5)
	if kept != nil || more != 0 {
		t.Fatalf("nil: kept %v more %d", kept, more)
	}
	kept, more = limitContents(lines, 0)
	if len(kept) != 7 || more != 0 {
		t.Fatalf("no limit: kept %d more %d", len(kept), more)
	}
}

func TestBoosterName(t *testing.T) {
	set := &mtgmatcher.Set{Booster: map[string]mtgmatcher.Booster{"play": {Name: "Play Booster"}, "nameless": {}}}
	cases := map[string]string{"play": "Play Booster", "nameless": "Nameless booster", "collector": "Collector booster", "": "Booster"}
	for code, want := range cases {
		if got := boosterName(set, code); got != want {
			t.Errorf("boosterName(%q) = %q, want %q", code, got, want)
		}
	}
}

// contentLines on a hand-built product: every kind in the sealed package's
// order, a deck the set lacks skipped, a card the backend lacks skipped.
func TestContentLinesSkipsAnUnknownDeck(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	// Any real card and any real sealed product, for the lines that name one.
	var cardID, sealedID string
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		if co.Sealed && sealedID == "" {
			sealedID = uuid
		}
		if !co.Sealed && cardID == "" {
			cardID = uuid
		}
		if cardID != "" && sealedID != "" {
			break
		}
	}
	// GetUUIDs lists no sealed product, so take one from the sealed list.
	if sealedID == "" && len(b.GetSealedUUIDs()) > 0 {
		sealedID = b.GetSealedUUIDs()[0]
	}
	set := &mtgmatcher.Set{Booster: map[string]mtgmatcher.Booster{"play": {Name: "Play Booster"}}}
	product := &mtgmatcher.SealedProduct{Contents: map[string][]mtgmatcher.SealedContent{
		"card":     {{UUID: cardID, Count: 2}, {UUID: "no-such-card", Count: 1}},
		"pack":     {{Code: "play", Count: 36}},
		"deck":     {{Set: "XYZ", Name: "No Such Deck"}},
		"sealed":   {{UUID: sealedID, Count: 1}},
		"variable": {{Configs: make([]map[string][]mtgmatcher.SealedContent, 3)}},
	}}
	lines := contentLines(b, set, product)
	var names []string
	for _, l := range lines {
		names = append(names, l.Name)
	}
	if len(lines) != 4 {
		t.Fatalf("lines %v, want a card, a pack, a product and a variable line", names)
	}
	if lines[0].Count != 2 || lines[0].Link != "/search?q="+cardID {
		t.Errorf("card line %+v", lines[0])
	}
	if lines[1].Count != 36 || lines[1].Name != "Play Booster" || lines[1].Link != "" {
		t.Errorf("pack line %+v", lines[1])
	}
	if lines[2].Count != 1 || lines[2].Link != "/sealed?q="+sealedID {
		t.Errorf("sealed line %+v", lines[2])
	}
	if lines[3].Name != "One of 3 configurations" || lines[3].Link != "" {
		t.Errorf("variable line %+v", lines[3])
	}
}

// findProduct returns the first sealed product of the loaded datastore that
// keep accepts, with its set, or skips the test.
func findProduct(t *testing.T, keep func(p mtgmatcher.SealedProduct) bool) (*mtgmatcher.CardObject, *mtgmatcher.Set) {
	t.Helper()
	b := backend()
	for _, code := range b.GetAllSets() {
		set, err := b.GetSet(code)
		if err != nil {
			continue
		}
		for _, p := range set.SealedProduct {
			if !keep(p) {
				continue
			}
			co, err := b.GetUUID(p.UUID)
			if err != nil {
				continue
			}
			return co, set
		}
	}
	t.Skip("no such product in this datastore")
	return nil, nil
}

func entryCount(p mtgmatcher.SealedProduct) int {
	n := 0
	for _, entries := range p.Contents {
		n += len(entries)
	}
	return n
}

func TestProductContentsListsAPreconsNotableCards(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := findProduct(t, func(p mtgmatcher.SealedProduct) bool {
		for _, d := range p.Contents["deck"] {
			if ids, err := sealed.DeckCards(backend(), d.Set, d.Name); err == nil && len(ids) >= 6 {
				return true
			}
		}
		return false
	})
	t.Logf("deck product: %s (%s)", co.Name, co.SetCode)
	lines, more := productContents(backend(), co, contentsLineLimit)
	if len(lines) == 0 || len(lines) > contentsLineLimit {
		t.Fatalf("%s: %d lines", co.Name, len(lines))
	}
	if more <= 0 {
		t.Fatalf("%s: a deck of cards left %d off", co.Name, more)
	}
	for _, l := range lines {
		if l.Name == "" {
			t.Fatalf("%s: a nameless line %+v", co.Name, l)
		}
		if l.Link == "" {
			t.Fatalf("%s: a line without a link %+v", co.Name, l)
		}
	}
}

// This data declares a box's packs as sealed boosters, not as pack entries.
func TestProductContentsListsABoxsSealedBoosters(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := findProduct(t, func(p mtgmatcher.SealedProduct) bool {
		return entryCount(p) == 1 && len(p.Contents["sealed"]) == 1 && p.Contents["sealed"][0].Count > 1
	})
	t.Logf("box product: %s (%s)", co.Name, co.SetCode)
	lines, _ := productContents(backend(), co, contentsLineLimit)
	if len(lines) != 1 || lines[0].Count <= 1 || lines[0].Name == "" || lines[0].Link == "" {
		t.Fatalf("%s: lines %+v, want one counted sealed line", co.Name, lines)
	}
}

func TestProductContentsSkipsALoneBooster(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := findProduct(t, func(p mtgmatcher.SealedProduct) bool {
		return entryCount(p) == 1 && len(p.Contents["pack"]) == 1 && p.Contents["pack"][0].Count <= 1
	})
	t.Logf("lone booster: %s (%s)", co.Name, co.SetCode)
	if lines, more := productContents(backend(), co, contentsLineLimit); lines != nil || more != 0 {
		t.Fatalf("%s: a lone booster listed %v (+%d)", co.Name, lines, more)
	}
}

func TestProductContentsNothingForACard(t *testing.T) {
	skipWithoutDatastore(t)
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		if lines, more := productContents(backend(), co, contentsLineLimit); lines != nil || more != 0 {
			t.Fatalf("a card listed contents %v", lines)
		}
		return
	}
}

func TestDedupeLinesByName(t *testing.T) {
	in := []ContentLine{
		{Name: "Sol Ring", Link: "a", Price: 2},
		{Name: "Forest", Link: "b"},
		{Name: "Sol Ring", Link: "c", Price: 1},
	}
	got := dedupeLinesByName(in)
	if len(got) != 2 || got[0].Link != "a" || got[1].Name != "Forest" {
		t.Errorf("got %+v, want the first Sol Ring then Forest", got)
	}
	if len(dedupeLinesByName(nil)) != 0 {
		t.Error("nil input gave lines")
	}
}
