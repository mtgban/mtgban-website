package palette

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestRarityListFollowsTheGame pins the rarity list: the game's order, only
// what a printing carries, each labelled as its cards spell it, and a letter
// only where it names that rarity alone.
func TestRarityListFollowsTheGame(t *testing.T) {
	b := &mtgmatcher.Backend{UUIDs: map[string]*mtgmatcher.CardObject{}}
	for uuid, rarity := range map[string]string{
		"a": "Super Rare", "b": "Super Rare", "c": "special", "d": "Legend Rare", "e": "Common",
	} {
		co := &mtgmatcher.CardObject{}
		co.UUID = uuid
		co.Rarity = rarity
		b.UUIDs[uuid] = co
		b.AllUUIDs = append(b.AllUUIDs, uuid)
	}
	slices.Sort(b.AllUUIDs)
	b.Rarities = mtgmatcher.RarityNames([]string{"Special", "Legend Rare", "Super Rare", "Rare", "Common"})

	got := RarityList(b)
	want := []Rarity{
		{Value: "special", Label: "Special", Count: 1},
		{Value: "legendrare", Label: "Legend Rare", Letter: "l", Count: 1},
		{Value: "superrare", Label: "Super Rare", Count: 2},
		{Value: "common", Label: "Common", Letter: "c", Count: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("RarityList =\n %+v\nwant\n %+v", got, want)
	}
}

// TestColorListFollowsTheSets pins the colour list: every colour a set lists,
// in the order the sets list them, colorless and multicolor last.
func TestColorListFollowsTheSets(t *testing.T) {
	b := &mtgmatcher.Backend{Sets: map[string]*mtgmatcher.Set{
		"AAA": {Code: "AAA", Colors: []string{"fury", "mind", "colorless"}},
		"BBB": {Code: "BBB", Colors: []string{"fury", "calm", "mind", "order", "multicolor"}},
		"CCC": {Code: "CCC"},
	}}
	b.AllSets = []string{"AAA", "BBB", "CCC"}

	var got []string
	for _, color := range ColorList(b) {
		got = append(got, color.Value+"="+color.Label)
	}
	want := []string{"fury=Fury", "calm=Calm", "mind=Mind", "order=Order", "colorless=Colorless", "multicolor=Multicolor"}
	if !slices.Equal(got, want) {
		t.Errorf("ColorList = %v, want %v", got, want)
	}
}
