package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
)

// TestRarityBadgesKeyByName pins that a badge's colors and shapes are keyed
// by matcher.RarityName, the spelling a card carries its rarity in, and
// that a rarity spelled the way a datastore publishes it finds its color.
func TestRarityBadgesKeyByName(t *testing.T) {
	for game, colors := range colorRarityMap {
		for rarity := range colors {
			if rarity != matcher.RarityName(rarity) {
				t.Errorf("%s: %q is not spelled by RarityName", game, rarity)
			}
		}
	}

	// As the datastores publish them
	for _, tt := range []struct {
		game   matcher.Game
		rarity string
	}{
		{matcher.GameOnePiece, "Super Rare"},
		{matcher.GamePalworld, "Trial Deck Super Rare"},
		{matcher.GameYuGiOh, "Secret Pharaoh's Rare"},
		{matcher.GameYuGiOh, "Ultra Pharaoh's Rare"},
		{matcher.GameGundam, "LR++"},
	} {
		if colorRarityMap[tt.game][matcher.RarityName(tt.rarity)] == "" {
			t.Errorf("%s %q has no color", tt.game, tt.rarity)
		}
	}

	dirs, err := os.ReadDir("img/setsymbol")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		files, err := os.ReadDir("img/setsymbol/" + dir.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			rarity := strings.TrimSuffix(file.Name(), ".svg")
			if rarity != matcher.RarityName(rarity) {
				t.Errorf("%s: shape %q is not named by RarityName", dir.Name(), file.Name())
			}
		}
	}
}
