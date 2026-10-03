package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestRarityBadgesKeyByName pins that a badge's colors and shapes are keyed
// by mtgmatcher.RarityName, the spelling a card carries its rarity in, and
// that a rarity spelled the way a datastore publishes it finds its color.
func TestRarityBadgesKeyByName(t *testing.T) {
	for game, colors := range colorRarityMap {
		for rarity := range colors {
			if rarity != mtgmatcher.RarityName(rarity) {
				t.Errorf("%s: %q is not spelled by RarityName", game, rarity)
			}
		}
	}

	// As the datastores publish them
	for _, tt := range []struct {
		game   mtgmatcher.Game
		rarity string
	}{
		{mtgmatcher.GameOnePiece, "Super Rare"},
		{mtgmatcher.GamePalworld, "Trial Deck Super Rare"},
		{mtgmatcher.GameYuGiOh, "Secret Pharaoh's Rare"},
		{mtgmatcher.GameYuGiOh, "Ultra Pharaoh's Rare"},
		{mtgmatcher.GameGundam, "LR++"},
	} {
		if colorRarityMap[tt.game][mtgmatcher.RarityName(tt.rarity)] == "" {
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
			if rarity != mtgmatcher.RarityName(rarity) {
				t.Errorf("%s: shape %q is not named by RarityName", dir.Name(), file.Name())
			}
		}
	}
}
