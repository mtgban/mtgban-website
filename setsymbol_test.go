package main

import (
	"os"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The set-symbol directory is named for the game, and that name is written by
// whoever edits the config. Only a game the matcher registers may name one.
//
// What the old code did with a climbing name is worth stating exactly, because
// it is narrower than the shape of the bug suggests: it read every .svg in
// whatever directory the name reached - img/logo holds two - but only files
// parsing as a badge were ever filed, and a logo is not one. So this closes an
// arbitrary .svg read rather than a demonstrated leak, and the one case below
// whose behaviour visibly changes is the empty name, which used to file
// img/setsymbol/default.svg a second time under "default".
func TestSetSymbolsOnlyReadUnderTheirOwnDirectory(t *testing.T) {
	for _, game := range []string{"../logo", "..", "../..", "/etc", "nosuchgame", ""} {
		t.Run(game, func(t *testing.T) {
			defer func(old string) { Config.Game = old }(Config.Game)
			defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
			Config.Game = game
			rarityBadges = map[string]rarityBadge{}

			loadRarityBadges()

			for key := range rarityBadges {
				// The "" fallback comes from a fixed path and is always fine.
				if key != "" {
					t.Errorf("game %q filed a badge %q read from outside its directory", game, key)
				}
			}
		})
	}
}

// A game that is registered still reads its own symbols.
func TestSetSymbolsLoadForARegisteredGame(t *testing.T) {
	for _, game := range mtgmatcher.RegisteredGames() {
		if game == DefaultGame {
			continue // the default returns before reading a directory
		}
		entries, err := os.ReadDir("img/setsymbol/" + game)
		if err != nil || len(entries) == 0 {
			continue
		}

		defer func(old string) { Config.Game = old }(Config.Game)
		defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
		Config.Game = game
		rarityBadges = map[string]rarityBadge{}

		loadRarityBadges()
		if len(rarityBadges) < 2 { // the fallback, plus at least one symbol
			t.Errorf("%s is registered and ships symbols, but loaded %d badges", game, len(rarityBadges))
		}
		return
	}
	t.Skip("no registered game ships set symbols in this checkout")
}
