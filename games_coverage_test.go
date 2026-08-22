package main

import "testing"

// registeredGames is every game mtgmatcher activates through its games
// package, which is what a deployment can be configured as. Keep it in step
// with go-mtgban/mtgmatcher/games/games.go.
var registeredGames = []string{
	"fleshandblood",
	"lorcana",
	"magic",
	"onepiece",
	"riftbound",
	"yugioh",
}

// A game absent from gameMap panics the newspaper cache at startup
// (news.go's "missing game in newspaper map"), so the entry has to exist
// before an instance of that game is stood up rather than after the crash.
func TestEveryRegisteredGameIsNamed(t *testing.T) {
	for _, game := range registeredGames {
		name, found := gameMap[game]
		if !found {
			t.Errorf("game %q has no gameMap entry; a deployment of it would panic at startup", game)
			continue
		}
		if name == "" {
			t.Errorf("game %q is named by an empty string", game)
		}
	}
}
