package main

import "testing"

// A game other than Magic searches by substring, since its card names carry a
// subtitle the searcher rarely types from the front of. Magic keeps the
// exact-then-prefix default. Anything the query names itself wins on both.
func TestDefaultSearchModePerGame(t *testing.T) {
	prev := Config.Game
	t.Cleanup(func() { Config.Game = prev })

	for _, tc := range []struct {
		name, game, query, want string
	}{
		{"magic keeps the default mode", DefaultGame, "lightning bolt", ""},
		{"lorcana searches by substring", "lorcana", "mickey mouse", "any"},
		{"riftbound searches by substring", "riftbound", "yasuo", "any"},
		{"onepiece searches by substring", "onepiece", "luffy", "any"},

		{"an explicit mode wins on magic", DefaultGame, "bolt sm:exact", "exact"},
		{"an explicit mode wins elsewhere", "lorcana", "mickey sm:exact", "exact"},
		{"an explicit prefix wins elsewhere", "lorcana", "mickey sm:prefix", "prefix"},
		// Asking for the mode that is now the default is not a mistake.
		{"asking for the default explicitly", "lorcana", "mickey sm:any", "any"},

		// An empty query with only a filter still seeds from the set index;
		// search.go's edition-seed switch has to list the mode for that.
		{"a filter-only query", "lorcana", "s:TFC", "any"},

		// Scryfall knows only Magic, and only a Magic datastore resolves what
		// it returns, so the mode is Magic's alone.
		{"scryfall stands on magic", DefaultGame, "bolt sm:scryfall", "scryfall"},
		{"scryfall is dropped on lorcana", "lorcana", "mickey sm:scryfall", "any"},
		{"scryfall is dropped on riftbound", "riftbound", "yasuo sm:scryfall", "any"},
		{"scryfall is dropped on onepiece", "onepiece", "luffy sm:scryfall", "any"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Config.Game = tc.game
			config := parseSearchOptionsNG(tc.query, nil, nil, nil)
			if config.SearchMode != tc.want {
				t.Errorf("game %q, query %q: SearchMode = %q, want %q",
					tc.game, tc.query, config.SearchMode, tc.want)
			}
		})
	}
}

// Dropping the mode must not leave its text in the query: the option is
// stripped before the mode is read, so what is left is the name alone.
func TestDroppedScryfallLeavesNoResidue(t *testing.T) {
	prev := Config.Game
	t.Cleanup(func() { Config.Game = prev })
	Config.Game = "lorcana"

	config := parseSearchOptionsNG("mickey sm:scryfall", nil, nil, nil)
	if config.CleanQuery != "mickey" {
		t.Errorf("CleanQuery = %q, want %q", config.CleanQuery, "mickey")
	}
	if config.SearchMode != "any" {
		t.Errorf("SearchMode = %q, want the game default %q", config.SearchMode, "any")
	}
}

// The sealed handlers assign their mode after the parse, so the per-game
// default must not survive into a sealed search.
func TestSealedOverridesTheGameDefault(t *testing.T) {
	prev := Config.Game
	t.Cleanup(func() { Config.Game = prev })
	Config.Game = "lorcana"

	config := parseSearchOptionsNG("illumineer's quest", nil, nil, nil)
	if config.SearchMode != "any" {
		t.Fatalf("precondition: SearchMode = %q, want %q", config.SearchMode, "any")
	}
	config.SearchMode = "sealed"
	if config.SearchMode != "sealed" {
		t.Errorf("SearchMode = %q, want the sealed handler's own mode", config.SearchMode)
	}
}
