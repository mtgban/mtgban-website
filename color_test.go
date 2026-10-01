package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// colorBackend builds a backend for the game holding one card per uuid, with
// the colours given.
func colorBackend(game mtgmatcher.Game, cards map[string][]string) *mtgmatcher.Backend {
	b := &mtgmatcher.Backend{Game: game, UUIDs: map[string]*mtgmatcher.CardObject{}}
	for uuid, colors := range cards {
		co := &mtgmatcher.CardObject{}
		co.UUID = uuid
		co.Colors = colors
		b.UUIDs[uuid] = co
		b.AllUUIDs = append(b.AllUUIDs, uuid)
	}
	slices.Sort(b.AllUUIDs)
	return b
}

// keptBy parses the query the way the search does and lists the cards its
// filters keep.
func keptBy(b *mtgmatcher.Backend, query string) []string {
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

// Magic reads c: as its letters and named groups; every other game reads it
// as the colour names it publishes, with colorless and multicolor meaning
// the same everywhere.
func TestColorFilterReadsEachGamesNames(t *testing.T) {
	magic := colorBackend(mtgmatcher.GameMagic, map[string][]string{
		"bolt":        {"R"},
		"detain":      {"W", "U"},
		"ornithopter": nil,
	})
	gundam := colorBackend("gundam", map[string][]string{
		"red":      {"red"},
		"purple":   {"purple"},
		"redblue":  {"red", "blue"},
		"resource": nil,
	})
	riftbound := colorBackend("riftbound", map[string][]string{
		"chaos":       {"chaos"},
		"chaosfury":   {"chaos", "fury"},
		"battlefield": {"colorless"},
		"rune":        nil,
	})
	palworld := colorBackend("palworld", map[string][]string{
		"pal":  {"colorless"},
		"soul": nil,
		"red":  {"red"},
	})
	pokemon := colorBackend("pokemon", map[string][]string{
		"charizard": {"fire"},
		"snorlax":   {"colorless"},
		"bill":      nil,
	})
	yugioh := colorBackend("yugioh", map[string][]string{
		"dark":  {"dark"},
		"spell": {"spell"},
	})

	tests := []struct {
		b     *mtgmatcher.Backend
		query string
		want  []string
	}{
		{magic, "c:red", []string{"bolt"}},
		{magic, "c:r", []string{"bolt"}},
		{magic, "c:azorius", []string{"detain"}},
		{magic, "c:wu", []string{"detain"}},
		{magic, "c:colorless", []string{"ornithopter"}},
		{magic, "c:multicolor", []string{"detain"}},

		{gundam, "c:Red", []string{"red", "redblue"}},
		{gundam, "c:red", []string{"red", "redblue"}},
		{gundam, "c:PURPLE", []string{"purple"}},
		{gundam, "-c:red", []string{"purple", "resource"}},
		{gundam, "c:colorless", []string{"resource"}},
		{gundam, "c:multicolor", []string{"redblue"}},

		{riftbound, "c:chaos", []string{"chaos", "chaosfury"}},
		{riftbound, "c:colorless", []string{"battlefield", "rune"}},
		{riftbound, "c:m", []string{"chaosfury"}},

		{palworld, "c:Colorless", []string{"pal", "soul"}},
		{palworld, "c:red", []string{"red"}},

		{pokemon, "c:fire", []string{"charizard"}},
		{pokemon, "c:colorless", []string{"bill", "snorlax"}},
		{pokemon, "-c:colorless", []string{"charizard"}},

		{yugioh, "c:dark", []string{"dark"}},
		{yugioh, "c:Spell", []string{"spell"}},
	}
	for _, test := range tests {
		got := keptBy(test.b, test.query)
		if !slices.Equal(got, test.want) {
			t.Errorf("%s %q kept %v, want %v", test.b.Game, test.query, got, test.want)
		}
	}
}

// identity: is the guide's alias of ci:, so both filter on colour identity.
func TestIdentityIsAColorIdentityAlias(t *testing.T) {
	b := colorBackend(mtgmatcher.GameMagic, nil)
	for _, query := range []string{"ci:wu", "identity:wu"} {
		config := parseSearchOptionsNG(b, query, nil, nil, nil)
		var names []string
		for _, filter := range config.CardFilters {
			names = append(names, filter.Name)
		}
		if !slices.Contains(names, "color_identity") {
			t.Errorf("%s filters on %v, want color_identity", query, names)
		}
	}
}
