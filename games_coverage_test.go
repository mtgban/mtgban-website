package main

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

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

// A game with no TCGplayer category can't scope its variant cache warm, so it
// silently falls back to loading every game's variants -- the ~120MB startup
// that OOMs the small instances. Catch the missing entry here instead.
func TestEveryRegisteredGameHasAVariantScope(t *testing.T) {
	for _, game := range registeredGames {
		id, found := tcgcsv.CategoryForGame(game)
		switch {
		case game == DefaultGame:
			if found {
				t.Errorf("magic has TCGplayer category %d; its variants are keyed by mtgjson uuid", id)
			}
		case !found:
			t.Errorf("game %q has no tcgcsv.CategoryForGame entry; its variant cache would warm every game", game)
		case id == 0:
			t.Errorf("game %q maps to category 0", game)
		}
	}
}

func TestVariantCacheScope(t *testing.T) {
	origGame, origTCGCSV := Config.Game, Config.TCGCSVConfig
	t.Cleanup(func() { Config.Game, Config.TCGCSVConfig = origGame, origTCGCSV })

	ingesting := &tcgcsv.Config{Games: []tcgcsv.GameConfig{
		{Name: "Disney Lorcana", CategoryID: tcgcsv.CategoryLorcana},
		{Name: "Riftbound", CategoryID: tcgcsv.CategoryRiftbound},
	}}

	cases := []struct {
		name   string
		game   string
		tcgcsv *tcgcsv.Config
		want   timeseries.VariantScope
	}{
		{
			name: "magic reads only the uuid-keyed rows",
			game: DefaultGame,
			want: timeseries.VariantScope{Magic: true},
		},
		{
			name: "a non-magic site reads only its own category",
			game: "lorcana",
			want: timeseries.VariantScope{TCGCategoryIDs: []int{tcgcsv.CategoryLorcana}},
		},
		{
			name:   "an ingesting site also reads what it writes",
			game:   "onepiece",
			tcgcsv: ingesting,
			want: timeseries.VariantScope{TCGCategoryIDs: []int{
				tcgcsv.CategoryOnePiece, tcgcsv.CategoryLorcana, tcgcsv.CategoryRiftbound,
			}},
		},
		{
			name:   "the site's own category is not repeated",
			game:   "lorcana",
			tcgcsv: ingesting,
			want: timeseries.VariantScope{TCGCategoryIDs: []int{
				tcgcsv.CategoryLorcana, tcgcsv.CategoryRiftbound,
			}},
		},
		{
			name:   "magic ingesting non-magic games wants both halves",
			game:   DefaultGame,
			tcgcsv: ingesting,
			want: timeseries.VariantScope{Magic: true, TCGCategoryIDs: []int{
				tcgcsv.CategoryLorcana, tcgcsv.CategoryRiftbound,
			}},
		},
		{
			name: "an unknown game falls back to the whole table",
			game: "notagame",
			want: timeseries.VariantScope{},
		},
		{
			// The fallback has to stay the whole table rather than narrowing to
			// what this process ingests: the site's own game is the one thing
			// the ingest list does not name, and dropping it would cost every
			// rendered card its ban_id.
			name:   "an unknown game that ingests still reads everything",
			game:   "notagame",
			tcgcsv: ingesting,
			want:   timeseries.VariantScope{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			Config.Game, Config.TCGCSVConfig = tc.game, tc.tcgcsv
			got := variantCacheScope()
			if got.Magic != tc.want.Magic {
				t.Errorf("Magic = %v, want %v", got.Magic, tc.want.Magic)
			}
			if !slices.Equal(got.TCGCategoryIDs, tc.want.TCGCategoryIDs) {
				t.Errorf("TCGCategoryIDs = %v, want %v", got.TCGCategoryIDs, tc.want.TCGCategoryIDs)
			}
		})
	}
}
