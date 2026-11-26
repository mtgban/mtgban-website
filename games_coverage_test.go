package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// registeredGames is every game matcher activates through its games
// package, which is what a deployment can be configured as. Read from
// matcher.RegisteredGames() rather than a hand-kept list, so a game whose
// blank import lands here doesn't first need a matching edit in this file.
var registeredGames = matcher.RegisteredGames()

// A game absent from gameMap gets no newspaper, cacheNewspaper logging an
// error on every refresh, so the entry has to exist before an instance of
// that game is stood up.
func TestEveryRegisteredGameIsNamed(t *testing.T) {
	for _, game := range registeredGames {
		name, found := gameMap[game]
		if !found {
			t.Errorf("game %q has no gameMap entry; a deployment of it would serve no newspaper", game)
			continue
		}
		if name == "" {
			t.Errorf("game %q is named by an empty string", game)
		}
	}
}

// A non-Magic site names its own category through the catalog it ships, so
// there is no table here to fall out of step with the games the matcher
// registers - only a dump to ship. What still has to hold is that the scope
// degrades safely when no catalog is loaded: it widens to the whole table
// rather than resolving to nothing.
func TestVariantScopeWithoutCatalog(t *testing.T) {
	origGame := Config().Game
	t.Cleanup(func() { Config().Game = origGame })

	for _, game := range registeredGames {
		if game == DefaultGame {
			continue
		}
		Config().Game = game
		scope := variantCacheScope()
		if scope.Magic || len(scope.TCGCategoryIDs) != 0 {
			t.Errorf("game %q with no catalog: scope is %+v, want the unscoped fallback", game, scope)
		}
	}
}

func TestVariantCacheScope(t *testing.T) {
	origGame, origTCGCSV, origCatalog := Config().Game, Config().TCGCSVConfig, tcgCatalogPtr.Load()
	t.Cleanup(func() {
		Config().Game, Config().TCGCSVConfig = origGame, origTCGCSV
		tcgCatalogPtr.Store(origCatalog)
	})

	// A config listing other games must not widen the scope: the site ingests nothing.
	listing := &tcgcsv.Config{Games: []tcgcsv.GameConfig{
		{Name: "Disney Lorcana", CategoryID: tcgcsv.CategoryLorcana},
		{Name: "Riftbound", CategoryID: tcgcsv.CategoryRiftbound},
	}}

	cases := []struct {
		name string
		game matcher.Game
		// catalog is the TCGplayer category the loaded dump names, which is
		// how a non-Magic site learns its own; 0 stands for no dump loaded.
		catalog int
		tcgcsv  *tcgcsv.Config
		want    timeseries.VariantScope
	}{
		{
			name: "magic reads only the uuid-keyed rows",
			game: DefaultGame,
			want: timeseries.VariantScope{Magic: true},
		},
		{
			name:    "a non-magic site reads only its own category",
			game:    "lorcana",
			catalog: tcgcsv.CategoryLorcana,
			want:    timeseries.VariantScope{TCGCategoryIDs: []int{tcgcsv.CategoryLorcana}},
		},
		{
			name:    "a tcgcsv_config listing other games does not widen the scope",
			game:    "onepiece",
			catalog: tcgcsv.CategoryOnePiece,
			tcgcsv:  listing,
			want:    timeseries.VariantScope{TCGCategoryIDs: []int{tcgcsv.CategoryOnePiece}},
		},
		{
			name: "a site whose catalog has not loaded falls back to the whole table",
			game: "lorcana",
			want: timeseries.VariantScope{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			Config().Game, Config().TCGCSVConfig = tc.game, tc.tcgcsv
			if tc.catalog != 0 {
				tcgCatalogPtr.Store(&tcgCatalogSnapshot{CategoryID: tc.catalog})
			} else {
				tcgCatalogPtr.Store(nil)
			}
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
