package main

import (
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/tcgcsv"
)

func TestBackfillGames(t *testing.T) {
	prev := Config.TCGCSVConfig
	t.Cleanup(func() { Config.TCGCSVConfig = prev })
	Config.TCGCSVConfig = &tcgcsv.Config{Games: []tcgcsv.GameConfig{
		{Name: "Pokemon", CategoryID: 3},
		{Name: "Disney Lorcana", CategoryID: 71},
		{Name: "Riftbound", CategoryID: 89},
	}}

	t.Run("empty spec takes every configured game", func(t *testing.T) {
		games, err := backfillGames("")
		if err != nil {
			t.Fatal(err)
		}
		if len(games) != 3 {
			t.Fatalf("got %d games, want all 3", len(games))
		}
	})

	t.Run("filters and dedupes", func(t *testing.T) {
		games, err := backfillGames(" 71, 3 ,71")
		if err != nil {
			t.Fatal(err)
		}
		if len(games) != 2 || games[0].CategoryID != 71 || games[1].CategoryID != 3 {
			t.Fatalf("got %+v, want categories 71 then 3", games)
		}
		if games[0].Name != "Disney Lorcana" {
			t.Errorf("category 71 resolved to %q, want the configured name", games[0].Name)
		}
	})

	t.Run("unconfigured category is an error", func(t *testing.T) {
		_, err := backfillGames("71,999")
		if err == nil {
			t.Fatal("want an error for a category that isn't configured")
		}
		// The message lists what is configured, so a typo is fixable from it.
		if !strings.Contains(err.Error(), "71 (Disney Lorcana)") {
			t.Errorf("error should list the configured games, got %q", err)
		}
	})

	t.Run("non-numeric category is an error", func(t *testing.T) {
		if _, err := backfillGames("lorcana"); err == nil {
			t.Fatal("want an error for a non-numeric category id")
		}
	})

	t.Run("comma-only spec selects nothing", func(t *testing.T) {
		if _, err := backfillGames(","); err == nil {
			t.Fatal("want an error when the spec selects no games")
		}
	})
}
