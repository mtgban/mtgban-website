package main

import (
	"testing"
	"time"
)

// Curated ban/unban/format events are matched purely by card name and carry no
// Magic assumptions, so they must surface for a TCGplayer-product-id game
// (Lorcana) exactly as they do for Magic. Only the MTGJSON/Keyrune-derived
// release & reprint markers are Magic-gated. Regression guard against the
// earlier "checkpoints are Magic-only" gate that suppressed bans wholesale.
func TestCuratedCheckpointsApplyToAllGames(t *testing.T) {
	savedGame := Config.Game
	savedEvents := checkpointsStore.Get()
	defer func() {
		Config.Game = savedGame
		checkpointsStore.Set(savedEvents)
	}()

	const banned = "Bucky - Squirrel Squadron"
	checkpointsStore.Set(checkpointsFile{Events: []CheckpointEvent{
		{
			ID:          "test-ban",
			Type:        "ban",
			Date:        "2024-11-15",
			Format:      "Core Constructed",
			Title:       "Q3 Banned & Restricted",
			CardsBanned: []string{banned},
		},
	}})

	earliest := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, game := range []string{"lorcana", "magic"} {
		Config.Game = game

		bans := 0
		for _, cp := range relevantCheckpoints(banned, earliest) {
			if cp.Type == "ban" {
				bans++
			}
		}
		if bans != 1 {
			t.Errorf("%s: got %d ban checkpoints, want 1 (curated bans apply to every game)", game, bans)
		}

		// A card on no curated list gets no curated markers — the match is by
		// name. Magic still emits card-independent release markers from set
		// metadata (they annotate every chart in the window), so count only the
		// curated types here rather than the full set.
		curated := 0
		for _, cp := range relevantCheckpoints("Some Unlisted Card", earliest) {
			switch cp.Type {
			case "ban", "unban", "format":
				curated++
			}
		}
		if curated != 0 {
			t.Errorf("%s: unlisted card got %d curated checkpoints, want 0", game, curated)
		}
	}
}
