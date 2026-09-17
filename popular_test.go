package main

import "testing"

func TestFirstUnusedPopularCardSkipsDuplicateAndMissingArt(t *testing.T) {
	resolved := map[string]GenericCard{
		"duplicate": {UUID: "duplicate", ImageURL: "used.jpg"},
		"missing":   {UUID: "missing"},
		"unique":    {UUID: "unique", ImageURL: "unique.jpg"},
	}

	card, ok := firstUnusedPopularCard(
		[]string{"duplicate", "missing", "unique"},
		map[string]struct{}{"used.jpg": {}},
		func(id string) GenericCard { return resolved[id] },
	)
	if !ok {
		t.Fatal("firstUnusedPopularCard returned no card")
	}
	if card.UUID != "unique" {
		t.Fatalf("firstUnusedPopularCard chose %q, want unique", card.UUID)
	}
}

func TestFirstUnusedPopularCardReturnsFalseWhenAllArtIsUsed(t *testing.T) {
	card, ok := firstUnusedPopularCard(
		[]string{"one", "two"},
		map[string]struct{}{"same.jpg": {}},
		func(id string) GenericCard {
			return GenericCard{UUID: id, ImageURL: "same.jpg"}
		},
	)
	if ok {
		t.Fatalf("firstUnusedPopularCard returned %q for used art", card.UUID)
	}
}
