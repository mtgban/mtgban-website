package main

import "testing"

func TestAllEditionsByCategoryCoversAllEditions(t *testing.T) {
	if len(AllEditionsKeys) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	categorized := 0
	for _, entries := range AllEditionsByCategory {
		categorized += len(entries)
	}
	if categorized != len(AllEditionsKeys) {
		t.Fatalf("AllEditionsByCategory covers %d sets but AllEditionsKeys has %d",
			categorized, len(AllEditionsKeys))
	}
}

func TestAllEditionsByCategoryHasKnownCategories(t *testing.T) {
	if len(AllEditionsByCategory) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	wanted := []string{"Expansions", "Commander Decks", "Core Sets"}
	for _, w := range wanted {
		if _, ok := AllEditionsByCategory[w]; !ok {
			t.Errorf("expected category %q in AllEditionsByCategory", w)
		}
	}
}
