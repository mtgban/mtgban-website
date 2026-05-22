package main

import "testing"

func TestAllEditionsByCategoryCoversAllEditions(t *testing.T) {
	editions := GetEditions()
	if len(editions.AllEditionsKeys) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	categorized := 0
	for _, entries := range editions.AllEditionsByCategory {
		categorized += len(entries)
	}
	if categorized != len(editions.AllEditionsKeys) {
		t.Fatalf("AllEditionsByCategory covers %d sets but AllEditionsKeys has %d",
			categorized, len(editions.AllEditionsKeys))
	}
}

func TestAllEditionsByCategoryHasKnownCategories(t *testing.T) {
	editions := GetEditions()
	if len(editions.AllEditionsByCategory) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	wanted := []string{"Expansions", "Commander Decks", "Core Sets"}
	for _, w := range wanted {
		if _, ok := editions.AllEditionsByCategory[w]; !ok {
			t.Errorf("expected category %q in AllEditionsByCategory", w)
		}
	}
}
