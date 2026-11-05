package main

import (
	"slices"
	"testing"
)

// TestSleepersLanguagesAreEnglishMarket checks the list says what it means:
// English itself, and nothing that carries a flag elsewhere on the site.
func TestSleepersLanguagesAreEnglishMarket(t *testing.T) {
	if !slices.Contains(sleepersLanguages, "English") {
		t.Error("English is not on the list, so the tiers would come back empty")
	}
	for _, lang := range sleepersLanguages {
		if allLanguageFlags[lang] != "" {
			t.Errorf("%s carries a flag, so it is a foreign printing", lang)
		}
	}
}

// TestSleepersLanguagesFollowDatastore is the cost of listing languages by
// hand: it logs a language the datastore has that the list lacks, which the
// tiers leave out, and one the list names that no printing has. Neither
// fails: both follow the data, and a language can be listed before the
// datastore names it.
func TestSleepersLanguagesFollowDatastore(t *testing.T) {
	t.Parallel()
	skipWithoutDatastore(t)
	b := backend()

	seen := map[string]int{}
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed || co.Language == "" || slices.Contains(playtestEditions, co.SetCode) {
			continue
		}
		seen[co.Language]++
	}
	for lang, printings := range seen {
		// A flagged language is meant to be dropped, not listed
		if allLanguageFlags[lang] == "" && !slices.Contains(sleepersLanguages, lang) {
			t.Logf("%s (%d printings) is left out of the tiers: list it in sleepersLanguages or leave it out", lang, printings)
		}
	}
	for _, lang := range sleepersLanguages {
		if seen[lang] == 0 {
			t.Logf("sleepersLanguages lists %s, which no printing has", lang)
		}
	}
}

// TestSleepersDropForeignPrintings exercises the two modes that go through
// ArbitOpts, which is what issue #319 asks for.
func TestSleepersDropForeignPrintings(t *testing.T) {
	skipWithoutDatastore(t)
	// Without scrapers there is nothing to compare and both come back empty,
	// which is not the same as passing.
	results := map[string]map[string]int{
		"mismatch": getTiers(backend(), currentPrices(), nil, nil, nil),
		"gap":      getGap(backend(), currentPrices(), nil, "TCGLow", "CK", nil),
	}
	if len(results["mismatch"]) == 0 && len(results["gap"]) == 0 {
		t.Skip("no scrapers loaded, nothing to filter")
	}
	for name, tiers := range results {
		for cardID := range tiers {
			co, err := backend().GetUUID(cardID)
			if err != nil {
				continue
			}
			if !slices.Contains(sleepersLanguages, co.Language) {
				t.Errorf("%s returned %s in %s", name, co.Name, co.Language)
			}
		}
	}
}
