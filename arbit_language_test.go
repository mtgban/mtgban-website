package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
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

// TestSleepersLanguagesCoverFlavourPrintings is the cost of listing languages
// by hand: one the datastore gains later would be dropped silently, being
// neither English nor on the list. This is where that shows up.
func TestSleepersLanguagesCoverFlavourPrintings(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}

	missing := map[string]int{}
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
		if err != nil || co.Language == "" {
			continue
		}
		// A flagged language is meant to be dropped, not covered.
		if allLanguageFlags[co.Language] != "" {
			continue
		}
		if !slices.Contains(sleepersLanguages, co.Language) {
			missing[co.Language]++
		}
	}
	if len(missing) > 0 {
		t.Errorf("flavour languages the tiers would now drop: %v\n"+
			"add them to sleepersLanguages, or decide they should go", missing)
	}
}

// TestSleepersDropForeignPrintings exercises the two modes that go through
// ArbitOpts, which is what issue #319 asks for.
func TestSleepersDropForeignPrintings(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}
	// Without scrapers there is nothing to compare and both come back empty,
	// which is not the same as passing.
	results := map[string]map[string]int{
		"mismatch": getTiers(nil, nil, nil),
		"gap":      getGap(nil, "TCGLow", "CK", nil),
	}
	if len(results["mismatch"]) == 0 && len(results["gap"]) == 0 {
		t.Skip("no scrapers loaded, nothing to filter")
	}
	for name, tiers := range results {
		for cardId := range tiers {
			co, err := mtgmatcher.GetUUID(cardId)
			if err != nil {
				continue
			}
			if !slices.Contains(sleepersLanguages, co.Language) {
				t.Errorf("%s returned %s in %s", name, co.Name, co.Language)
			}
		}
	}
}
