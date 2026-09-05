package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// sealedSearch runs a query the way the sealed tab does, fallback and all.
func sealedSearch(t *testing.T, query string) []string {
	t.Helper()
	config := parseSearchOptionsNG(query, nil, nil, nil)
	config.SearchMode = "sealed"

	keys, err := searchAndFilter(config)
	if err != nil {
		keys = searchFallback(config)
	}
	return keys
}

// The sealed tab answers with products or with nothing. A card matched by name
// is no answer to "which product is this": the search used to fall through to
// the card matcher when no product carried the name, so /sealed?q=the+last+ronin
// showed the Magic card called The Last Ronin.
func TestSealedTabNeverAnswersWithACard(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	// A card whose name no product carries, so the search has to fall back.
	var orphan string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		if _, err := mtgmatcher.SearchSealedContains(co.Name); err == nil {
			continue
		}
		if _, err := searchSealedFragment(co.Name); err == nil {
			continue
		}
		orphan = co.Name
		break
	}
	if orphan == "" {
		t.Skip("every card name is carried by some product here")
	}

	for _, key := range sealedSearch(t, orphan) {
		co, err := mtgmatcher.GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if !co.Sealed {
			t.Errorf("the sealed tab answered %q with the card %q", orphan, co.Name)
		}
	}
}

// And it does find the product, article and all. A name is normalized whole,
// where an interior " the " is dropped; a query is normalized alone, where a
// leading one is not. "the last ronin" is not a substring of what the Secret
// Lair is stored as, though the name plainly holds the words.
func TestSealedTabFindsAProductPastAnInteriorArticle(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	// Any product whose name carries an interior "The", asked for from that
	// word on, so the query leads with the article the name buried.
	var product, query string
	for _, uuid := range mtgmatcher.GetSealedUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		at := strings.Index(co.Name, " The ")
		if at < 0 {
			continue
		}
		candidate := co.Name[at+1:]
		// The asymmetry itself: what the query spells is not what the name
		// stored, so the plain substring search cannot find it.
		if _, err := mtgmatcher.SearchSealedContains(candidate); err == nil {
			continue
		}
		product, query = co.Name, candidate
		break
	}
	if product == "" {
		t.Skip("no product here is named around an interior article")
	}

	keys := sealedSearch(t, query)
	if len(keys) == 0 {
		t.Fatalf("the sealed tab found nothing for %q, which %q holds", query, product)
	}

	var found bool
	for _, key := range keys {
		co, err := mtgmatcher.GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if !co.Sealed {
			t.Errorf("answered with the card %q", co.Name)
		}
		if co.Name == product {
			found = true
		}
	}
	if !found {
		t.Errorf("%q is not among the %d products found for %q", product, len(keys), query)
	}
}
