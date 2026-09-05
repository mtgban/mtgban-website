package main

import (
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
