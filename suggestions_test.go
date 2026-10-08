package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/suggest"
)

// These tests rely on the datastore loaded in TestMain, which is why they
// live here rather than in internal/suggest.

func TestClosestCardName(t *testing.T) {
	skipWithoutDatastore(t)
	got := suggest.Closest(backend(), "lightnig bolt", suggest.PoolSingles)
	if got != "Lightning Bolt" {
		t.Errorf("typo: Closest = %q, want Lightning Bolt", got)
	}
	got = suggest.Closest(backend(), "Lightning Bolt", suggest.PoolSingles)
	if got != "" {
		t.Errorf("valid name should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "zzqwxvkjmpft", suggest.PoolSingles)
	if got != "" {
		t.Errorf("gibberish should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "ab", suggest.PoolSingles)
	if got != "" {
		t.Errorf("short query should not suggest, got %q", got)
	}
}

func TestAppliedFiltersCapture(t *testing.T) {
	config := parseSearchOptionsWrapper("lightning bolt s:lea f:foil")
	if config.CleanQuery != "lightning bolt" {
		t.Errorf("CleanQuery = %q, want 'lightning bolt'", config.CleanQuery)
	}
	for _, want := range []string{"s:lea", "f:foil"} {
		if !slices.Contains(config.AppliedFilters, want) {
			t.Errorf("AppliedFilters %v missing %q", config.AppliedFilters, want)
		}
	}
}

// Over both pools the closest name may be a product; over cards alone a
// product's name is out of reach.
func TestClosestOverBothPoolsReachesAProduct(t *testing.T) {
	skipWithoutDatastore(t)

	var product string
	for _, uuid := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err == nil && len(co.Name) > 12 {
			product = co.Name
			break
		}
	}
	if product == "" {
		t.Skip("no sealed product loaded")
	}
	// One letter dropped from the middle, the way a typo reads.
	typo := product[:5] + product[6:]

	if got := suggest.Closest(backend(), typo, suggest.PoolBoth); got != product {
		t.Errorf("PoolBoth: Closest(%q) = %q, want %q", typo, got, product)
	}
	if got := suggest.Closest(backend(), typo, suggest.PoolSealed); got != product {
		t.Errorf("PoolSealed: Closest(%q) = %q, want %q", typo, got, product)
	}
	if got := suggest.Closest(backend(), typo, suggest.PoolSingles); got == product {
		t.Errorf("PoolSingles reached the product %q", product)
	}
}

// A free-text query on the page that found nothing gets the set-plus-type
// rewrite, since the page searches products too.
func TestSearchSuggestionsOfferTheSealedRewriteOnThePage(t *testing.T) {
	skipWithoutDatastore(t)

	config := parseSearchOptionsNG(backend(), "lost caverns booster", nil, nil, nil)
	config.IncludeSealed = true
	_, alts := searchSuggestions(backend(), "lost caverns booster", config)
	found := false
	for _, alt := range alts {
		if strings.HasPrefix(alt.Query, "s:") && strings.Contains(alt.Query, " t:") {
			found = true
		}
	}
	if !found {
		t.Errorf("no set-plus-type rewrite among %v", alts)
	}

	config.IncludeSealed = false
	_, alts = searchSuggestions(backend(), "lost caverns booster", config)
	for _, alt := range alts {
		if strings.HasPrefix(alt.Query, "s:") && strings.Contains(alt.Query, " t:") {
			t.Errorf("a cards-only search offered the sealed rewrite %q", alt.Query)
		}
	}
}
