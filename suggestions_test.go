package main

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/suggest"
)

// These tests rely on the datastore loaded in TestMain, which is why they
// live here rather than in internal/suggest.

func TestClosestCardName(t *testing.T) {
	skipWithoutDatastore(t)
	got := suggest.Closest(backend(), "lightnig bolt", false)
	if got != "Lightning Bolt" {
		t.Errorf("typo: Closest = %q, want Lightning Bolt", got)
	}
	got = suggest.Closest(backend(), "Lightning Bolt", false)
	if got != "" {
		t.Errorf("valid name should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "zzqwxvkjmpft", false)
	if got != "" {
		t.Errorf("gibberish should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "ab", false)
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

// The did-you-mean keeps the filters typed, and reads one whose key does
// not take its value under the key that does.
func TestDidYouMeanKeepsFilters(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	tests := []struct{ query, want string }{
		{"control mage s:4ed", "Control Magic s:4ed"},
		{"mountain is:plst", "mountain s:plst"},
		{"mountian -is:plst f:foil", "Mountain -s:plst f:foil"},
		{"mountain not:plst", "mountain -s:plst"},
		{"mountain -not:plst", "mountain s:plst"},
		{"mountain is:plst,lea", "mountain s:plst,lea"},
		{"mountain is:plst,foil", ""},
		{"is:plst", "s:plst"},
		{"sol ring store:plst", "sol ring s:plst"},
		{"lightning bolt f:mythic", "lightning bolt r:mythic"},
		{"lightning bolt r:foil", "lightning bolt f:foil"},
		{"lightning bolt is:modern", "lightning bolt legal:modern"},
		{"lightning bolt c:instant", "lightning bolt t:instant"},
		{"goblin guide is:red", "goblin guide c:red"},
		{"lightning bolt s:lea", ""},
		{"lightning bolt s:lea f:foil", ""},
		{"lightning bolt is:xyz", ""},
	}
	for _, tt := range tests {
		config := parseSearchOptionsNG(ds.backend, tt.query, nil, nil, nil)
		got, _ := searchSuggestions(ds, tt.query, config, nil, false)
		if got != tt.want {
			t.Errorf("%q: did-you-mean %q, want %q", tt.query, got, tt.want)
		}
	}
}

// The rekey keeps to the pinned bar, and leaves a query of more filters,
// or a filter of more values, than it walks alone.
func TestDidYouMeanRekeyBounds(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	query := "mountain is:plst"
	config := parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
	pinned := parseSearchOptionsNG(ds.backend, "s:lea", nil, nil, nil).CardFilters
	if got, _ := searchSuggestions(ds, query, config, pinned, false); got != "" {
		t.Errorf("%q pinned to s:lea: did-you-mean %q, want none", query, got)
	}

	query = "mountain is:plst t:land t:basic t:mountain"
	config = parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, query, config, nil, false); got != "" {
		t.Errorf("%q: did-you-mean %q, want none past %d filters", query, got, maxRekeyFilters)
	}

	query = "mountain is:plst,lea,leb,2ed"
	config = parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, query, config, nil, false); got != "" {
		t.Errorf("%q: did-you-mean %q, want none past %d values", query, got, maxRekeyValues)
	}
}
