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

// The did-you-mean keeps the filters typed, and reads an is: naming a set
// code as the s: it was meant to be.
func TestDidYouMeanKeepsFilters(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()

	tests := []struct{ query, want string }{
		{"control mage s:4ed", "Control Magic s:4ed"},
		{"mountain is:plst", "mountain s:plst"},
		{"mountian -is:plst f:foil", "Mountain -s:plst f:foil"},
		{"mountain not:plst", "mountain -s:plst"},
		{"mountain -not:plst", "mountain s:plst"},
		{"mountain is:plst,lea", "mountain s:plst,lea"},
		{"mountain is:plst,foil", ""},
		{"is:plst", "s:plst"},
		{"lightning bolt s:lea", ""},
		{"lightning bolt is:foil", ""},
	}
	for _, tt := range tests {
		config := parseSearchOptionsNG(b, tt.query, nil, nil, nil)
		got, _ := searchSuggestions(b, tt.query, config, false)
		if got != tt.want {
			t.Errorf("%q: did-you-mean %q, want %q", tt.query, got, tt.want)
		}
	}
}
