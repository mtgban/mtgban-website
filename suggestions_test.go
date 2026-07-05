package main

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/suggest"
)

// These tests rely on the datastore loaded in TestMain, which is why they
// live here rather than in internal/suggest.

func TestClosestCardName(t *testing.T) {
	if got := suggest.Closest("lightnig bolt", false); got != "Lightning Bolt" {
		t.Errorf("typo: Closest = %q, want Lightning Bolt", got)
	}
	if got := suggest.Closest("Lightning Bolt", false); got != "" {
		t.Errorf("valid name should not suggest, got %q", got)
	}
	if got := suggest.Closest("zzqwxvkjmpft", false); got != "" {
		t.Errorf("gibberish should not suggest, got %q", got)
	}
	if got := suggest.Closest("ab", false); got != "" {
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
