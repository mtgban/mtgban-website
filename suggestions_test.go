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
		{"counterspell c:r", ""},
		{"goblin guide c:u", ""},
		{"llanowar elves -c:g", ""},
		{"lightning bolt year>2030", ""},
		{"lightning bolt price>200", ""},
		{"black lotus store:ck", ""},
		{"lightning bolt region:jp", ""},
		{"lightnin bolt region:jp", "Lightning Bolt region:jp"},
		{"lightning bolt is:m10 f:foil", "lightning bolt s:m10 f:foil"},
		{"goblin guide is:zen t:creature", "goblin guide s:zen t:creature"},
	}
	for _, tt := range tests {
		config := parseSearchOptionsNG(ds.backend, tt.query, nil, nil, nil)
		got, _ := searchSuggestions(ds, tt.query, config, nil, false)
		if got != tt.want {
			t.Errorf("%q: did-you-mean %q, want %q", tt.query, got, tt.want)
		}
	}
}

// The did-you-mean keeps a collector number the parser read off the
// words, after a name, alone or after a set code.
func TestDidYouMeanKeepsANumber(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	tests := []struct{ query, want string }{
		{"lightning bolt 146 is:m10", "lightning bolt cn:146 s:m10"},
		{"lightning bolt 141 is:m10", ""},
		{"146 is:m10", "cn:146 s:m10"},
		{"m10 146 r:foil", "s:M10 cn:146 f:foil"},
	}
	for _, tt := range tests {
		config := parseSearchPage(ds, tt.query, false, nil, nil, nil)
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

// A store filter naming a store stays one, though a set shares its code.
func TestDidYouMeanKeepsAStore(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	query := "murder store:mkm"
	config := parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, query, config, nil, false); got != "murder s:mkm" {
		t.Fatalf("%q with no such store: did-you-mean %q, want murder s:mkm", query, got)
	}
	registerTestSeller(t, "MKM", somePlainCardUUIDs(t, 1))
	for _, query := range []string{query, "murder store:empty:mkm"} {
		config := parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
		if got, _ := searchSuggestions(ds, query, config, nil, false); got != "" {
			t.Errorf("%q with an MKM store: did-you-mean %q, want none", query, got)
		}
	}
}
