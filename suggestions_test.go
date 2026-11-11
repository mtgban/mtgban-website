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
	got := suggest.Closest(backend(), "lightnig bolt", false)
	if len(got) == 0 || got[0] != "Lightning Bolt" {
		t.Errorf("typo: Closest = %q, want Lightning Bolt first", got)
	}
	got = suggest.Closest(backend(), "swapm", false)
	if len(got) < 2 || got[0] != "Swamp" || !slices.Contains(got, "Snap") {
		t.Errorf("swapped letters: Closest = %q, want Swamp first and Snap among the rest", got)
	}
	got = suggest.Closest(backend(), "Lightning Bolt", false)
	if got != nil {
		t.Errorf("valid name should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "zzqwxvkjmpft", false)
	if got != nil {
		t.Errorf("gibberish should not suggest, got %q", got)
	}
	got = suggest.Closest(backend(), "ab", false)
	if got != nil {
		t.Errorf("short query should not suggest, got %q", got)
	}
}

// nearest is the first did-you-mean, the one built on the nearest name,
// or "" where there is none; the tables below check the filters it keeps.
func nearest(queries []string) string {
	if len(queries) == 0 {
		return ""
	}
	return queries[0]
}

// A did-you-mean per close name, nearest first, each keeping the filters
// typed; a filter rekeys against its own name, and the name it rekeyed
// for leads (Krosa is in ONS, Karma is not).
func TestDidYouMeanRunnersUp(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	query := "swapm is:wcd"
	config := parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false)
	if len(got) < 2 || got[0] != "Swamp is:wcd" || !slices.Contains(got, "Snap is:wcd") {
		t.Errorf("%q: did-you-mean %q, want Swamp is:wcd first and Snap is:wcd among the rest", query, got)
	}
	for _, q := range got {
		if !strings.HasSuffix(q, " is:wcd") {
			t.Errorf("%q: did-you-mean %q dropped the filter", query, q)
		}
	}

	query = "akroma is:ons t:creature"
	config = parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	got, _ = searchSuggestions(ds, currentPrices(), query, config, nil, nil, false)
	if !slices.Equal(got, []string{"Krosa s:ons t:creature", "Karma is:ons t:creature"}) {
		t.Errorf("%q: did-you-mean %q, want Krosa rekeyed then Karma as typed", query, got)
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
		{"serra is:lea t:creature", "serra s:lea t:creature"},
		{"serra is:leb r:uncommon", "serra s:leb r:uncommon"},
		{"serra r:uncommon is:leb", "serra r:uncommon s:leb"},
	}
	for _, tt := range tests {
		config := parseSearchOptionsNG(ds.backend, currentPrices(), tt.query, nil, nil, nil)
		got, _ := searchSuggestions(ds, currentPrices(), tt.query, config, nil, nil, false)
		if nearest(got) != tt.want {
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
		config := parseSearchPage(ds, currentPrices(), tt.query, false, false, nil, nil, nil)
		got, _ := searchSuggestions(ds, currentPrices(), tt.query, config, nil, nil, false)
		if nearest(got) != tt.want {
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
	config := parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	pinned := parseSearchOptionsNG(ds.backend, currentPrices(), "s:lea", nil, nil, nil).CardFilters
	if got, _ := searchSuggestions(ds, currentPrices(), query, config, pinned, nil, false); len(got) != 0 {
		t.Errorf("%q pinned to s:lea: did-you-mean %q, want none", query, got)
	}

	query = "mountain is:plst t:land t:basic t:mountain"
	config = parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false); len(got) != 0 {
		t.Errorf("%q: did-you-mean %q, want none past %d filters", query, got, maxRekeyFilters)
	}

	query = "mountain is:plst,lea,leb,2ed"
	config = parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false); len(got) != 0 {
		t.Errorf("%q: did-you-mean %q, want none past %d values", query, got, maxRekeyValues)
	}
}

// A store filter naming a store stays one, though a set shares its code.
func TestDidYouMeanKeepsAStore(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	query := "murder store:mkm"
	config := parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
	if got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false); nearest(got) != "murder s:mkm" {
		t.Fatalf("%q with no such store: did-you-mean %q, want murder s:mkm", query, got)
	}
	registerTestSeller(t, testSite, "MKM", somePlainCardUUIDs(t, 1))
	for _, query := range []string{query, "murder store:empty:mkm"} {
		config := parseSearchOptionsNG(ds.backend, currentPrices(), query, nil, nil, nil)
		if got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false); len(got) != 0 {
			t.Errorf("%q with an MKM store: did-you-mean %q, want none", query, got)
		}
	}
}

// A set filter naming no set is read as the nearest set the query's name
// is printed in, by code or by name.
func TestDidYouMeanNearestSet(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	tests := []struct{ query, want string }{
		{"urza's mine s:atw", "urza's mine s:atq"},
		{"urza's mine e:atw f:nonfoil", "urza's mine e:atq f:nonfoil"},
		{`urza's mine s:"antiquites"`, "urza's mine s:atq"},
		{"urza's mine s:atw,5ef", "urza's mine s:atq,5ed"},
		{"urza's mine s:atw,zzq", ""},
		{"urza's mine s:zzq", ""},
		{"urza's mine s:m10", ""},
		{"lightning bolt s:atw", "lightning bolt s:ath"},
		{"black lotus s:atw", ""},
	}
	for _, tt := range tests {
		config := parseSearchPage(ds, currentPrices(), tt.query, false, false, nil, nil, nil)
		got, _ := searchSuggestions(ds, currentPrices(), tt.query, config, nil, nil, false)
		if nearest(got) != tt.want {
			t.Errorf("%q: did-you-mean %q, want %q", tt.query, got, tt.want)
		}
	}

	query := "s:atw"
	config := parseSearchPage(ds, currentPrices(), query, false, false, nil, nil, nil)
	got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, false)
	if !slices.Contains(got, "s:atq") || !slices.Contains(got, "s:ath") {
		t.Errorf("%q: did-you-mean %q, want s:atq and s:ath among them", query, got)
	}
}

// A sealed search offers only sets with sealed product: OTJ has some, OTP
// none, and both sit one edit from the typo.
func TestDidYouMeanNearestSetSealed(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	query := "s:otx"
	config := parseSearchPage(ds, currentPrices(), query, true, false, nil, nil, nil)
	got, _ := searchSuggestions(ds, currentPrices(), query, config, nil, nil, true)
	if !slices.Contains(got, "s:otj") || slices.Contains(got, "s:otp") {
		t.Errorf("sealed %q: did-you-mean %q, want s:otj and no s:otp", query, got)
	}
	config = parseSearchPage(ds, currentPrices(), query, false, false, nil, nil, nil)
	got, _ = searchSuggestions(ds, currentPrices(), query, config, nil, nil, false)
	if !slices.Contains(got, "s:otp") {
		t.Errorf("%q: did-you-mean %q, want s:otp among them", query, got)
	}
}

// An is: naming no promo type is read as the nearest one, or its short
// form, among those the printings of the query's name carry.
func TestDidYouMeanNearestPromoType(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()

	tests := []struct{ query, want string }{
		{"Battlefield Forge is:riple", "Battlefield Forge is:ripple"},
		{"Battlefield Forge is:riplefoil", "Battlefield Forge is:ripplefoil"},
		{"Battlefield Forge is:riple,zzqx", "Battlefield Forge is:ripple,zzqx"},
		{"Battlefield Forge is:reserved is:riple", "Battlefield Forge is:reserved is:ripple"},
		{"Battlefield Forge s:atw is:riple", ""},
		{"black lotus is:riple", ""},
		{"black lotus is:surge", ""},
		{"Battlefield Forge is:riple f:foil", "Battlefield Forge is:ripple f:foil"},
		{"Battlefield Forge is:riple,surge", "Battlefield Forge is:ripple,surge"},
		{"is:riple", "is:ripple"},
		{"lightning bolt is:xyz", ""},
	}
	for _, tt := range tests {
		config := parseSearchPage(ds, currentPrices(), tt.query, false, false, nil, nil, nil)
		got, _ := searchSuggestions(ds, currentPrices(), tt.query, config, nil, nil, false)
		if nearest(got) != tt.want {
			t.Errorf("%q: did-you-mean %q, want %q", tt.query, got, tt.want)
		}
	}
}
