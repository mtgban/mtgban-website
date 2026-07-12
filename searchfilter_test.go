package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestFormatFilter(t *testing.T) {
	skip := func(filters []string, co *mtgmatcher.CardObject) bool {
		return applyCardFilter("format", filters, co)
	}

	co := &mtgmatcher.CardObject{}
	co.Legalities = map[string]string{
		"standard": "Legal",
		"vintage":  "Restricted",
		"modern":   "Banned",
	}

	tests := []struct {
		name     string
		formats  []string
		wantSkip bool
	}{
		{"legal is kept", []string{"standard"}, false},
		{"restricted is kept", []string{"vintage"}, false},
		{"banned is skipped", []string{"modern"}, true},
		{"absent format is skipped", []string{"legacy"}, true},
		{"any legal format keeps the card", []string{"modern", "standard"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skip(tt.formats, co); got != tt.wantSkip {
				t.Errorf("skip = %v, want %v", got, tt.wantSkip)
			}
		})
	}
}

func TestFixupFormatNG(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"Standard", []string{"standard"}},
		{"edh", []string{"commander"}},
		{"pdh", []string{"paupercommander"}},
		{"modern, legacy", []string{"modern", "legacy"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := fixupFormatNG(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("fixupFormatNG(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Errorf("fixupFormatNG(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func TestCollectorNumberRange(t *testing.T) {
	findFilter := func(config SearchConfig, name string) *FilterElem {
		for i := range config.CardFilters {
			if config.CardFilters[i].Name == name {
				return &config.CardFilters[i]
			}
		}
		return nil
	}

	t.Run("ascending numbers parse as a range", func(t *testing.T) {
		config := parseSearchOptionsNG("cn:7000-7010", nil, nil, nil)
		elem := findFilter(config, "number_less_than")
		if elem == nil {
			t.Fatal("missing number_less_than filter")
		}
		if len(elem.Values) != 1 || elem.Values[0] != "7010" {
			t.Errorf("upper bound = %v, want [7010]", elem.Values)
		}
		if len(elem.Subfilters) != 1 || elem.Subfilters[0].Name != "number_greater_than" {
			t.Fatalf("subfilters = %+v, want a single number_greater_than", elem.Subfilters)
		}
		if len(elem.Subfilters[0].Values) != 1 || elem.Subfilters[0].Values[0] != "7000" {
			t.Errorf("lower bound = %v, want [7000]", elem.Subfilters[0].Values)
		}
	})

	t.Run("year-prefixed number stays literal", func(t *testing.T) {
		config := parseSearchOptionsNG("cn:2002-1", nil, nil, nil)
		elem := findFilter(config, "number")
		if elem == nil {
			t.Fatal("missing number filter")
		}
		if len(elem.Values) != 1 || elem.Values[0] != "2002-1" {
			t.Errorf("values = %v, want [2002-1]", elem.Values)
		}
		if findFilter(config, "number_less_than") != nil {
			t.Error("unexpected range filter for a year-prefixed number")
		}
	})

	t.Run("lettered number stays literal", func(t *testing.T) {
		config := parseSearchOptionsNG("cn:akh-127", nil, nil, nil)
		elem := findFilter(config, "number")
		if elem == nil {
			t.Fatal("missing number filter")
		}
		if len(elem.Values) != 1 || elem.Values[0] != "akh-127" {
			t.Errorf("values = %v, want [akh-127]", elem.Values)
		}
	})
}

func TestCollectorNumberPLST(t *testing.T) {
	// The List mirrors the original printing's set code in its collector
	// numbers (eg "AKH-127") - the dashed shape the range parser must not
	// split, and that range comparisons reduce to the embedded value.
	co := &mtgmatcher.CardObject{}
	co.Number = "AKH-127"

	config := parseSearchOptionsNG("cn:akh-127", nil, nil, nil)
	var elem *FilterElem
	for i := range config.CardFilters {
		if config.CardFilters[i].Name == "number" {
			elem = &config.CardFilters[i]
		}
	}
	if elem == nil {
		t.Fatal("missing number filter")
	}
	if skip := applyCardFilter("number", elem.Values, co); skip {
		t.Error("cn:akh-127 should match a card numbered AKH-127")
	}
	if skip := applyCardFilter("number", fixupNumberNG("akh-50"), co); !skip {
		t.Error("cn:akh-50 should not match a card numbered AKH-127")
	}

	// Ranges compare the number embedded after the prefix (127), so the
	// card falls outside 7000-7010 but within 100-200.
	if skip := applyCardFilter("number_greater_than", []string{"7000"}, co); !skip {
		t.Error("AKH-127 should be excluded by cn>7000")
	}
	if skip := applyCardFilter("number_greater_than", []string{"100"}, co); skip {
		t.Error("AKH-127 should be kept by cn>100")
	}
	if skip := applyCardFilter("number_less_than", []string{"200"}, co); skip {
		t.Error("AKH-127 should be kept by cn<200")
	}
}
