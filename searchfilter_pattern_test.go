package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestPatternKeepsItsBrackets pins the brackets to the pattern. They used to
// be trimmed off the sides of a name pattern along with the quotes, which
// reads a pair as a wrapper: a matched pair is no wrapper, since "(635)"
// already matches what "635" matches, and half a pair is a pattern that
// cannot compile and so answers for no card at all.
func TestPatternKeepsItsBrackets(t *testing.T) {
	for _, tt := range []struct {
		query, filter, want string
	}{
		{`namee:"^Toxin"`, "name_regexp", "^Toxin"},
		{`namee:^Toxin`, "name_regexp", "^Toxin"},
		{`namee:(Toxin)(Sliver)`, "name_regexp", "(Toxin)(Sliver)"},
		{`namee:(Toxin|Plague)`, "name_regexp", "(Toxin|Plague)"},
		{`cne:(6|7)5`, "number_regexp", "(6|7)5"},
		{`cne:"635"`, "number_regexp", "635"},
		{`cne:(00)?635`, "number_regexp", "(00)?635"},
		{`ee:"^Secret"`, "edition_regexp", "^Secret"},
		{`ee:(Secret|Special)`, "edition_regexp", "(Secret|Special)"},
	} {
		t.Run(tt.query, func(t *testing.T) {
			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			var elem *FilterElem
			for i := range config.CardFilters {
				if config.CardFilters[i].Name == tt.filter {
					elem = &config.CardFilters[i]
				}
			}
			if elem == nil {
				t.Fatalf("missing %s filter", tt.filter)
			}
			if elem.Values[0] != tt.want {
				t.Errorf("pattern = %q, want %q", elem.Values[0], tt.want)
			}
			if elem.Regexp == nil {
				t.Errorf("pattern %q did not compile", elem.Values[0])
			}
		})
	}
}

// TestPatternWithBracketsMatches walks the whole way through, so the pattern
// is graded on the card it reaches rather than on how it is spelled.
func TestPatternWithBracketsMatches(t *testing.T) {
	co := &mtgmatcher.CardObject{}
	co.Number = "635"
	co.Name = "Toxin Sliver"
	co.Edition = "Secret Lair Drop"

	for _, tt := range []struct {
		query, filter string
		wantMatch     bool
	}{
		// "(6|7)5" is six-or-seven then five, so it reaches 65 and 75 and
		// not 635 - the point being that it compiles and answers at all,
		// where trimming its brackets left it answering for nothing.
		{`cne:(6|7)35`, "number_regexp", true},
		{`cne:(8|9)35`, "number_regexp", false},
		{`cne:(00)?635`, "number_regexp", true},
		{`namee:^(Toxin)`, "name_regexp", true},
		{`namee:"^Toxin"`, "name_regexp", true},
		{`ee:(Secret|Special)`, "edition_regexp", true},
	} {
		t.Run(tt.query, func(t *testing.T) {
			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			var elem *FilterElem
			for i := range config.CardFilters {
				if config.CardFilters[i].Name == tt.filter {
					elem = &config.CardFilters[i]
				}
			}
			if elem == nil {
				t.Fatalf("missing %s filter", tt.filter)
			}
			if match := !cardFilterRegexp(elem.Name, elem.Regexp, co); match != tt.wantMatch {
				t.Errorf("%s matched=%v, want %v", tt.query, match, tt.wantMatch)
			}
		})
	}
}
