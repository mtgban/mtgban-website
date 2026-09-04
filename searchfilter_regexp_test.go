package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestRegexpFilterCompiledWithQuery pins the pattern to the filter it was
// parsed into. The pattern used to be compiled inside the comparison, so a
// query naming one paid a compile for every card it was compared against -
// once per query now, and 155,651 times before on Magic.
func TestRegexpFilterCompiledWithQuery(t *testing.T) {
	for _, tt := range []struct {
		query, filter string
		wantCompiled  bool
		wantMatch     bool
	}{
		{"cne:^6.5$", "number_regexp", true, true},
		{"cne:^7.5$", "number_regexp", true, false},
		{"namee:^Toxin", "name_regexp", true, true},
		{"ee:^Secret", "edition_regexp", true, true},
		{
			// A pattern that cannot compile matches nothing, which is what
			// the discarded error said when the compile lived in the
			// comparison.
			query: "cne:[", filter: "number_regexp",
			wantCompiled: false, wantMatch: false,
		},
	} {
		t.Run(tt.query, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = "635"
			co.Name = "Toxin Sliver"
			co.Edition = "Secret Lair Drop"

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
			if compiled := elem.Regexp != nil; compiled != tt.wantCompiled {
				t.Errorf("compiled = %v, want %v", compiled, tt.wantCompiled)
			}
			if match := !cardFilterRegexp(elem.Name, elem.Regexp, co); match != tt.wantMatch {
				t.Errorf("matched = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}
