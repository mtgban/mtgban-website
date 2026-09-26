package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestFormatFilter(t *testing.T) {
	skip := func(filters []string, co *mtgmatcher.CardObject) bool {
		return applyCardFilter(backend(), "format", filters, co)
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
		config := parseSearchOptionsNG(backend(), "cn:7000-7010", nil, nil, nil)
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
		config := parseSearchOptionsNG(backend(), "cn:2002-1", nil, nil, nil)
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
		config := parseSearchOptionsNG(backend(), "cn:akh-127", nil, nil, nil)
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
	co.PlainNumber = "AKH-127"

	config := parseSearchOptionsNG(backend(), "cn:akh-127", nil, nil, nil)
	var elem *FilterElem
	for i := range config.CardFilters {
		if config.CardFilters[i].Name == "number" {
			elem = &config.CardFilters[i]
		}
	}
	if elem == nil {
		t.Fatal("missing number filter")
	}
	if skip := applyCardFilter(backend(), "number", elem.Values, co); skip {
		t.Error("cn:akh-127 should match a card numbered AKH-127")
	}
	if skip := applyCardFilter(backend(), "number", fixupNumberNG(backend(), "akh-50", false), co); !skip {
		t.Error("cn:akh-50 should not match a card numbered AKH-127")
	}

	// Ranges compare the number embedded after the prefix (127), so the
	// card falls outside 7000-7010 but within 100-200.
	if skip := applyCardFilter(backend(), "number_greater_than", []string{"7000"}, co); !skip {
		t.Error("AKH-127 should be excluded by cn>7000")
	}
	if skip := applyCardFilter(backend(), "number_greater_than", []string{"100"}, co); skip {
		t.Error("AKH-127 should be kept by cn>100")
	}
	if skip := applyCardFilter(backend(), "number_less_than", []string{"200"}, co); skip {
		t.Error("AKH-127 should be kept by cn<200")
	}
}

func TestSetNumberShorthand(t *testing.T) {
	if _, err := backend().GetSet("PLST"); err != nil {
		t.Skip("datastore not loaded")
	}

	findFilter := func(config SearchConfig, name string) *FilterElem {
		for i := range config.CardFilters {
			if config.CardFilters[i].Name == name {
				return &config.CardFilters[i]
			}
		}
		return nil
	}

	checkValues := func(t *testing.T, elem *FilterElem, filterName, want string) {
		t.Helper()
		if elem == nil {
			t.Fatalf("missing %s filter", filterName)
		}
		if len(elem.Values) != 1 || elem.Values[0] != want {
			t.Errorf("%s = %v, want [%s]", filterName, elem.Values, want)
		}
	}

	checkNameSearch := func(t *testing.T, query string) {
		t.Helper()
		config := parseSearchOptionsNG(backend(), query, nil, nil, nil)
		if findFilter(config, "edition") != nil {
			t.Error("unexpected edition filter")
		}
		if config.CleanQuery != query {
			t.Errorf("CleanQuery = %q, want %q", config.CleanQuery, query)
		}
	}

	t.Run("set code and number rewrite to filters", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo 234", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "NEO")
		checkValues(t, findFilter(config, "number"), "number", "234")
		if config.CleanQuery != "" {
			t.Errorf("CleanQuery = %q, want empty", config.CleanQuery)
		}
		// Synthesized filters must not leak into AppliedFilters: the
		// suggestion engine removes those tokens from the raw query,
		// where they never appear
		if len(config.AppliedFilters) != 0 {
			t.Errorf("AppliedFilters = %v, want empty", config.AppliedFilters)
		}
	})

	// The number survives whole either way; what the set code in front of
	// it decides is that the query is asked as written.
	t.Run("PLST prefixed numbers stay in one piece", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "plst c16-177", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "PLST")
		checkValues(t, findFilter(config, "number_strict"), "number_strict", "c16-177")
	})

	t.Run("set reading wins over prefix reading", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "c16 177", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "C16")
		checkValues(t, findFilter(config, "number"), "number", "177")
	})

	t.Run("ascending numbers still parse as a range", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo 1-10", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "NEO")
		elem := findFilter(config, "number_less_than")
		checkValues(t, elem, "number_less_than", "10")
		if len(elem.Subfilters) != 1 || elem.Subfilters[0].Name != "number_greater_than" {
			t.Fatalf("subfilters = %+v, want a single number_greater_than", elem.Subfilters)
		}
	})

	t.Run("shorthand composes with other filters", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo 234 f:foil", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "NEO")
		checkValues(t, findFilter(config, "number"), "number", "234")
		checkValues(t, findFilter(config, "finish"), "finish", "foil")
		if len(config.AppliedFilters) != 1 || config.AppliedFilters[0] != "f:foil" {
			t.Errorf("AppliedFilters = %v, want [f:foil]", config.AppliedFilters)
		}
	})

	t.Run("shorthand composes with finish suffixes", func(t *testing.T) {
		// The trailing */&/~ is peeled into a finish filter before the
		// shorthand sees the query, leaving a clean two-token rewrite
		config := parseSearchOptionsNG(backend(), "neo 123*", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "NEO")
		checkValues(t, findFilter(config, "number"), "number", "123")
		checkValues(t, findFilter(config, "finish"), "finish", "foil")
	})

	t.Run("hash and zero prefixes normalize away", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo #234", nil, nil, nil)
		checkValues(t, findFilter(config, "number"), "number", "234")
		config = parseSearchOptionsNG(backend(), "neo 0234", nil, nil, nil)
		checkValues(t, findFilter(config, "number"), "number", "234")
	})

	t.Run("unknown set code keeps the name search", func(t *testing.T) {
		checkNameSearch(t, "lightning 148")
	})

	t.Run("non numeric second token keeps the name search", func(t *testing.T) {
		checkNameSearch(t, "neo dragon")
	})

	t.Run("ordinal second token keeps the name search", func(t *testing.T) {
		checkNameSearch(t, "neo 4th")
	})

	t.Run("set-code-shaped second token keeps the name search", func(t *testing.T) {
		checkNameSearch(t, "neo 10e")
	})

	t.Run("explicit search mode disables the shorthand", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo 234 sm:prefix", nil, nil, nil)
		if findFilter(config, "edition") != nil {
			t.Error("unexpected edition filter")
		}
		if config.CleanQuery != "neo 234" {
			t.Errorf("CleanQuery = %q, want %q", config.CleanQuery, "neo 234")
		}
	})

	// A number saying more than the plain one behind it is asked for as
	// written. cn: reads a number down to that plain one and answers with
	// every printing filed under it, which is the right reading for whoever
	// writes cn: and the wrong one for whoever typed two words: SPG files
	// eight Mana Crypts under 17, and "spg 17a" names exactly one of them.
	t.Run("a suffix asks for the printing wearing it", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "spg 17a", nil, nil, nil)
		checkValues(t, findFilter(config, "edition"), "edition", "SPG")
		checkValues(t, findFilter(config, "number_strict"), "number_strict", "17a")
		if findFilter(config, "number") != nil {
			t.Error("unexpected loose number filter")
		}

		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		var numbers []string
		seen := map[string]bool{}
		for _, key := range keys {
			co, err := backend().GetUUID(key)
			if err != nil || seen[co.Number] {
				continue
			}
			seen[co.Number] = true
			numbers = append(numbers, co.Number)
		}
		if len(numbers) != 1 || numbers[0] != "17a" {
			t.Errorf("spg 17a reached %v, want only [17a]", numbers)
		}
	})

	// A mark is a suffix like any other: 4ED files Thoughtlace at 107 and
	// Drudge Skeletons at 107†, and cn: answers both.
	t.Run("a mark asks for the marked printing", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "4ed 107†", nil, nil, nil)
		checkValues(t, findFilter(config, "number_strict"), "number_strict", "107†")

		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			co, err := backend().GetUUID(key)
			if err != nil {
				continue
			}
			if co.Number != "107†" {
				t.Errorf("4ed 107† reached #%s", co.Number)
			}
		}
		if len(keys) == 0 {
			t.Error("4ed 107† reached no printing")
		}
	})

	t.Run("a plain number still answers the family", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "spg 17", nil, nil, nil)
		checkValues(t, findFilter(config, "number"), "number", "17")

		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		numbers := map[string]bool{}
		for _, key := range keys {
			co, err := backend().GetUUID(key)
			if err != nil {
				continue
			}
			numbers[co.Number] = true
		}
		if len(numbers) < 2 {
			t.Errorf("spg 17 reached %d distinct numbers, want the family", len(numbers))
		}
	})

	// A prefixed number is asked as written like any other, and reaches the
	// one printing it names.
	t.Run("a prefixed number reaches its printing", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "plst c16-177", nil, nil, nil)
		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			co, err := backend().GetUUID(key)
			if err != nil {
				continue
			}
			if !strings.EqualFold(co.Number, "C16-177") {
				t.Errorf("plst c16-177 reached #%s", co.Number)
			}
		}
		if len(keys) == 0 {
			t.Error("plst c16-177 reached no printing")
		}
	})

	// Only the shorthand moves. Whoever writes the operator out has picked
	// its reading and keeps it, decorations and all.
	t.Run("writing cn: keeps its own looser reading", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "s:spg cn:17a", nil, nil, nil)
		checkValues(t, findFilter(config, "number"), "number", "17")
	})

	// ExtractNumberAny drops a # along with the parens and padding it
	// cleans off a vendor's listing, so "#234" arrives as the plain number
	// it means and reads loosely. It is what is left after that which
	// picks the reading, while the token as typed is what gets asked for -
	// so "#17a" is asked for whole, and no card is numbered that.
	t.Run("a hash on a suffixed number is no number at all", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "spg #17a", nil, nil, nil)
		checkValues(t, findFilter(config, "number_strict"), "number_strict", "#17a")

		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Errorf("spg #17a reached %d printings, want none", len(keys))
		}
	})

	// NEO carries no 30a. The shorthand used to drop the letter and hand
	// back #30; answering nothing says what is true, and the plain number
	// is still one keystroke away.
	t.Run("a suffix the set does not carry reaches nothing", func(t *testing.T) {
		config := parseSearchOptionsNG(backend(), "neo 30a", nil, nil, nil)
		checkValues(t, findFilter(config, "number_strict"), "number_strict", "30a")

		keys, err := searchAndFilter(currentDatastore(), config)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Errorf("neo 30a reached %d printings, want none", len(keys))
		}
	})
}

// cn strips the star/dagger/phi decorations from both sides, so plain
// queries find decorated printings; cns keeps the query verbatim and
// matches the full decorated number only.
func TestCollectorNumberStrict(t *testing.T) {
	co := &mtgmatcher.CardObject{}
	co.Number = "107★"
	co.PlainNumber = "107"

	config := parseSearchOptionsNG(backend(), "cn:107", nil, nil, nil)
	elem := findNumberFilter(t, config, "number")
	if skip := applyCardFilter(backend(), "number", elem.Values, co); skip {
		t.Error("cn:107 should match the starred printing")
	}

	config = parseSearchOptionsNG(backend(), "cn:107★", nil, nil, nil)
	elem = findNumberFilter(t, config, "number")
	if len(elem.Values) != 1 || elem.Values[0] != "107" {
		t.Errorf("cn should strip decorations from the query, got %v", elem.Values)
	}

	config = parseSearchOptionsNG(backend(), "cns:107★", nil, nil, nil)
	elem = findNumberFilter(t, config, "number_strict")
	if len(elem.Values) != 1 || elem.Values[0] != "107★" {
		t.Errorf("cns should keep the query verbatim, got %v", elem.Values)
	}
	if skip := applyCardFilter(backend(), "number_strict", elem.Values, co); skip {
		t.Error("cns:107★ should match the starred printing")
	}

	config = parseSearchOptionsNG(backend(), "cns:107", nil, nil, nil)
	elem = findNumberFilter(t, config, "number_strict")
	if skip := applyCardFilter(backend(), "number_strict", elem.Values, co); !skip {
		t.Error("cns:107 should not match the starred printing")
	}
}

func findNumberFilter(t *testing.T, config SearchConfig, name string) *FilterElem {
	t.Helper()
	for i := range config.CardFilters {
		if config.CardFilters[i].Name == name {
			return &config.CardFilters[i]
		}
	}
	t.Fatalf("missing %s filter", name)
	return nil
}
