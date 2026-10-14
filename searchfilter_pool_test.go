package main

import (
	"slices"
	"strings"
	"testing"
)

// The scanner needs no datastore: it reads text.
func TestSplitQueryPlain(t *testing.T) {
	pools, protected, rest := splitQuery("Dark Ritual s:LEA f:foil")
	if len(pools) != 0 || len(protected) != 0 || rest != "Dark Ritual s:LEA f:foil" {
		t.Fatalf("plain query changed: %v %v %q", pools, protected, rest)
	}
}

func TestSplitQueryPools(t *testing.T) {
	tests := []struct {
		query string
		pools []poolSpan
		rest  string
	}{
		{
			`r:mythic in:(contents:"Commander Legends Collector Booster")`,
			[]poolSpan{{Raw: `in:(contents:"Commander Legends Collector Booster")`, Value: `contents:"Commander Legends Collector Booster"`, Paren: true}},
			"r:mythic " + poolMark,
		},
		{
			"in:(in:(s:CMR) r:rare) sm:any dragon",
			[]poolSpan{{Raw: "in:(in:(s:CMR) r:rare)", Value: "in:(s:CMR) r:rare", Paren: true}},
			poolMark + " sm:any dragon",
		},
		{
			"in:(s:CMR r:rare",
			[]poolSpan{{Raw: "in:(s:CMR r:rare", Value: "s:CMR r:rare", Paren: true}},
			poolMark,
		},
		{
			`in:("Fourth Edition" r:rare) x`,
			[]poolSpan{{Raw: `in:("Fourth Edition" r:rare)`, Value: `"Fourth Edition" r:rare`, Paren: true}},
			poolMark + " x",
		},
		{
			`in:(s:"A (B)")`,
			[]poolSpan{{Raw: `in:(s:"A (B)")`, Value: `s:"A (B)"`, Paren: true}},
			poolMark,
		},
		// A bare quote whose closing quote comes after the next paren is
		// a character of the subquery; one after a key opens a value.
		{
			`in:(sm:regexp ^"Ach) r:rare`,
			[]poolSpan{{Raw: `in:(sm:regexp ^"Ach)`, Value: `sm:regexp ^"Ach`, Paren: true}},
			poolMark + " r:rare",
		},
		{
			`in:(sm:regexp "Ach) r:rare`,
			[]poolSpan{{Raw: `in:(sm:regexp "Ach)`, Value: `sm:regexp "Ach`, Paren: true}},
			poolMark + " r:rare",
		},

		{
			"r:mythic in:CMR",
			[]poolSpan{{Raw: "in:CMR", Value: "CMR"}},
			"r:mythic " + poolMark,
		},
		{
			`in:"Commander Legends Collector Booster" r:mythic`,
			[]poolSpan{{Raw: `in:"Commander Legends Collector Booster"`, Value: "Commander Legends Collector Booster"}},
			poolMark + " r:mythic",
		},
		{
			"contents:\"X\" -in:(decklist:\"X\")",
			[]poolSpan{{Raw: `-in:(decklist:"X")`, Value: `decklist:"X"`, Paren: true, Negate: true}},
			"contents:\"X\" " + poolMark,
		},
		{
			"IN:(s:CMR) a",
			[]poolSpan{{Raw: "IN:(s:CMR)", Value: "s:CMR", Paren: true}},
			poolMark + " a",
		},
		{
			"in:(s:CMR) in:(r:rare)",
			[]poolSpan{
				{Raw: "in:(s:CMR)", Value: "s:CMR", Paren: true},
				{Raw: "in:(r:rare)", Value: "r:rare", Paren: true},
			},
			poolMark + " " + poolMark,
		},
		// A word that ends in "in:" is not the key.
		{"Merlin: Wise", nil, "Merlin: Wise"},
		// Nothing after the key is an empty value, left to the parser to drop.
		{"in: foo", []poolSpan{{Raw: "in:", Value: ""}}, poolMark + " foo"},
		{"in:()", []poolSpan{{Raw: "in:()", Value: "", Paren: true}}, poolMark},
	}
	for _, tt := range tests {
		pools, protected, rest := splitQuery(tt.query)
		if !slices.Equal(pools, tt.pools) {
			t.Errorf("%q: pools %+v, want %+v", tt.query, pools, tt.pools)
		}
		if len(protected) != 0 {
			t.Errorf("%q: protected %v, want none", tt.query, protected)
		}
		if rest != tt.rest {
			t.Errorf("%q: rest %q, want %q", tt.query, rest, tt.rest)
		}
	}
}

func TestSplitQueryProtectedText(t *testing.T) {
	tests := []struct {
		query     string
		protected []string
		rest      string
	}{
		{`"S:P Little Knight"`, []string{`"S:P Little Knight"`}, " " + protectedMark + " "},
		{`"Dark Ritual" s:LEA`, []string{`"Dark Ritual"`}, " " + protectedMark + "  s:LEA"},
		// A quote after a key is a filter value and stays for the regexp,
		// comma-joined values included.
		{`s:"Fourth Edition"`, nil, `s:"Fourth Edition"`},
		{`s:"A B","C D" x`, nil, `s:"A B","C D" x`},
		{`"S:P Little Knight" s:"Fourth Edition"`, []string{`"S:P Little Knight"`}, " " + protectedMark + "  s:\"Fourth Edition\""},
		// Unbalanced closes at the end, with the one quote it has.
		{`"Dark Ritual`, []string{`"Dark Ritual`}, " " + protectedMark + " "},
		// Two spans keep their order.
		{`"a b" "c d"`, []string{`"a b"`, `"c d"`}, " " + protectedMark + "   " + protectedMark + " "},
	}
	for _, tt := range tests {
		pools, protected, rest := splitQuery(tt.query)
		if len(pools) != 0 {
			t.Errorf("%q: pools %+v, want none", tt.query, pools)
		}
		if !slices.Equal(protected, tt.protected) {
			t.Errorf("%q: protected %q, want %q", tt.query, protected, tt.protected)
		}
		if rest != tt.rest {
			t.Errorf("%q: rest %q, want %q", tt.query, rest, tt.rest)
		}
	}
}

// A quote after a Pricefall | is the set name the | branch makes a filter
// of, so it stays for the regexp, spaces or not.
func TestSplitQueryPricefall(t *testing.T) {
	for _, query := range []string{`Dark Ritual | "Fourth Edition"`, `Dark Ritual|"Fourth Edition"|32`} {
		pools, protected, rest := splitQuery(query)
		if len(pools) != 0 || len(protected) != 0 || rest != query {
			t.Errorf("%q: pools %v protected %q rest %q, want untouched", query, pools, protected, rest)
		}
	}
	pools, protected, rest := splitQuery(`in:(sm:regexp ^"Ach) r:rare "Dark Ritual"`)
	if len(pools) != 1 || pools[0].Value != `sm:regexp ^"Ach` || !slices.Equal(protected, []string{`"Dark Ritual"`}) || rest != poolMark+" r:rare  "+protectedMark+" " {
		t.Errorf("pool then quoted name: pools %+v protected %q rest %q", pools, protected, rest)
	}
}

func TestRestoreProtected(t *testing.T) {
	marks := " " + protectedMark + "   " + protectedMark + " "
	if got := restoreProtected(marks, []string{`"a b"`, `"c d`}, false); got != "a b c d" {
		t.Errorf("restoreProtected: %q", got)
	}
	if got := restoreProtected(marks, []string{`"a b"`, `"c d`}, true); got != `"a b" "c d` {
		t.Errorf("restoreProtected verbatim: %q", got)
	}
}

// poolFilters returns the pool filters a parse produced.
func poolFilters(config SearchConfig) []FilterElem {
	var out []FilterElem
	for _, f := range config.CardFilters {
		if f.Name == "pool" {
			out = append(out, f)
		}
	}
	return out
}

// A pool carries its sub-parse and nothing in Values, so the edition and
// number seeds do not mistake it for theirs.
func TestParsePoolSubquery(t *testing.T) {
	config := parseSearchOptionsWrapper(`r:mythic in:(s:CMR sm:any dragon)`)
	pools := poolFilters(config)
	if len(pools) != 1 {
		t.Fatalf("pool filters: %d, want 1", len(pools))
	}
	pool := pools[0]
	if pool.Negate || len(pool.Values) != 0 || pool.Pool == nil || pool.Members != nil {
		t.Fatalf("pool filter: %+v", pool)
	}
	if pool.Pool.SearchMode != "any" || pool.Pool.CleanQuery != "dragon" {
		t.Errorf("sub-parse: mode %q query %q", pool.Pool.SearchMode, pool.Pool.CleanQuery)
	}
	if !slices.Contains(filterNames(pool.Pool.CardFilters), "edition") {
		t.Errorf("sub-parse lost its set filter: %v", filterNames(pool.Pool.CardFilters))
	}
	if !slices.Contains(filterNames(config.CardFilters), "rarity") {
		t.Errorf("outer parse lost its rarity filter: %v", filterNames(config.CardFilters))
	}
	if config.CleanQuery != "" {
		t.Errorf("outer clean query %q, want empty", config.CleanQuery)
	}
	if !slices.Contains(config.AppliedFilters, "in:(s:CMR sm:any dragon)") {
		t.Errorf("AppliedFilters %v lacks the pool as typed", config.AppliedFilters)
	}
}

func TestParsePoolNegated(t *testing.T) {
	pools := poolFilters(parseSearchOptionsWrapper(`contents:"X" -in:(decklist:"X")`))
	if len(pools) != 1 || !pools[0].Negate {
		t.Fatalf("pool filters: %+v", pools)
	}
}

// A bare value names a set when one answers to it, in any case, and a
// product otherwise. Needs the datastore for the set lookup.
func TestParsePoolShortcuts(t *testing.T) {
	skipWithoutDatastore(t)

	for _, query := range []string{"r:mythic in:CMR", "r:mythic in:cmr"} {
		pools := poolFilters(parseSearchOptionsWrapper(query))
		if len(pools) != 1 {
			t.Fatalf("%q: pool filters %d, want 1", query, len(pools))
		}
		names := filterNames(pools[0].Pool.CardFilters)
		if !slices.Contains(names, "edition") {
			t.Errorf("%q: sub-parse filters %v, want an edition", query, names)
		}
	}

	pools := poolFilters(parseSearchOptionsWrapper(`r:mythic in:"Commander Legends Collector Booster"`))
	if len(pools) != 1 {
		t.Fatalf("product pool filters %d, want 1", len(pools))
	}
	names := filterNames(pools[0].Pool.CardFilters)
	if !slices.Contains(names, "contents") {
		t.Errorf("product sub-parse filters %v, want contents", names)
	}
	if pools[0].Pool.SearchMode != "mixed" {
		t.Errorf("product sub-parse mode %q, want mixed", pools[0].Pool.SearchMode)
	}
}

// Nothing after in: is nothing to pool; the search runs as if it was not
// typed, and the term is not an applied filter. Alone, it is a pool that
// holds nothing, resolved by the parser itself.
func TestParsePoolEmptyValue(t *testing.T) {
	for _, query := range []string{"in: Dark Ritual", "in:() Dark Ritual", "Dark Ritual in:"} {
		config := parseSearchOptionsWrapper(query)
		if len(poolFilters(config)) != 0 {
			t.Errorf("%q: made a pool filter", query)
		}
		if config.CleanQuery != "Dark Ritual" {
			t.Errorf("%q: clean query %q", query, config.CleanQuery)
		}
		if len(config.AppliedFilters) != 0 {
			t.Errorf("%q: applied filters %v, want none", query, config.AppliedFilters)
		}
	}
	for _, query := range []string{"in:", "in:()", "in: in:"} {
		config := parseSearchOptionsWrapper(query)
		pools := poolFilters(config)
		if len(pools) != 1 || pools[0].Pool != nil || pools[0].Members == nil || len(pools[0].Members) != 0 {
			t.Errorf("%q: pool filters %+v, want one resolved to nothing", query, pools)
		}
		if config.CleanQuery != "" || len(config.AppliedFilters) != 0 {
			t.Errorf("%q: clean query %q, applied %v, want neither", query, config.CleanQuery, config.AppliedFilters)
		}
	}
	// With a filter left, nothing is added.
	if config := parseSearchOptionsWrapper("in: f:foil"); len(poolFilters(config)) != 0 {
		t.Errorf("in: f:foil made a pool filter")
	}
}

// The outer query is depth 0; pools at depth 1, 2, 3 parse, depth 4 is
// dropped.
func TestParsePoolDepth(t *testing.T) {
	config := parseSearchOptionsWrapper("in:(in:(in:(in:(s:CMR) r:rare) r:mythic) r:common)")
	d1 := poolFilters(config)
	if len(d1) != 1 {
		t.Fatalf("depth 1: %d pools", len(d1))
	}
	d2 := poolFilters(*d1[0].Pool)
	if len(d2) != 1 {
		t.Fatalf("depth 2: %d pools", len(d2))
	}
	d3 := poolFilters(*d2[0].Pool)
	if len(d3) != 1 {
		t.Fatalf("depth 3: %d pools", len(d3))
	}
	if d4 := poolFilters(*d3[0].Pool); len(d4) != 0 {
		t.Errorf("depth 4: %d pools, want none", len(d4))
	}
	// The depth-3 parse still kept its own filter, and the dropped term
	// is words in its name, not an applied filter.
	if !slices.Contains(filterNames(d3[0].Pool.CardFilters), "rarity") {
		t.Errorf("depth 3 lost its rarity filter: %v", filterNames(d3[0].Pool.CardFilters))
	}
	if d3[0].Pool.CleanQuery != "in:(s:CMR)" {
		t.Errorf("depth 3 clean query %q, want the dropped term", d3[0].Pool.CleanQuery)
	}
	if !slices.Equal(d3[0].Pool.AppliedFilters, []string{"r:rare"}) {
		t.Errorf("depth 3 applied filters %v, want r:rare alone", d3[0].Pool.AppliedFilters)
	}
	if !slices.Equal(config.AppliedFilters, []string{"in:(in:(in:(in:(s:CMR) r:rare) r:mythic) r:common)"}) {
		t.Errorf("applied filters %v, want the outer pool", config.AppliedFilters)
	}
}

// countPools counts the pool filters a parse produced at every depth.
func countPools(config SearchConfig) int {
	n := 0
	for _, f := range poolFilters(config) {
		n++
		if f.Pool != nil {
			n += countPools(*f.Pool)
		}
	}
	return n
}

// A query carries at most maxPools pools, nested ones drawing on the same
// budget in the order they are read.
func TestParsePoolBudget(t *testing.T) {
	config := parseSearchOptionsWrapper(strings.Repeat("in:(r:rare) ", 10))
	if n := len(poolFilters(config)); n != maxPools {
		t.Errorf("ten pools: %d kept, want %d", n, maxPools)
	}

	config = parseSearchOptionsWrapper("in:(in:(r:rare) in:(r:mythic)) in:(r:common)")
	top := poolFilters(config)
	if len(top) != 2 || len(poolFilters(*top[0].Pool)) != 2 || countPools(config) != 4 {
		t.Errorf("nested pools: %d top, %d in all, want 2 and 4", len(top), countPools(config))
	}

	// Twelve terms: the eighth nested in the seventh takes the last of
	// the budget, so the four after it are dropped.
	query := strings.Repeat("in:(r:rare) ", 6) + "in:(in:(r:mythic) r:rare) " + strings.Repeat("in:(r:common) ", 4)
	config = parseSearchOptionsWrapper(query)
	top = poolFilters(config)
	if countPools(config) != maxPools || len(top) != 7 {
		t.Fatalf("budget: %d top, %d in all, want 7 and %d", len(top), countPools(config), maxPools)
	}
	if len(poolFilters(*top[6].Pool)) != 1 {
		t.Error("the nested pool was dropped")
	}
	for _, f := range top {
		if f.Pool.CleanQuery != "" || slices.ContainsFunc(f.Pool.CardFilters, func(c FilterElem) bool {
			return c.Name == "rarity" && slices.Contains(c.Values, "common")
		}) {
			t.Error("a trailing pool was kept")
		}
	}
	if config.CleanQuery != strings.TrimSpace(strings.Repeat("in:(r:common) ", 4)) {
		t.Errorf("clean query %q, want the four dropped terms", config.CleanQuery)
	}
	if len(config.AppliedFilters) != 7 {
		t.Errorf("applied filters %v, want the seven kept pools", config.AppliedFilters)
	}
}

// The Pricefall | set name reaches the edition filter as the set it names.
func TestParsePricefallQuotedEdition(t *testing.T) {
	skipWithoutDatastore(t)

	for _, query := range []string{`Dark Ritual | "Fourth Edition"`, `Dark Ritual|"Fourth Edition"|32`} {
		config := parseSearchOptionsWrapper(query)
		names := filterNames(config.CardFilters)
		i := slices.Index(names, "edition")
		if i == -1 || !slices.Equal(config.CardFilters[i].Values, []string{"4ED"}) {
			t.Errorf("%q: filters %+v, want edition 4ED", query, config.CardFilters)
		}
		if j := slices.Index(names, "number"); strings.Contains(query, "32") && (j == -1 || !slices.Equal(config.CardFilters[j].Values, []string{"32"})) {
			t.Errorf("%q: filters %+v, want number 32", query, config.CardFilters)
		}
	}
}

// A typed sentinel is not the scanner's: neither mark survives the parse.
func TestParseStripsMarks(t *testing.T) {
	config := parseSearchOptionsWrapper("Dark" + protectedMark + " Ritual " + poolMark + " s:LEA")
	if config.CleanQuery != "Dark Ritual" {
		t.Errorf("clean query %q, want Dark Ritual", config.CleanQuery)
	}
	if !slices.Equal(filterNames(config.CardFilters), []string{"edition"}) {
		t.Errorf("filters %v, want the edition alone", filterNames(config.CardFilters))
	}
}

// A trailing regexp mark goes back to the regexp, not to a finish, when a
// pool filter follows it in the parse.
func TestParsePoolKeepsRegexpSuffix(t *testing.T) {
	config := parseSearchOptionsWrapper("in:CMR se:^Dom.*")
	names := filterNames(config.CardFilters)
	if slices.Contains(names, "finish") {
		t.Errorf("the * became a finish: %v", names)
	}
	if len(poolFilters(config)) != 1 {
		t.Errorf("pool filter lost: %v", names)
	}
	i := slices.Index(names, "edition_regexp")
	if i == -1 || config.CardFilters[i].Values[0] != "^Dom.*" {
		t.Errorf("edition regexp: %v", config.CardFilters)
	}
}

// A scryfall search keeps no filter, pools included.
func TestParsePoolScryfall(t *testing.T) {
	config := parseSearchOptionsWrapper("sm:scryfall in:(r:rare) dragon")
	if len(poolFilters(config)) != 0 {
		t.Error("a scryfall search kept a pool")
	}
}

// #467: a quoted name is a name, whatever it looks like.
func TestParseProtectedText(t *testing.T) {
	tests := []struct {
		query string
		clean string
		names []string // card filter names expected
	}{
		{`"S:P Little Knight"`, "S:P Little Knight", nil},
		{`"Dark Ritual" s:LEA`, "Dark Ritual", []string{"edition"}},
		{`s:LEA "Dark Ritual"`, "Dark Ritual", []string{"edition"}},
		{`"S:P Little Knight" s:"Fourth Edition"`, "S:P Little Knight", []string{"edition"}},
		// In a regexp a quote is a character of the pattern.
		{`sm:regexp ^"A" Cell`, `^"A" Cell`, nil},
		{`sm:regexp ^"Ach`, `^"Ach`, nil},
		{`sm:regexp ^(.*) "Toolbox"`, `^(.*) "Toolbox"`, nil},
		{`sm:regexp "Toolbox" s:LEA`, `"Toolbox"`, []string{"edition"}},
		{`in:(sm:regexp "Toolbox") "S:P Little Knight"`, "S:P Little Knight", []string{"pool"}},
		// A Pricefall set name is the | branch's filter, not a name.
		{`Dark Ritual | "Fourth Edition"`, "Dark Ritual", []string{"edition"}},
		{`Dark Ritual|"Fourth Edition"|32`, "Dark Ritual", []string{"edition", "number"}},
	}
	for _, tt := range tests {
		config := parseSearchOptionsWrapper(tt.query)
		if config.CleanQuery != tt.clean {
			t.Errorf("%q: clean query %q, want %q", tt.query, config.CleanQuery, tt.clean)
		}
		names := filterNames(config.CardFilters)
		if !slices.Equal(names, tt.names) {
			t.Errorf("%q: filters %v, want %v", tt.query, names, tt.names)
		}
		if strings.Contains(config.CleanQuery, protectedMark) {
			t.Errorf("%q: the mark leaked into the clean query", tt.query)
		}
	}
}

func TestCardFilterPool(t *testing.T) {
	skipWithoutDatastore(t)
	uuid := backend().GetUUIDs()[0]
	co, err := backend().GetUUID(uuid)
	if err != nil {
		t.Fatal(err)
	}
	if cardFilterPool(map[string]bool{uuid: true}, co) {
		t.Error("a member was skipped")
	}
	if !cardFilterPool(map[string]bool{}, co) {
		t.Error("a non-member was kept")
	}
	if !cardFilterPool(nil, co) {
		t.Error("an unresolved pool kept a card")
	}
}

// A name the filter regexp would read a filter out of is quoted when a
// query is built from it; every other name is left as it is.
func TestQuoteIfFilter(t *testing.T) {
	tests := []struct{ name, want string }{
		{"Dark Ritual", "Dark Ritual"},
		{"S:P Little Knight", `"S:P Little Knight"`},
		{"Mr. 1 (Daz.Bonez)", "Mr. 1 (Daz.Bonez)"},
		{"Ratio: 3", "Ratio: 3"}, // a colon with a space after it is no filter
		{"is:promo", `"is:promo"`},
	}
	for _, tt := range tests {
		if got := quoteIfFilter(tt.name); got != tt.want {
			t.Errorf("quoteIfFilter(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIndexOutsidePools(t *testing.T) {
	tests := []struct {
		query, substr string
		want          int
	}{
		{`contents:"X" r:rare`, "contents:", 0},
		{`in:(contents:"X") contents:"Y"`, "contents:", 18},
		{`in:(contents:"X")`, "contents:", -1},
		{`-in:(contents:"X") r:rare contents:"Y"`, "contents:", 26},
	}
	for _, tt := range tests {
		if got := indexOutsidePools(tt.query, tt.substr); got != tt.want {
			t.Errorf("indexOutsidePools(%q, %q) = %d, want %d", tt.query, tt.substr, got, tt.want)
		}
	}
}
