package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

// poolSearch runs a query as the search page does, with the given pinned
// bar and tab, and returns its keys sorted, or the error.
func poolSearch(t *testing.T, query, scope string, sealed bool) ([]string, error) {
	t.Helper()
	ds := currentDatastore()
	config := parseSearchOptionsNG(ds.backend, query, nil, nil, nil)
	applySearchScope(&config, scopeFilters(ds.backend, scope))
	if sealed {
		config.SearchMode = "sealed"
	}
	keys, err := searchAndFilter(ds, config)
	if err != nil {
		return nil, err
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func mustPoolSearch(t *testing.T, query string) []string {
	t.Helper()
	keys, err := poolSearch(t, query, "", false)
	if err != nil {
		t.Fatalf("%q: %v", query, err)
	}
	if len(keys) == 0 {
		t.Fatalf("%q: no keys", query)
	}
	return keys
}

// aProductWithBothParts finds a sealed product that has guaranteed cards
// and a random part, so all three contents readings mean something.
func aProductWithBothParts(t *testing.T) string {
	t.Helper()
	b := backend()
	for _, uuid := range b.GetSealedUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		if sealed.HasDecklist(b, co.SetCode, co.UUID) && sealed.IsRandom(b, co.SetCode, co.UUID) {
			return co.Name
		}
	}
	t.Skip("no product with both a fixed and a random part")
	return ""
}

// A set pool is the set filter; a product pool is the contents filter; a
// subquery pool is the subquery's own filters. Same keys either way.
func TestPoolEqualsFilters(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)

	tests := []struct{ pooled, plain string }{
		{"r:mythic in:CMR", "r:mythic s:CMR"},
		{"r:mythic in:(s:CMR)", "r:mythic s:CMR"},
		// A negated rarity keeps most of a product, whatever it holds.
		{`in:"` + product + `"`, `contents:"` + product + `"`},
		{`-r:mythic in:"` + product + `"`, `-r:mythic contents:"` + product + `"`},
		{"s:CMR in:(sm:any dragon)", "sm:any dragon s:CMR"},
		{"in:(s:CMR) in:(r:rare)", "s:CMR r:rare"},
		{"sm:any dragon in:CMR", "sm:any dragon s:CMR"},
	}
	for _, tt := range tests {
		pooled := mustPoolSearch(t, tt.pooled)
		plain := mustPoolSearch(t, tt.plain)
		if !slices.Equal(pooled, plain) {
			t.Errorf("%q gave %d keys, %q gave %d", tt.pooled, len(pooled), tt.plain, len(plain))
		}
	}
}

// Everything a product can hold minus what it always holds is its
// variable part, which variable: already names.
func TestPoolNegatedEqualsVariable(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)

	negated := mustPoolSearch(t, `contents:"`+product+`" -in:(decklist:"`+product+`")`)
	variable := mustPoolSearch(t, `variable:"`+product+`"`)
	if !slices.Equal(negated, variable) {
		t.Errorf("negated pool gave %d keys, variable: gave %d", len(negated), len(variable))
	}
}

// The pinned bar carries a pool like any filter, and a pool alone seeds.
func TestPoolPinned(t *testing.T) {
	skipWithoutDatastore(t)

	pinned, err := poolSearch(t, "r:mythic", "in:(s:CMR)", false)
	if err != nil {
		t.Fatal(err)
	}
	plain := mustPoolSearch(t, "r:mythic s:CMR")
	if !slices.Equal(pinned, plain) {
		t.Errorf("pinned pool gave %d keys, plain %d", len(pinned), len(plain))
	}

	alone, err := poolSearch(t, "", "in:(s:CMR)", false)
	if err != nil {
		t.Fatal(err)
	}
	set := mustPoolSearch(t, "s:CMR")
	if !slices.Equal(alone, set) {
		t.Errorf("pool alone gave %d keys, the set %d", len(alone), len(set))
	}
}

// On the sealed tab a pool with no mode of its own names products.
func TestPoolSealedInherits(t *testing.T) {
	skipWithoutDatastore(t)

	pooled, err := poolSearch(t, "in:CMR", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pooled) == 0 || containsSingles(backend(), pooled) {
		t.Fatalf("sealed pool gave %d keys with a single among them", len(pooled))
	}
	plain, err := poolSearch(t, "s:CMR", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pooled, plain) {
		t.Errorf("sealed pool gave %d keys, s:CMR on the sealed tab %d", len(pooled), len(plain))
	}
}

// On the sealed tab a product pool names the products inside it, never its cards.
func TestPoolSealedProduct(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)

	pooled, err := poolSearch(t, "in:\""+product+"\"", "", true)
	plain, perr := poolSearch(t, "contents:\""+product+"\"", "", true)
	if perr == nil && len(plain) > 0 {
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(pooled, plain) {
			t.Errorf("sealed product pool gave %d keys, contents: %d", len(pooled), len(plain))
		}
		if containsSingles(backend(), pooled) {
			t.Error("sealed product pool holds a single")
		}
	} else if !errors.Is(err, errEmptyPool) {
		t.Errorf("sealed product pool with no products: %v, want errEmptyPool", err)
	}
}

// A game whose default mode is any still inherits the sealed tab.
func TestPoolDefaultModeInherits(t *testing.T) {
	skipWithoutDatastore(t)

	sub := parseSearchOptionsNG(backend(), "s:CMR", nil, nil, nil)
	sub.SearchMode = "any"
	sub.DefaultMode = true
	config := SearchConfig{SearchMode: "sealed", CardFilters: []FilterElem{{Name: "pool", Pool: &sub}}}
	keys, err := searchAndFilter(currentDatastore(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 || containsSingles(backend(), keys) {
		t.Fatalf("default-mode pool gave %d keys with a single among them", len(keys))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	want := slices.Clone(backend().GetSealedUUIDsInSet("CMR"))
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("default-mode pool gave %d keys, CMR's sealed products %d", len(keys), len(want))
	}
}

// A contents: search is mixed, and a pool under it keeps nested products.
func TestPoolInheritsMixed(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()

	// A CMR product whose contents hold a CMR product, so mixed shows.
	for _, uuid := range b.GetSealedUUIDsInSet("CMR") {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		plain, err := poolSearch(t, "contents:\""+co.Name+"\" s:CMR", "", false)
		if err != nil || !slices.ContainsFunc(plain, func(id string) bool {
			c, err := b.GetUUID(id)
			return err == nil && c.Sealed
		}) {
			continue
		}
		pooled, err := poolSearch(t, "contents:\""+co.Name+"\" in:CMR", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(pooled, plain) {
			t.Errorf("%s: in:CMR gave %d keys, s:CMR %d", co.Name, len(pooled), len(plain))
		}
		return
	}
	t.Skip("no CMR product holds another CMR product")
}

// A positive pool holding nothing answers nothing, as a name no card
// carries does; a negated empty pool excludes nothing.
func TestPoolEmpty(t *testing.T) {
	skipWithoutDatastore(t)

	_, err := poolSearch(t, "r:mythic in:(s:CMR cn:99999)", "", false)
	if !errors.Is(err, errEmptyPool) {
		t.Errorf("empty pool: %v, want errEmptyPool", err)
	}

	negated, err := poolSearch(t, "r:mythic s:CMR -in:(s:CMR cn:99999)", "", false)
	if err != nil {
		t.Fatal(err)
	}
	plain := mustPoolSearch(t, "r:mythic s:CMR")
	if !slices.Equal(negated, plain) {
		t.Errorf("negated empty pool changed the result: %d vs %d", len(negated), len(plain))
	}
}

// Store and price terms in a subquery do not shape membership.
func TestPoolIgnoresStoreTerms(t *testing.T) {
	skipWithoutDatastore(t)

	with := mustPoolSearch(t, "r:mythic in:(s:CMR store:CK price>1000)")
	without := mustPoolSearch(t, "r:mythic in:(s:CMR)")
	if !slices.Equal(with, without) {
		t.Errorf("store terms changed membership: %d vs %d", len(with), len(without))
	}
}

// A decklist search names its own uuids and copies; a pool filters them
// and never replaces them as the seed.
func TestPoolKeepsDecklistCopies(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)
	ds := currentDatastore()

	config := parseSearchOptionsNG(ds.backend, `decklist:"`+product+`"`, nil, nil, nil)
	deck, err := searchAndFilter(ds, config)
	if err != nil || len(deck) == 0 {
		t.Fatalf("decklist: %d keys, %v", len(deck), err)
	}
	co, err := ds.backend.GetUUID(deck[0])
	if err != nil {
		t.Fatal(err)
	}

	config = parseSearchOptionsNG(ds.backend, `decklist:"`+product+`" in:`+co.SetCode, nil, nil, nil)
	pooled, err := searchAndFilter(ds, config)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, uuid := range deck {
		if c, err := ds.backend.GetUUID(uuid); err == nil && c.SetCode == co.SetCode {
			want = append(want, uuid)
		}
	}
	if !slices.Equal(pooled, want) {
		t.Errorf("pooled decklist %d keys, want %d with repeats kept", len(pooled), len(want))
	}
}

// The seed only spares the walk over every uuid: the contents filter still
// decides, so a seeded contents: search answers exactly what the full walk
// did, for every product that has a decklist. A product that differs is a
// data quirk to report, not a reason to loosen this.
func TestContentsSeedMatchesFullWalk(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()

	all := append(slices.Clone(b.GetUUIDs()), b.GetSealedUUIDs()...)
	checked := 0
	// A stride reaches every set rather than the first few.
	products := b.GetSealedUUIDs()
	stride := max(1, len(products)/200)
	for i := 0; i < len(products); i += stride {
		co, err := b.GetUUID(products[i])
		if err != nil || !sealed.HasDecklist(b, co.SetCode, co.UUID) {
			continue
		}
		config := parseSearchOptionsNG(b, `contents:"`+co.Name+`"`, nil, nil, nil)
		if len(config.CardFilters) != 1 || config.CardFilters[0].Name != "contents" {
			continue // the name resolved to several products or none
		}
		seed, ok := contentsSeedUUIDs(currentDatastore().sources, config.SearchMode, config.CardFilters)
		if !ok {
			t.Errorf("%s: no seed", co.Name)
			continue
		}
		got := filterUUIDs(b, seed, config.CardFilters)
		want := filterUUIDs(b, all, config.CardFilters)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(slices.Compact(got), slices.Compact(want)) {
			t.Errorf("%s: seeded %d keys, full walk %d", co.Name, len(got), len(want))
		}
		checked++
		if checked == 200 {
			break
		}
	}
	if checked == 0 {
		t.Skip("no product with a decklist")
	}
}

// contents: alone, with no name, goes through the seed.
func TestContentsSeedUsed(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)

	config := parseSearchOptionsNG(backend(), `contents:"`+product+`"`, nil, nil, nil)
	seed, ok := contentsSeedUUIDs(currentDatastore().sources, config.SearchMode, config.CardFilters)
	if !ok || len(seed) == 0 {
		t.Fatalf("seed: ok=%v len=%d", ok, len(seed))
	}
	if len(seed) >= len(backend().GetUUIDs()) {
		t.Errorf("seed is %d uuids, no smaller than the datastore", len(seed))
	}
	// A negated contents filter bounds nothing.
	config = parseSearchOptionsNG(backend(), `-contents:"`+product+`"`, nil, nil, nil)
	if _, ok := contentsSeedUUIDs(currentDatastore().sources, config.SearchMode, config.CardFilters); ok {
		t.Error("a negated contents filter seeded")
	}
}

// The three-way contents switch swaps the mode word outside any pool, so
// a contents: inside a pool is left alone.
func TestContentsViewsSkipPools(t *testing.T) {
	skipWithoutDatastore(t)
	product := aProductWithBothParts(t)
	b := backend()

	query := `in:(contents:"` + product + `") variable:"` + product + `"`
	config := parseSearchOptionsNG(b, query, nil, nil, nil)
	views := contentsViews(b, query, config)
	if views == nil {
		t.Fatal("no views for a product with both parts")
	}
	want := `in:(contents:"` + product + `") decklist:"` + product + `"`
	if views.Fixed != want {
		t.Errorf("Fixed = %q, want %q", views.Fixed, want)
	}
}

// genQuery quotes the name only when the regexp would eat part of it.
func TestGenQueryQuotesFilterLikeNames(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	uuid := b.GetUUIDs()[0]
	co, err := b.GetUUID(uuid)
	if err != nil {
		t.Fatal(err)
	}
	if co.Sealed {
		t.Skip("first uuid is a product")
	}
	got := genQuery(co)
	if !strings.HasPrefix(got, quoteIfFilter(co.Name)+" s:"+co.SetCode) {
		t.Errorf("genQuery = %q", got)
	}
	// Round trip: a query built from a card finds that card's name.
	config := parseSearchOptionsNG(b, got, nil, nil, nil)
	if config.CleanQuery != co.Name {
		t.Errorf("round trip clean query %q, want %q", config.CleanQuery, co.Name)
	}
}

// #467: the show-all link and the bare-name suggestion keep the quotes a
// filter-looking name needs.
func TestShowAllAndSuggestionsQuoteFilterLikeName(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()

	query := `"S:P Little Knight" s:LEA`
	config := parseSearchOptionsNG(b, query, nil, nil, nil)
	if got := quoteIfFilter(config.CleanQuery); got != `"S:P Little Knight"` {
		t.Errorf("show-all query = %q", got)
	}
	didYouMean, alts := searchSuggestions(b, query, config, false)
	if !slices.ContainsFunc(alts, func(alt suggest.AltSearch) bool {
		return alt.Query == `"S:P Little Knight"`
	}) {
		t.Errorf("no quoted bare-name suggestion in %+v", alts)
	}
	if strings.Contains(didYouMean, `"`) {
		t.Errorf("did-you-mean read the quotes: %q", didYouMean)
	}
}
