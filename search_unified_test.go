package main

import (
	"slices"
	"testing"
)

// unifiedSearch runs a query the way the search page will: cards and
// sealed products together, before any store filtering.
func unifiedSearch(t *testing.T, query string) []string {
	t.Helper()
	config := parseSearchOptionsNG(backend(), query, nil, nil, nil)
	config.IncludeSealed = true
	keys, err := searchAndFilter(currentDatastore(), config)
	if err != nil {
		t.Fatalf("%q: %v", query, err)
	}
	return keys
}

// splitSealed counts the cards and the products among keys.
func splitSealed(t *testing.T, keys []string) (singles, sealed int) {
	t.Helper()
	for _, key := range keys {
		co, err := backend().GetUUID(key)
		if err != nil {
			t.Fatal(err)
		}
		if co.Sealed {
			sealed++
		} else {
			singles++
		}
	}
	return
}

// A name that is both a card and a set with product answers with both:
// Onslaught the enchantment and the Onslaught boxes and packs.
func TestUnifiedSearchAnswersWithCardsAndProducts(t *testing.T) {
	skipWithoutDatastore(t)

	singles, sealed := splitSealed(t, unifiedSearch(t, "onslaught"))
	if singles == 0 || sealed == 0 {
		t.Fatalf("onslaught found %d cards and %d products, want both", singles, sealed)
	}
}

// The card side keeps its whole ladder: "bolt" names no card exactly and
// reaches Lightning Bolt and the rest by prefix, as it does without the flag.
func TestUnifiedSearchKeepsTheCardLadder(t *testing.T) {
	skipWithoutDatastore(t)

	plain := parseSearchOptionsNG(backend(), "bolt", nil, nil, nil)
	cards, err := searchAndFilter(currentDatastore(), plain)
	if err != nil {
		t.Fatal(err)
	}
	both := unifiedSearch(t, "bolt")
	for _, key := range cards {
		if !slices.Contains(both, key) {
			t.Fatalf("the plain search finds %s, the unified one does not", key)
		}
	}
	if _, sealed := splitSealed(t, both); sealed == 0 {
		t.Error("bolt reaches no product; the sealed side did not run")
	}
}

// sm:exact means exact on both sides: "onslaught" names no product
// exactly, so an exact search finds the card alone.
func TestUnifiedExactSearchIsExactOnProducts(t *testing.T) {
	skipWithoutDatastore(t)

	keys := unifiedSearch(t, "sm:exact onslaught")
	singles, sealed := splitSealed(t, keys)
	if singles == 0 || sealed != 0 {
		t.Fatalf("sm:exact onslaught found %d cards and %d products, want cards only", singles, sealed)
	}
}

// A card search that finds cards and no product is not an error, and the
// card matcher does not run over a union that already holds results:
// Lightning Bolt gives the same cards with the flag as without it.
func TestUnifiedSearchIsCardsAloneWhenNoProductMatches(t *testing.T) {
	skipWithoutDatastore(t)

	plain := parseSearchOptionsNG(backend(), "Lightning Bolt", nil, nil, nil)
	cards, err := searchAndFilter(currentDatastore(), plain)
	if err != nil {
		t.Fatal(err)
	}
	both := unifiedSearch(t, "Lightning Bolt")
	slices.Sort(cards)
	slices.Sort(both)
	if !slices.Equal(cards, both) {
		t.Errorf("Lightning Bolt: plain %d keys, unified %d keys", len(cards), len(both))
	}
}

// An exact product name is one product, however many ladders reach it.
func TestUnifiedSearchDoesNotRepeatAProduct(t *testing.T) {
	skipWithoutDatastore(t)

	var product string
	for _, uuid := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err == nil {
			product = co.Name
			break
		}
	}
	if product == "" {
		t.Skip("no sealed product loaded")
	}
	keys := unifiedSearch(t, product)
	seen := map[string]int{}
	for _, key := range keys {
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("%q lists %s twice", product, key)
		}
	}
	want, _ := backend().SearchSealedEquals(product)
	if len(keys) != len(want) {
		t.Errorf("%q found %d keys, want %d", product, len(keys), len(want))
	}
}

// Neither side answering is still an error, so the fallback readings run.
func TestUnifiedSearchStillErrsOnNothing(t *testing.T) {
	skipWithoutDatastore(t)

	config := parseSearchOptionsNG(backend(), "zzzznotacardnoraproduct", nil, nil, nil)
	config.IncludeSealed = true
	if _, err := searchAndFilter(currentDatastore(), config); err == nil {
		t.Error("a name nothing carries returned no error")
	}
}

// An edition filter alone seeds both pools from the set index: every card
// and every product of the set, without a scan of the whole datastore.
func TestUnifiedSearchSeedsBothPoolsFromAnEdition(t *testing.T) {
	skipWithoutDatastore(t)

	var code string
	for _, c := range backend().GetAllSets() {
		if len(backend().GetSealedUUIDsInSet(c)) > 0 && len(backend().GetUUIDsInSet(c)) > 0 {
			code = c
			break
		}
	}
	if code == "" {
		t.Skip("no set carries both cards and products")
	}

	config := parseSearchOptionsNG(backend(), "s:"+code, nil, nil, nil)
	config.IncludeSealed = true
	seeded, ok := seedUUIDs(currentDatastore(), config)
	if !ok {
		t.Fatal("an edition filter did not seed")
	}
	want := len(backend().GetUUIDsInSet(code)) + len(backend().GetSealedUUIDsInSet(code))
	if len(seeded) != want {
		t.Errorf("s:%s seeded %d uuids, want %d", code, len(seeded), want)
	}
}

// The products-only mode is untouched by the flag: the API and the Discord
// bot ask for it and get products or nothing.
func TestSealedModeIgnoresTheFlag(t *testing.T) {
	skipWithoutDatastore(t)

	config := parseSearchOptionsNG(backend(), "onslaught", nil, nil, nil)
	config.SearchMode = "sealed"
	config.IncludeSealed = true
	keys, err := searchAndFilter(currentDatastore(), config)
	if err != nil {
		t.Fatal(err)
	}
	if singles, _ := splitSealed(t, keys); singles != 0 {
		t.Errorf("sealed mode answered with %d cards", singles)
	}
}

// Both routes run the same search, cards and products together; the route
// decides only which group leads.
func TestBothRoutesSearchBothPools(t *testing.T) {
	for _, tc := range []struct {
		path        string
		sealedFirst bool
	}{
		{"/search", false},
		{"/sealed", true},
	} {
		config := SearchConfig{CleanQuery: "onslaught"}
		applyRouteSearch(&config, tc.path)
		if !config.IncludeSealed {
			t.Errorf("%s: IncludeSealed not set", tc.path)
		}
		if config.SearchMode == "sealed" {
			t.Errorf("%s: the route forced the products-only mode", tc.path)
		}
		if config.SealedFirst != tc.sealedFirst {
			t.Errorf("%s: SealedFirst = %v, want %v", tc.path, config.SealedFirst, tc.sealedFirst)
		}
	}
	if !routeSealed("/sealed") || routeSealed("/search") || routeSealed("/sets") {
		t.Error("routeSealed does not read the path")
	}
}

// mixedKeys returns some cards and some products, interleaved, for the
// ordering tests.
func mixedKeys(t *testing.T) []string {
	t.Helper()
	cards := backend().GetUUIDs()
	products := backend().GetSealedUUIDs()
	if len(cards) < 3 || len(products) < 3 {
		t.Skip("not enough cards and products loaded")
	}
	return []string{cards[0], products[0], cards[1], products[1], cards[2], products[2]}
}

// The partition keeps each group in the order it was handed and puts the
// asked-for group first.
func TestGroupSealedKeepsOrderWithinEachGroup(t *testing.T) {
	skipWithoutDatastore(t)

	for _, sealedFirst := range []bool{false, true} {
		keys := mixedKeys(t)
		cards := []string{keys[0], keys[2], keys[4]}
		products := []string{keys[1], keys[3], keys[5]}

		singles, sealed, _ := groupSealed(backend(), keys, sealedFirst)
		if singles != 3 || sealed != 3 {
			t.Fatalf("counted %d cards and %d products, want 3 and 3", singles, sealed)
		}
		want := append(slices.Clone(cards), products...)
		if sealedFirst {
			want = append(slices.Clone(products), cards...)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("sealedFirst=%v: got %v, want %v", sealedFirst, keys, want)
		}
	}
}

// A header sits before the first row of each group on the page, with the
// group's whole count, and only when the result holds both groups. The
// row before each header ends its group.
func TestGroupHeadersMarkEachGroupOnce(t *testing.T) {
	skipWithoutDatastore(t)

	keys := mixedKeys(t)
	singles, sealed, isSealed := groupSealed(backend(), keys, false)
	headers, ends := groupHeaders(isSealed, keys, singles, sealed)
	if len(headers) != 2 {
		t.Fatalf("%d headers, want 2: %v", len(headers), headers)
	}
	if headers[keys[0]] != "Singles (3)" {
		t.Errorf("first card header = %q", headers[keys[0]])
	}
	if headers[keys[3]] != "Sealed products (3)" {
		t.Errorf("first product header = %q", headers[keys[3]])
	}
	if len(ends) != 1 || !ends[keys[2]] {
		t.Errorf("ends = %v, want the last card %s alone", ends, keys[2])
	}

	// One group alone draws no header: a plain card search looks as it did.
	cards := []string{keys[0], keys[1], keys[2]}
	if h, e := groupHeaders(isSealed, cards, 3, 0); len(h) != 0 || len(e) != 0 {
		t.Errorf("a single-group result drew headers %v and ends %v", h, e)
	}
}

// A page that starts inside a group, because pagination split the group
// across pages, still names the group at its first row.
func TestGroupHeadersLabelAPageThatStartsInsideAGroup(t *testing.T) {
	skipWithoutDatastore(t)

	keys := mixedKeys(t)
	singles, sealed, isSealed := groupSealed(backend(), keys, false)
	page := keys[3:]
	headers, ends := groupHeaders(isSealed, page, singles, sealed)
	if len(headers) != 1 {
		t.Fatalf("%d headers, want 1: %v", len(headers), headers)
	}
	if headers[page[0]] != "Sealed products (3)" {
		t.Errorf("page-top header = %q", headers[page[0]])
	}
	if len(ends) != 0 {
		t.Errorf("ends = %v, want none: no group ends on this page", ends)
	}
}

// A set name no card carries still reaches the set's cards on the page: the
// product side answering must not silence the fallback that reads "kaldheim"
// as a set. Both the cards and the boxes come back.
func TestUnifiedSearchStillFallsBackToASetName(t *testing.T) {
	skipWithoutDatastore(t)

	plain := parseSearchOptionsNG(backend(), "kaldheim", nil, nil, nil)
	cards, err := searchAndFilter(currentDatastore(), plain)
	if err != nil {
		cards = searchFallback(currentDatastore(), plain)
	}
	if len(cards) == 0 {
		t.Skip("kaldheim reaches no cards here")
	}

	keys := unifiedSearch(t, "kaldheim")
	singles, sealed := splitSealed(t, keys)
	if singles < len(cards) || sealed == 0 {
		t.Fatalf("kaldheim found %d cards and %d products, want at least %d cards and some products", singles, sealed, len(cards))
	}
}

// A treatment word reads as a promo type the same way: "galaxy" is the
// galaxy-foil cards, with any product named for it beside them.
func TestUnifiedSearchStillFallsBackToATreatment(t *testing.T) {
	skipWithoutDatastore(t)

	plain := parseSearchOptionsNG(backend(), "galaxy", nil, nil, nil)
	cards, err := searchAndFilter(currentDatastore(), plain)
	if err != nil {
		cards = searchFallback(currentDatastore(), plain)
	}
	if len(cards) == 0 {
		t.Skip("galaxy reaches no cards here")
	}

	keys := unifiedSearch(t, "galaxy")
	singles, _ := splitSealed(t, keys)
	if singles < len(cards) {
		t.Fatalf("galaxy found %d cards, want at least %d", singles, len(cards))
	}
}

// The other direction: a name only products carry is an answer, not an
// error, and holds no card.
func TestUnifiedSearchAnswersWithProductsAlone(t *testing.T) {
	skipWithoutDatastore(t)

	keys := unifiedSearch(t, "onslaught booster")
	singles, sealed := splitSealed(t, keys)
	if singles != 0 || sealed == 0 {
		t.Fatalf("onslaught booster found %d cards and %d products, want products only", singles, sealed)
	}
}

// Over the cap, the route's lead group survives the cut: a filter-only
// query on /sealed keeps its products ahead of 149k cards.
func TestResultCapKeepsTheLeadGroup(t *testing.T) {
	skipWithoutDatastore(t)

	config := parseSearchOptionsNG(backend(), "price>0", nil, nil, nil)
	applyRouteSearch(&config, "/sealed")
	keys, err := searchAndFilter(currentDatastore(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) <= MaxSearchTotalResults {
		t.Skipf("only %d keys, the cap never applies", len(keys))
	}
	groupSealed(backend(), keys, config.SealedFirst)
	_, sealed := splitSealed(t, keys[:MaxSearchTotalResults])
	if sealed != len(backend().GetSealedUUIDs()) {
		t.Errorf("the cut kept %d products, want all %d", sealed, len(backend().GetSealedUUIDs()))
	}
}
