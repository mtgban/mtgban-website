package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A contents: or variable: query that names no product has nothing to be the
// contents of. Left as an empty filter it matched every card there is, and
// variable: on a product with nothing guaranteed left no filter at all - both
// answered a typo with the whole datastore.
func TestContentsOfNothingIsNothing(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	for _, query := range []string{
		`contents:"No Such Product Exists"`,
		`variable:"No Such Product Exists"`,
	} {
		ids, _ := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
		if len(ids) != 0 {
			t.Errorf("%s found %d cards", query, len(ids))
		}
	}

	// A product with contents but no decklist: everything it holds is
	// variable, so the two readings agree.
	var box string
	for _, code := range backend().GetAllSets() {
		set, err := backend().GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if backend().SealedIsRandom(code, product.UUID) && !backend().SealedHasDecklist(code, product.UUID) {
				box = product.Name
				break
			}
		}
		if box != "" {
			break
		}
	}
	if box == "" {
		t.Skip("no product without a decklist")
	}
	all, _ := searchAndFilter(parseSearchOptionsNG(`contents:"`+box+`"`, nil, nil, nil))
	variable, _ := searchAndFilter(parseSearchOptionsNG(`variable:"`+box+`"`, nil, nil, nil))
	if len(variable) != len(all) {
		t.Errorf("variable:%q found %d cards, contents: finds %d", box, len(variable), len(all))
	}

	// The same is true once several typoed names are comma-listed: none of
	// them resolves to anything, so there is still nothing to be the
	// contents of.
	ids, _ := searchAndFilter(parseSearchOptionsNG(`contents:"No Such Product Exists","Nor Is This One"`, nil, nil, nil))
	if len(ids) != 0 {
		t.Errorf("multi-value typo list found %d cards", len(ids))
	}
}

// The shared query tokenizer has to accept a comma-joined list of quoted
// multi-word values, with no space around the comma - the same rule every
// other multi-value key (edition:, set:, store:, ...) already parses under.
// Runs without a datastore: it only checks what the regexp captures into one
// field, not what the values resolve to.
func TestCommaQuotedListsTokenize(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query string
	}{
		{"no space", `contents:"A B","C D"`},
		{"three values", `contents:"A B","C D","E F"`},
		// The blast radius is the whole tokenizer, not just contents: -
		// every key that reads a comma list off fixupEditionNG's pattern
		// goes through the same regexp.
		{"another key, no space", `edition:"Kaladesh Inventions","Amonkhet Invocations"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			if config.CleanQuery != "" {
				t.Errorf("%q: leftover free text %q, the value list did not fully tokenize", tt.query, config.CleanQuery)
			}
			if len(config.AppliedFilters) != 1 {
				t.Errorf("%q: tokenized into %d fields, want 1: %v", tt.query, len(config.AppliedFilters), config.AppliedFilters)
			}
		})
	}

	// A trailing free-text word after the list is left alone rather than
	// swallowed into the value.
	config := parseSearchOptionsNG(`contents:"A B","C D" trailing text`, nil, nil, nil)
	if config.CleanQuery != "trailing text" {
		t.Errorf("leftover query = %q, want %q", config.CleanQuery, "trailing text")
	}

	// A space around the comma is not part of the syntax: the second value
	// is left as free text rather than joined into the list. Documents the
	// boundary rather than asserting it should work, so a future change
	// that widens the syntax fails here instead of silently.
	for _, spaced := range []string{
		`contents:"A B", "C D"`,
		`contents:"A B" , "C D"`,
	} {
		config := parseSearchOptionsNG(spaced, nil, nil, nil)
		if config.CleanQuery == "" {
			t.Errorf("%q: the whole list tokenized as one field; expected the spaced second value to fall out as free text", spaced)
		}
	}
}

// twoDisjointSealedProducts finds two products with a nonempty fixed
// decklist that share no card, scanning rather than pinning names so the
// test fails for being wrong instead of for a product having been reprinted
// or delisted. A shared basic land or promo between the first two products
// found is common enough that only taking the first two would make the
// union test flaky, so this checks pairs (capped, since real datastores
// carry thousands of products) until it finds one that is genuinely
// disjoint.
func twoDisjointSealedProducts(t *testing.T) (a, b *mtgmatcher.CardObject) {
	t.Helper()
	type candidate struct {
		co   *mtgmatcher.CardObject
		deck []string
	}
	var candidates []candidate
	for _, code := range backend().GetAllSets() {
		set, err := backend().GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !backend().SealedHasDecklist(code, product.UUID) {
				continue
			}
			deck, err := backend().GetDecklist(code, product.UUID)
			if err != nil || len(deck) == 0 {
				continue
			}
			co, err := backend().GetUUID(product.UUID)
			if err != nil {
				continue
			}
			candidates = append(candidates, candidate{co, deck})
			if len(candidates) >= 60 {
				break
			}
		}
		if len(candidates) >= 60 {
			break
		}
	}

	// clean reports whether a candidate's own contents: search returns
	// exactly its decklist - false for a wrapper product, whose contents:
	// answers with the other sealed products it holds instead of cards
	// (TestAWrapperAnswersWithProductsNotCards). Memoized and checked only
	// for a pair the cheap decklist-disjointness test below already
	// accepted, since a full-datastore search is not free and a pair scan
	// would otherwise repeat it for the same candidate many times over.
	cleanCache := map[string]bool{}
	clean := func(c candidate) bool {
		if v, ok := cleanCache[c.co.UUID]; ok {
			return v
		}
		res, err := searchAndFilter(parseSearchOptionsNG(`contents:"`+c.co.Name+`"`, nil, nil, nil))
		v := err == nil && len(res) == len(c.deck)
		cleanCache[c.co.UUID] = v
		return v
	}

	for i := range candidates {
		for j := i + 1; j < len(candidates); j++ {
			disjoint := true
			for _, c := range candidates[j].deck {
				if slices.Contains(candidates[i].deck, c) {
					disjoint = false
					break
				}
			}
			if !disjoint || !clean(candidates[i]) || !clean(candidates[j]) {
				continue
			}
			return candidates[i].co, candidates[j].co
		}
	}
	return nil, nil
}

// Naming more than one product under contents: is a union, not an
// intersection: a card belongs in the results if it came from any of the
// named products, not only if it came from all of them at once (which, for
// two unrelated products, is normally nobody). Checked against real decklist
// sizes, and a single exact product is checked to still return only its own
// cards.
func TestContentsMultipleExactProductsUnion(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	a, b := twoDisjointSealedProducts(t)
	if a == nil || b == nil {
		t.Skip("this datastore has no two products with disjoint decklists")
	}

	deckA, errA := backend().GetDecklist(a.SetCode, a.UUID)
	deckB, errB := backend().GetDecklist(b.SetCode, b.UUID)
	if errA != nil || errB != nil || len(deckA) == 0 || len(deckB) == 0 {
		t.Skip("decklists unavailable")
	}

	resA, _ := searchAndFilter(parseSearchOptionsNG(`contents:"`+a.Name+`"`, nil, nil, nil))
	resB, _ := searchAndFilter(parseSearchOptionsNG(`contents:"`+b.Name+`"`, nil, nil, nil))
	if len(resA) != len(deckA) || len(resB) != len(deckB) {
		t.Skip("a product's contents: result doesn't line up 1:1 with its raw decklist (a wrapper product)")
	}

	query := `contents:"` + a.Name + `","` + b.Name + `"`
	config := parseSearchOptionsNG(query, nil, nil, nil)
	if config.CleanQuery != "" {
		t.Errorf("leftover free text %q", config.CleanQuery)
	}
	got, err := searchAndFilter(config)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(got) != len(resA)+len(resB) {
		t.Errorf("got %d cards, want the additive union %d (%d + %d)", len(got), len(resA)+len(resB), len(resA), len(resB))
	}

	// A single exact product is unaffected by any of the above: it still
	// returns only its own cards.
	single, _ := searchAndFilter(parseSearchOptionsNG(`contents:"`+a.Name+`"`, nil, nil, nil))
	if len(single) != len(deckA) {
		t.Errorf("a single exact contents: query returned %d cards, want %d", len(single), len(deckA))
	}
}

// A term naming no exact product is read as a product-type search instead:
// every sealed product whose name contains it. Found as a strict partial
// name of a real product rather than a pinned word like "Scene Box", so the
// test doesn't depend on that product line still existing.
func TestContentsSubstringFallsBackToProductType(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var co *mtgmatcher.CardObject
	var term string
	for _, code := range backend().GetAllSets() {
		set, err := backend().GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !backend().SealedHasDecklist(code, product.UUID) {
				continue
			}
			words := strings.Fields(product.Name)
			if len(words) < 2 {
				continue
			}
			candidate := strings.Join(words[1:], " ")
			// Skip a partial name that happens to name an exact product of
			// its own - that isn't the fallback path this test is for.
			if uuid := sealedname2uuid(candidate); uuid != "" {
				continue
			}
			c, err := backend().GetUUID(product.UUID)
			if err != nil {
				continue
			}
			co, term = c, candidate
			break
		}
		if co != nil {
			break
		}
	}
	if co == nil {
		t.Skip("no product name yields an unambiguous partial-name fallback case")
	}

	exact, err := searchAndFilter(parseSearchOptionsNG(`contents:"`+co.Name+`"`, nil, nil, nil))
	if err != nil || len(exact) == 0 {
		t.Skipf("%s finds nothing at all: %v", co.Name, err)
	}
	wide, err := searchAndFilter(parseSearchOptionsNG(`contents:"`+term+`"`, nil, nil, nil))
	if err != nil {
		t.Fatalf("contents:%q: %v", term, err)
	}
	if len(wide) < len(exact) {
		t.Errorf("contents:%q (fallback) found %d cards, want at least the %d the exact product %q has", term, len(wide), len(exact), co.Name)
	}
}
