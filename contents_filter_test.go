package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A contents: or variable: query that names no product has nothing to be the
// contents of. Left as an empty filter it matched every card there is, and
// variable: on a product with nothing guaranteed left no filter at all - both
// answered a typo with the whole datastore.
func TestContentsOfNothingIsNothing(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
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
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if mtgmatcher.SealedIsRandom(code, product.UUID) && !mtgmatcher.SealedHasDecklist(code, product.UUID) {
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
}
