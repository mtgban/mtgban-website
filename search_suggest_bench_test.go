package main

import "testing"

// BenchmarkSearchSuggestions is the did-you-mean of a misspelled name
// beside filters that keep none of its runner-up names, one of which names
// nothing and so walks the datastore; and of a set or an is: naming
// nothing, which searches once for the printings a rewrite picks from, the
// bare is: over every card.
func BenchmarkSearchSuggestions(b *testing.B) {
	skipWithoutDatastore(b)
	ds := testSite.datastore()
	p := currentPrices()
	for _, q := range []string{"swapm is:plst", "akroma is:ons t:creature", "urza's mine s:atw", "is:riple"} {
		config := parseSearchPage(ds, p, q, false, false, nil, nil, nil)
		b.Run(q, func(b *testing.B) {
			for b.Loop() {
				searchSuggestions(ds, p, q, config, nil, nil, false)
			}
		})
	}
}
