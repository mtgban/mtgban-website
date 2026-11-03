package main

import "testing"

// BenchmarkSearchSuggestions is the did-you-mean of a misspelled name
// beside filters that keep none of its runner-up names, one of which names
// nothing and so walks the datastore.
func BenchmarkSearchSuggestions(b *testing.B) {
	skipWithoutDatastore(b)
	ds := testSite.datastore()
	p := currentPrices()
	for _, q := range []string{"swapm is:plst", "akroma is:ons t:creature"} {
		config := parseSearchPage(ds, p, q, false, false, nil, nil, nil)
		b.Run(q, func(b *testing.B) {
			for b.Loop() {
				searchSuggestions(ds, p, q, config, nil, nil, false)
			}
		})
	}
}
