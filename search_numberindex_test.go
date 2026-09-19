package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestNumberIndexMatchesScan pins the index to the scan it stands in for. A
// key spelled one way and a query the other does not raise anything: the
// search simply finds nothing and reads as "no such card", so the agreement
// is worth asserting rather than assuming.
func TestNumberIndexMatchesScan(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("Need a datastore loaded to run this test")
	}
	previous := numberIdx.Load()
	t.Cleanup(func() { numberIdx.Store(previous) })
	numberIdx.Store(buildNumberIndex(backend()))

	for _, tt := range []struct {
		query, filter string
	}{
		{"cn:635", "number"},
		{"cn:1", "number"},
		{"cn:107", "number"},
		{"cns:107★", "number_strict"},
		{"cn:21", "number"},
		{"cn:0042", "number"},
		{"cn:635,635", "number"},
		{"cn:999999999", "number"},
	} {
		t.Run(tt.query, func(t *testing.T) {
			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			seeded, ok := numberSeedUUIDs(config.CardFilters)
			if !ok {
				t.Fatalf("%s did not seed", tt.query)
			}
			// The scan the seed replaces: every uuid, same filters.
			scanned := filterUUIDs(backend().GetUUIDs(), config.CardFilters)
			got := filterUUIDs(seeded, config.CardFilters)

			slices.Sort(got)
			slices.Sort(scanned)
			if !slices.Equal(got, scanned) {
				t.Errorf("%s: seed gave %d uuids, scan gave %d", tt.query, len(got), len(scanned))
			}
		})
	}
}

// TestNumberSeedDeclines pins the shapes that do not bound the result set, and
// so must keep scanning rather than seed a wrong answer.
func TestNumberSeedDeclines(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("Need a datastore loaded to run this test")
	}
	previous := numberIdx.Load()
	t.Cleanup(func() { numberIdx.Store(previous) })
	numberIdx.Store(buildNumberIndex(backend()))

	for _, query := range []string{
		"-cn:635",    // names what to leave out
		"cn:SLD:635", // scoped, so every card outside the scope passes
		"cn:1-10",    // a range, which names no key
		"cne:^6.5$",  // a pattern, which names no key
	} {
		t.Run(query, func(t *testing.T) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			if _, ok := numberSeedUUIDs(config.CardFilters); ok {
				t.Errorf("%s seeded, but it does not bound the result set", query)
			}
		})
	}
}

func TestNumberIndexKeepsStoredForms(t *testing.T) {
	b := &mtgmatcher.Backend{
		AllUUIDs: []string{"card"},
		UUIDs:    map[string]*mtgmatcher.CardObject{"card": {Card: mtgmatcher.Card{UUID: "card", Number: "021★", PlainNumber: "21"}}},
	}
	idx := buildNumberIndex(b)
	if !slices.Equal(idx.loose["21"], []string{"card"}) || !slices.Equal(idx.strict["021★"], []string{"card"}) {
		t.Fatal("index did not retain the stored plain and printed numbers")
	}
	if len(idx.strict["21★"]) != 0 || len(idx.strict["21"]) != 0 {
		t.Fatal("strict index normalized the printed number")
	}
}

func TestNumberSearchMatchesUnseededSearch(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("Need a datastore")
	}
	previous := numberIdx.Load()
	t.Cleanup(func() { numberIdx.Store(previous) })
	idx := buildNumberIndex(backend())
	for _, query := range []string{"cn:635", "cn:635,635", "cn:999999999", "cns:107★", "cn:635 -s:SLD", "-cn:635", "cn:SLD:635", "cn:1-10", "cne:^6.5$", "s:LEA cn:999999999"} {
		t.Run(query, func(t *testing.T) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			numberIdx.Store(nil)
			want, wantErr := searchAndFilter(config)
			numberIdx.Store(idx)
			got, gotErr := searchAndFilter(config)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("seeded returned %d results (%v), unseeded %d (%v)", len(got), gotErr, len(want), wantErr)
			}
		})
	}
}

// BenchmarkNumberIndexSearch measures the same request path with the index
// disabled and enabled, after first checking that the result sets agree.
func BenchmarkNumberIndexSearch(b *testing.B) {
	if len(backend().GetUUIDs()) == 0 {
		b.Skip("Need a datastore")
	}
	previous := numberIdx.Load()
	b.Cleanup(func() { numberIdx.Store(previous) })
	idx := buildNumberIndex(backend())
	for _, query := range []string{"cn:635", "cn:161", "cns:107★"} {
		config := parseSearchOptionsNG(query, nil, nil, nil)
		numberIdx.Store(nil)
		scanned, err := searchAndFilter(config)
		if err != nil {
			b.Fatal(err)
		}
		numberIdx.Store(idx)
		indexed, err := searchAndFilter(config)
		if err != nil {
			b.Fatal(err)
		}
		slices.Sort(scanned)
		slices.Sort(indexed)
		if !slices.Equal(scanned, indexed) {
			b.Fatalf("%s: indexed and scanned results differ", query)
		}
		b.Logf("%s: %d identical results", query, len(indexed))
		for _, mode := range []string{"scan", "index"} {
			b.Run(query+"/"+mode, func(b *testing.B) {
				numberIdx.Store(nil)
				if mode == "index" {
					numberIdx.Store(idx)
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := searchAndFilter(config); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkNumberIndexBuild(b *testing.B) {
	backend := backend()
	if len(backend.GetUUIDs()) == 0 {
		b.Skip("Need a datastore")
	}
	b.ReportAllocs()
	for b.Loop() {
		if buildNumberIndex(backend) == nil {
			b.Fatal("missing index")
		}
	}
}
