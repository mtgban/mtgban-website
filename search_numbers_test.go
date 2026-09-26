package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestNumbersSnapshotMatchesScan pins the snapshot to the scan it stands in
// for. A key spelled one way and a query the other does not raise anything:
// the search simply finds nothing and reads as "no such card", so the
// agreement is worth asserting rather than assuming.
func TestNumbersSnapshotMatchesScan(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("Need a datastore loaded to run this test")
	}
	numbers := newNumbersSnapshot(backend())

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
			seeded, ok := numberSeedUUIDs(numbers, config.CardFilters)
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
	numbers := newNumbersSnapshot(backend())

	for _, query := range []string{
		"-cn:635",    // names what to leave out
		"cn:SLD:635", // scoped, so every card outside the scope passes
		"cn:1-10",    // a range, which names no key
		"cne:^6.5$",  // a pattern, which names no key
	} {
		t.Run(query, func(t *testing.T) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			_, ok := numberSeedUUIDs(numbers, config.CardFilters)
			if ok {
				t.Errorf("%s seeded, but it does not bound the result set", query)
			}
		})
	}
}

func TestNumbersSnapshotKeepsStoredForms(t *testing.T) {
	b := &mtgmatcher.Backend{
		AllUUIDs: []string{"card"},
		UUIDs:    map[string]*mtgmatcher.CardObject{"card": {Card: mtgmatcher.Card{UUID: "card", Number: "021★", PlainNumber: "21"}}},
	}
	numbers := newNumbersSnapshot(b)
	if !slices.Equal(numbers.loose["21"], []string{"card"}) || !slices.Equal(numbers.strict["021★"], []string{"card"}) {
		t.Fatal("snapshot did not retain the stored plain and printed numbers")
	}
	if len(numbers.strict["21★"]) != 0 || len(numbers.strict["21"]) != 0 {
		t.Fatal("strict snapshot normalized the printed number")
	}
}

// TestNumberSearchMatchesUnseededSearch publishes a copy of the live
// datastore with numbers disabled, then the live datastore itself (whose
// numbers newDatastore already built), so searchAndFilter sees each in turn
// through currentDatastore() the way a request would.
func TestNumberSearchMatchesUnseededSearch(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("Need a datastore")
	}
	base := currentDatastore()
	withoutNumbers := *base
	withoutNumbers.numbers = nil

	for _, query := range []string{"cn:635", "cn:635,635", "cn:999999999", "cns:107★", "cn:635 -s:SLD", "-cn:635", "cn:SLD:635", "cn:1-10", "cne:^6.5$", "s:LEA cn:999999999"} {
		t.Run(query, func(t *testing.T) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			useDatastore(t, &withoutNumbers)
			want, wantErr := searchAndFilter(config)
			useDatastore(t, base)
			got, gotErr := searchAndFilter(config)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("seeded returned %d results (%v), unseeded %d (%v)", len(got), gotErr, len(want), wantErr)
			}
		})
	}
}

// BenchmarkNumbersSnapshotSearch measures the same request path with the
// snapshot disabled and enabled, after first checking that the result sets
// agree.
func BenchmarkNumbersSnapshotSearch(b *testing.B) {
	if len(backend().GetUUIDs()) == 0 {
		b.Skip("Need a datastore")
	}
	base := currentDatastore()
	withoutNumbers := *base
	withoutNumbers.numbers = nil

	for _, query := range []string{"cn:635", "cn:161", "cns:107★"} {
		config := parseSearchOptionsNG(query, nil, nil, nil)
		useDatastore(b, &withoutNumbers)
		scanned, err := searchAndFilter(config)
		if err != nil {
			b.Fatal(err)
		}
		useDatastore(b, base)
		seeded, err := searchAndFilter(config)
		if err != nil {
			b.Fatal(err)
		}
		slices.Sort(scanned)
		slices.Sort(seeded)
		if !slices.Equal(scanned, seeded) {
			b.Fatalf("%s: seeded and scanned results differ", query)
		}
		b.Logf("%s: %d identical results", query, len(seeded))
		for _, mode := range []string{"scan", "seeded"} {
			b.Run(query+"/"+mode, func(b *testing.B) {
				ds := &withoutNumbers
				if mode == "seeded" {
					ds = base
				}
				useDatastore(b, ds)
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

func BenchmarkNumbersSnapshotBuild(b *testing.B) {
	backend := backend()
	if len(backend.GetUUIDs()) == 0 {
		b.Skip("Need a datastore")
	}
	b.ReportAllocs()
	for b.Loop() {
		if newNumbersSnapshot(backend) == nil {
			b.Fatal("missing snapshot")
		}
	}
}
