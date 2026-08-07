package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// benchCards returns a fixed prefix of the uuid index. Load sorts that
// index, so every run measures the same cards in the same order.
func benchCards(b *testing.B, n int) []string {
	all := mtgmatcher.GetUUIDs()
	if len(all) == 0 {
		b.Skip("datastore not loaded")
	}
	return all[:min(n, len(all))]
}

// keptCards holds the escaping benchmark's result past the iteration that
// produced it, so the lookups below cannot be optimised away.
var keptCards []*mtgmatcher.CardObject

// The lookup on its own: the price every card-driven page pays per card.
func BenchmarkGetUUID(b *testing.B) {
	uuids := benchCards(b, 10000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		co, err := mtgmatcher.GetUUID(uuids[i%len(uuids)])
		if err != nil {
			b.Fatal(err)
		}
		if co.UUID == "" {
			b.Fatal("empty card")
		}
	}
}

// The same lookup where the result outlives the call. This is the shape
// anything collecting cards has - page data, a filter fed through an
// interface - and the one that used to allocate a copy per card, so it
// separates the copy cost from the escape cost.
func BenchmarkGetUUIDEscaping(b *testing.B) {
	uuids := benchCards(b, 10000)
	const pageSize = 60
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kept := make([]*mtgmatcher.CardObject, 0, pageSize)
		for j := 0; j < pageSize; j++ {
			co, err := mtgmatcher.GetUUID(uuids[(i*pageSize+j)%len(uuids)])
			if err != nil {
				continue
			}
			kept = append(kept, co)
		}
		if len(kept) == 0 {
			b.Fatal("no cards kept")
		}
		keptCards = kept
	}
}

// uuid2card renders one card tile, and runs once per result on a page.
func BenchmarkUUID2Card(b *testing.B) {
	uuids := benchCards(b, 10000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uuid2card(uuids[i%len(uuids)], false, false, false)
	}
}

// searchAndFilter walks the candidate pool looking up every card it
// tests, which makes it the heaviest datastore consumer the site has.
// The three queries cover the seeding paths it can take: a filter with
// no index behind it, an edition filter served from the set index, and a
// numeric comparison over the whole pool.
func BenchmarkSearchAndFilter(b *testing.B) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		b.Skip("datastore not loaded")
	}
	for _, query := range []string{"r:mythic", "s:MH2", "cn>300"} {
		b.Run(query, func(b *testing.B) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out, err := searchAndFilter(config)
				if err != nil {
					b.Fatal(err)
				}
				if len(out) == 0 {
					b.Fatalf("%s returned nothing", query)
				}
			}
		})
	}
}
