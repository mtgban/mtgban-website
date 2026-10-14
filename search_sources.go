package main

import "github.com/mtgban/go-mtgban/mtgmatcher"

// sourcesSnapshot inverts SourceProducts: for each sealed product, every
// uuid the contents filter would keep for it, read the way the filter reads
// them (cardobject2sources). Built once per load; nil before the first.
type sourcesSnapshot struct {
	byProduct map[string][]string
}

func newSourcesSnapshot(b *mtgmatcher.Backend) *sourcesSnapshot {
	sources := &sourcesSnapshot{byProduct: make(map[string][]string)}
	// The two lists are disjoint: non-sealed and sealed uuids.
	for _, list := range [][]string{b.GetUUIDs(), b.GetSealedUUIDs()} {
		for _, uuid := range list {
			co, err := b.GetUUID(uuid)
			if err != nil {
				continue
			}
			for _, product := range cardobject2sources(co) {
				sources.byProduct[product] = append(sources.byProduct[product], co.UUID)
			}
		}
	}
	return sources
}
