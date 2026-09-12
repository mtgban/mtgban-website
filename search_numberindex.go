package main

import (
	"strings"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// numberIndex accelerates exact collector-number filters. The keys are the
// fields those filters compare, already normalized by the datastore loader.
// No game-specific normalization belongs in this index.
type numberIndex struct {
	loose  map[string][]string
	strict map[string][]string
}

var numberIdx atomic.Pointer[numberIndex]

func buildNumberIndex(b *mtgmatcher.Backend) *numberIndex {
	all := b.GetUUIDs()
	idx := &numberIndex{
		loose:  make(map[string][]string),
		strict: make(map[string][]string),
	}
	for _, uuid := range all {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		loose := strings.ToLower(co.PlainNumber)
		idx.loose[loose] = append(idx.loose[loose], uuid)
		strict := strings.ToLower(co.Number)
		idx.strict[strict] = append(idx.strict[strict], uuid)
	}
	return idx
}
