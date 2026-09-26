package main

import (
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// numbersSnapshot accelerates exact collector-number filters. The keys are
// the fields those filters compare, already normalized by the datastore
// loader. No game-specific normalization belongs in this snapshot.
type numbersSnapshot struct {
	loose  map[string][]string
	strict map[string][]string
}

func newNumbersSnapshot(b *mtgmatcher.Backend) *numbersSnapshot {
	all := b.GetUUIDs()
	numbers := &numbersSnapshot{
		loose:  make(map[string][]string),
		strict: make(map[string][]string),
	}
	for _, uuid := range all {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		loose := strings.ToLower(co.PlainNumber)
		numbers.loose[loose] = append(numbers.loose[loose], uuid)
		strict := strings.ToLower(co.Number)
		numbers.strict[strict] = append(numbers.strict[strict], uuid)
	}
	return numbers
}
