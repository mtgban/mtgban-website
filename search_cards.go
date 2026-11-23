package main

import "github.com/mtgban/go-mtgban/mtgban"

// edgeOffer is the offer a Cards slide names at its edge for one side of a
// card: the first priced, unlocked offer of the first grade that has one,
// grades best first and rows as the search ranked them. Nil when none has.
func edgeOffer(found map[mtgban.Condition][]SearchEntry) *SearchEntry {
	for _, grade := range AllConditions {
		if grade == "INDEX" {
			continue
		}
		entries := found[grade]
		for i := range entries {
			if !entries[i].Locked && entries[i].IsOffer() && entries[i].Price > 0 {
				return &entries[i]
			}
		}
	}
	return nil
}
