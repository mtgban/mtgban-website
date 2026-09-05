package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The finishes a card is sold under are the matcher's answer, not a pair of
// names: asking for the foil and the etched by name missed a foil's own
// nonfoil, a game's own finishes, and the sets that file a foil as a card of
// its own. Every printing in the datastore is checked against that pair, which
// this must never contradict — only extend.
func TestAddFinishVariantsNeverContradictsTheFoilPair(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("no datastore loaded")
	}

	var extended int
	for _, id := range uuids {
		got := addFinishVariants(nil, id)

		// What asking by name used to answer.
		foilID, _ := mtgmatcher.MatchID(id, true)
		etchedID, _ := mtgmatcher.MatchID(id, false, true)
		for _, want := range []string{foilID, etchedID} {
			if want == "" || want == id {
				continue
			}
			if !slices.Contains(got, want) {
				t.Fatalf("%s: dropped the %s sibling the foil pair found", id, want)
			}
		}
		if slices.Contains(got, id) {
			t.Fatalf("%s: listed itself as its own variant", id)
		}
		if len(got) > 0 {
			extended++
		}
	}
	t.Logf("%d of %d printings have at least one other finish", extended, len(uuids))
}

// A foil is given its nonfoil, which asking for "the foil of this" never was.
func TestAddFinishVariantsWalksBackFromAFoil(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("no datastore loaded")
	}

	for _, id := range uuids {
		if !strings.HasSuffix(id, "_f") {
			continue
		}
		base := strings.TrimSuffix(id, "_f")
		if _, err := mtgmatcher.GetUUID(base); err != nil {
			continue
		}
		if !slices.Contains(addFinishVariants(nil, id), base) {
			t.Fatalf("%s was not offered its nonfoil %s", id, base)
		}
		return
	}
	t.Skip("no foil printing with a nonfoil sibling in this datastore")
}
