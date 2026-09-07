package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A card duplicated for its language keeps the plain number in OriginalNumber
// and prints the tagged one in Number. Searching either has to find it: the
// plain number is what a person types, the tagged one is what the results
// carry in data-number and what a favorite rebuilds its query from.
func TestTheNumberSearchTakesTheTagACardPrints(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}

	for _, tt := range []struct {
		query string
		want  int
	}{
		// SLD 1116 is printed in English and Japanese, each nonfoil + etched.
		{"Plaguecrafter s:SLD cn:1116", 4},
		{"Plaguecrafter s:SLD cn:1116jpn", 2},
		{"Plaguecrafter s:SLD cn:1116jpn f:nonfoil", 1},
		// The strict form still means exactly what it meant.
		{"Plaguecrafter s:SLD cns:1116jpn", 2},
		{"Plaguecrafter s:SLD cns:1116", 2},
	} {
		uuids, err := searchAndFilter(parseSearchOptionsWrapper(tt.query))
		if err != nil {
			t.Errorf("%q: %s", tt.query, err)
			continue
		}
		if len(uuids) != tt.want {
			t.Errorf("%q found %d printings, want %d", tt.query, len(uuids), tt.want)
		}
	}
}

// Every printing whose Number carries a tag has to be reachable by that
// Number, because that is the number the site itself puts in a link.
func TestEveryTaggedNumberFindsItsOwnCard(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}

	var checked, missed int
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, card := range set.Cards {
			if card.Number == card.OriginalNumber {
				continue
			}
			co, err := mtgmatcher.GetUUID(card.UUID)
			if err != nil {
				continue
			}
			checked++
			filters := fixupNumberNG(card.Number, false)
			if cardFilterNumber(filters, co) {
				missed++
				if missed < 5 {
					t.Errorf("cn:%s cannot find %s (%s), whose number it is", card.Number, card.Name, code)
				}
			}
		}
	}
	if checked == 0 {
		t.Skip("no tagged numbers in this datastore")
	}
	if missed != 0 {
		t.Errorf("%d of %d tagged printings are unreachable by their own number", missed, checked)
	}
	t.Logf("%d tagged printings, all reachable by their own number", checked)
}
