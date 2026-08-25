package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// firstPlainCard returns a nonfoil single to hang the price entries on.
func firstPlainCard(t *testing.T) string {
	t.Helper()
	for _, id := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(id)
		if err == nil && !co.Sealed && !co.Foil && !co.Etched {
			return id
		}
	}
	t.Skip("no datastore")
	return ""
}

// An index quotes one number for a printing, filed under whatever condition
// string its source uses. Asking it for the grade a row was uploaded at finds
// nothing and blanks the column - which is why an upload carrying MP rows lost
// its TCG Low prices while the NM rows kept theirs (the "spotty" shape: an
// index filing under NM answers NM and nothing else).
func TestIndexPriceIgnoresRowCondition(t *testing.T) {
	cardId := firstPlainCard(t)

	for _, indexCond := range []string{"NM", "INDEX"} {
		out := map[string]map[string]*BanPrice{}
		processEntry(out, []mtgban.InventoryEntry{{Conditions: indexCond, Price: 4.20}},
			"", cardId, "TCGLow", false, true /* conds */, false /* shouldBaseCond: an index */)
		price := out[cardId]["TCGLow"]

		// Every grade gets the one price the index carries, including the
		// grades it files nothing under.
		for _, row := range []string{"", "NM", "SP", "MP", "HP", "PO"} {
			if got := getPrice(price, row); got != 4.20 {
				t.Errorf("index filing under %q, row %q: got %v, want the flat 4.20", indexCond, row, got)
			}
		}
	}
}

// A real store among the index keys does list a price per grade, so it keeps
// the row's condition: answering an MP row with the NM price would overstate
// what is actually for sale.
func TestRealStoreKeepsRowCondition(t *testing.T) {
	cardId := firstPlainCard(t)

	out := map[string]map[string]*BanPrice{}
	processEntry(out, []mtgban.InventoryEntry{
		{Conditions: "NM", Price: 10.00, Quantity: 1},
		{Conditions: "SP", Price: 7.00, Quantity: 1},
	}, "", cardId, "TCGDirect", false, true /* conds */, true /* shouldBaseCond: a real store */)
	price := out[cardId]["TCGDirect"]

	for _, tc := range []struct {
		cond string
		want float64
	}{
		{"NM", 10.00},
		{"SP", 7.00},
		{"MP", 0}, // not stocked in that grade, and that is the true answer
	} {
		if got := getPrice(price, tc.cond); got != tc.want {
			t.Errorf("store, row %q: got %v, want %v", tc.cond, got, tc.want)
		}
	}
}

// The set the fix keys on: every loaded index, and nothing else.
func TestFlatPriceSourcesAreTheIndexes(t *testing.T) {
	var flat, priced int
	for _, seller := range GetSellers() {
		if seller == nil {
			continue
		}
		if seller.Info().MetadataOnly {
			flat++
		} else {
			priced++
		}
	}
	if flat+priced == 0 {
		t.Skip("no scrapers loaded")
	}
	t.Logf("loaded scrapers: %d flat (index), %d with per-grade prices", flat, priced)
}
