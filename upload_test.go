package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/moxfield"
)

// The mtgban inventory/cart CSV export must round-trip through the uploader:
// the Key column resolves directly by uuid, and with no usable id the sealed
// name fallback must handle punctuation loss and parenthesized variants.
// Relies on the datastore loaded in TestMain, which is why it lives here
// rather than in internal/docparse.
func TestUploadSealedCSV(t *testing.T) {
	if len(mtgmatcher.GetSealedUUIDs()) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}

	header := []string{"Key", "Name", "Edition", "Finish", "Number", "Rarity", "Conditions", "Price", "Quantity", "URL", "Seller", "Bundle", "Original Id", "Instance Id"}
	indexMap, err := uploadParser.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if idx, found := indexMap["id"]; !found || idx != 0 {
		t.Fatalf("Key column not mapped to id: %v", indexMap)
	}

	rows := [][]string{
		{"9e295ba4-a378-5259-8ba9-5a67ead6d17f", "Champions of Kamigawa Fat Pack", "Champions of Kamigawa", "sealed", "", "product", "NM", "368.58", "4", "url", "", "", "116082", "750831"},
		{"48ff4766-9d88-5426-800a-1613c990011b", "Mystery Booster Booster Box (Convention Edition)", "Mystery Booster", "sealed", "", "product", "NM", "15.36", "150", "url", "", "", "101685", "659571"},
		{"96772e6d-0aba-5362-ab10-d5f3f6d23634", "Urzas Saga Tournament Pack", "Urza's Saga", "sealed", "", "product", "NM", "645.01", "70", "url", "", "", "23679", "159742"},
	}

	// Path 1: resolve via the Key uuid
	for _, row := range rows {
		if _, err := mtgmatcher.GetUUID(row[0]); err != nil {
			t.Logf("uuid %s not in local datastore, skipping id check", row[0])
			continue
		}
		res, err := uploadParser.ParseRow(indexMap, append([]string{}, row...))
		if err != nil {
			t.Fatalf("ParseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("id path %q: MismatchError = %v", row[1], res.MismatchError)
		}
		if res.CardId == "" {
			t.Errorf("id path %q: empty CardId", row[1])
		}
	}

	// Path 2: blank the Key so the sealed-name fallback has to do the work
	for _, row := range rows {
		nameOnly := append([]string{}, row...)
		nameOnly[0] = ""
		res, err := uploadParser.ParseRow(indexMap, nameOnly)
		if err != nil {
			t.Fatalf("ParseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("name path %q: MismatchError = %v", row[1], res.MismatchError)
			continue
		}
		if res.CardId == "" {
			t.Errorf("name path %q: empty CardId", row[1])
			continue
		}
		co, err := mtgmatcher.GetUUID(res.CardId)
		if err != nil || !co.Sealed {
			t.Errorf("name path %q: resolved to non-sealed %q", row[1], res.CardId)
		}
		t.Logf("name path %q -> %s (%s)", row[1], res.CardId, co.Name)
	}
}

// Deck per-copy printings arrive as set+number instead of a scryfall id;
// they must resolve to the exact printing with the finish applied, so
// mixed-printing decks don't collapse into one variation.
func TestResolveMoxItemPrinting(t *testing.T) {
	if _, err := mtgmatcher.GetSet("UNF"); err != nil {
		t.Skip("datastore not loaded")
	}

	check := func(item moxfield.Item, wantNumber string, wantFoil bool) string {
		t.Helper()
		cardId, err := resolveMoxItem(item)
		if err != nil {
			t.Fatalf("resolve %+v: %s", item, err)
		}
		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			t.Fatal(err)
		}
		if co.SetCode != "UNF" || co.Number != wantNumber || co.Foil != wantFoil {
			t.Errorf("resolved to %s %s foil=%v, want UNF %s foil=%v",
				co.SetCode, co.Number, co.Foil, wantNumber, wantFoil)
		}
		return cardId
	}

	// The galaxy-foil printing is its own collector number
	check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "487", IsFoil: true}, "487", true)

	// Same number, different finishes stay distinct
	regular := check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "236"}, "236", false)
	foil := check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "236", IsFoil: true}, "236", true)
	if regular == foil {
		t.Error("foil and nonfoil of the same printing should resolve to different uuids")
	}

	// Unknown printings surface a mismatch error instead of a silent match
	if _, err := resolveMoxItem(moxfield.Item{Name: "Island", SetCode: "unf", Number: "9999"}); err == nil {
		t.Error("unknown collector number should error")
	}
}
