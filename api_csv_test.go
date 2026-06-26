package main

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestUUID2TCGCSVCondQtyIndexing checks that a repeated id with different
// conditions produces one row per (id, condition) with the right condition and
// quantity — the case the old deduped-index code got wrong.
func TestUUID2TCGCSVCondQtyIndexing(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}

	// Inject empty TCG sellers so the inventory lookups in UUID2TCGCSV succeed
	// (prices come out 0, which is fine — we only assert condition/quantity).
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	var sellers []mtgban.Seller
	for _, sh := range []string{"TCGPlayer", "TCGDirectLow", "TCGLow", "TCGSealed"} {
		sellers = append(sellers, mtgban.NewSellerFromInventory(
			mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: sh}))
	}
	sellersPtr.Store(&sellers)

	// Two distinct non-foil, non-sealed cards so condition codes map cleanly to
	// labels (no " Foil" suffix) and Rarity is present.
	var a, b string
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
		if err != nil || co.Sealed || co.Foil || co.Etched || co.Rarity == "" {
			continue
		}
		if a == "" {
			a = u
		} else if u != a {
			b = u
			break
		}
	}
	if a == "" || b == "" {
		t.Skip("could not find two suitable cards")
	}

	// id A appears twice with different conditions, B once.
	ids := []string{a, a, b}
	conds := []string{"NM", "SP", "MP"}
	qtys := []string{"1", "2", "3"}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := UUID2TCGCSV(w, ids, qtys, conds, false); err != nil {
		t.Fatalf("UUID2TCGCSV: %v", err)
	}
	w.Flush()

	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 4 { // header + 3 data rows
		t.Fatalf("got %d records (incl header), want 4: %v", len(records), records)
	}

	const condCol, qtyCol = 7, 13
	got := map[[2]string]bool{}
	for _, r := range records[1:] {
		got[[2]string{r[condCol], r[qtyCol]}] = true
	}
	for _, want := range [][2]string{
		{"Near Mint", "1"},
		{"Lightly Played", "2"},
		{"Moderately Played", "3"},
	} {
		if !got[want] {
			t.Errorf("missing row condition=%q qty=%q; got rows %v", want[0], want[1], got)
		}
	}
}
