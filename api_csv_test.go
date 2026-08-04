package main

import (
	"bytes"
	"encoding/csv"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestSimplePrice2CSVTCGSKU checks that an upload export carries the SKU of
// the condition each row was loaded with, and that the price API export (no
// upload data, so no condition either) keeps its original columns.
func TestSimplePrice2CSVTCGSKU(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}

	var id string
	for _, u := range uuids {
		if co, err := mtgmatcher.GetUUID(u); err == nil && !co.Sealed {
			id = u
			break
		}
	}
	if id == "" {
		t.Skip("could not find a suitable card")
	}

	// One SKU per condition, so a wrong condition would pick the wrong one
	inventory := mtgban.InventoryRecord{}
	for cond, sku := range map[string]string{"NM": "111", "SP": "222"} {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: cond, InstanceId: sku})
	}
	prev := scrapersPtr.Load()
	t.Cleanup(func() { scrapersPtr.Store(prev) })
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(
		inventory, mtgban.ScraperInfo{Shorthand: "TCGPlayer"})}
	scrapersPtr.Store(newScraperSnapshot(sellers, GetVendors()))

	pm := map[string]map[string]*BanPrice{
		id: {"TCGPlayer": &BanPrice{Regular: 1.0}},
	}

	header, row := runPrice2CSV(t, pm, []UploadEntry{
		{CardId: id, OriginalCondition: "SP"},
	})
	if header[0] != "UUID" || header[1] != "TCGplayer SKU" {
		t.Fatalf("SKU column is not next to the uuid: %v", header)
	}
	if row[1] != "222" {
		t.Errorf("got SKU %q for a SP row, want 222 (row %v)", row[1], row)
	}

	header, _ = runPrice2CSV(t, pm, nil)
	if slices.Contains(header, "TCGplayer SKU") {
		t.Errorf("price API export grew a SKU column: %v", header)
	}
}

// runPrice2CSV renders one export and returns its header and first data row.
func runPrice2CSV(t *testing.T, pm map[string]map[string]*BanPrice, uploaded []UploadEntry) (header, row []string) {
	t.Helper()

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := SimplePrice2CSV(w, pm, uploaded, nil, false); err != nil {
		t.Fatalf("SimplePrice2CSV: %v", err)
	}
	w.Flush()

	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records (incl header), want 2: %v", len(records), records)
	}
	return records[0], records[1]
}

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
	prev := scrapersPtr.Load()
	t.Cleanup(func() { scrapersPtr.Store(prev) })
	var sellers []mtgban.Seller
	for _, sh := range []string{"TCGPlayer", "TCGDirectLow", "TCGLow", "TCGSealed"} {
		sellers = append(sellers, mtgban.NewSellerFromInventory(
			mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: sh}))
	}
	scrapersPtr.Store(newScraperSnapshot(sellers, GetVendors()))

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
	if err := UUID2TCGCSV(w, ids, qtys, conds); err != nil {
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
