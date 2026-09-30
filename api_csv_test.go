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
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

	var id string
	for _, u := range uuids {
		if co, err := backend().GetUUID(u); err == nil && !co.Sealed {
			id = u
			break
		}
	}
	if id == "" {
		t.Skip("could not find a suitable card")
	}

	// One SKU per condition, so a wrong condition would pick the wrong one
	inventory := mtgban.InventoryRecord{}
	for cond, sku := range map[mtgban.Condition]string{mtgban.NM: "111", mtgban.SP: "222"} {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: cond, InstanceID: sku})
	}
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(
		inventory, mtgban.ScraperInfo{Shorthand: "TCGPlayer"})}
	sellersPtr.Store(&sellers)

	pm := map[string]map[string]*BanPrice{
		id: {"TCGPlayer": &BanPrice{Regular: 1.0}},
	}

	header, row := runPrice2CSV(t, pm, []UploadEntry{
		{CardID: id, OriginalCondition: "SP"},
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
	if err := SimplePrice2CSV(backend(), w, pm, uploaded, nil, false); err != nil {
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

// TestCSVCondQtyIndexing checks that a repeated id with different conditions
// produces one row per (id, condition) in the TCG and MKM exports, with the
// right condition and quantity.
func TestCSVCondQtyIndexing(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

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
		co, err := backend().GetUUID(u)
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

	for _, tc := range []struct {
		export          func(*mtgmatcher.Backend, *csv.Writer, []string, []string, []string) error
		condCol, qtyCol int
		labels          map[mtgban.Condition]string
	}{
		{UUID2TCGCSV, 7, 13, tcgConditionMap},
		{UUID2MKMCSV, 6, 1, mkmConditionMap},
	} {
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		err := tc.export(backend(), w, ids, qtys, conds)
		if err != nil {
			t.Fatal(err)
		}
		w.Flush()

		records, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatalf("parse csv: %v", err)
		}
		if len(records) != 4 { // header + 3 data rows
			t.Fatalf("got %d records (incl header), want 4: %v", len(records), records)
		}

		got := map[[2]string]bool{}
		for _, r := range records[1:] {
			got[[2]string{r[tc.condCol], r[tc.qtyCol]}] = true
		}
		for i, cond := range conds {
			want := [2]string{tc.labels[mtgban.Condition(cond)], qtys[i]}
			if !got[want] {
				t.Errorf("%s: missing row condition=%q qty=%q; got rows %v", records[0][0], want[0], want[1], got)
			}
		}
	}
}

// The CK and SCG exports write a row per id the vendor buys, from its first
// buylist entry; CK also skips a card with no CK title. A quantity of "0",
// or quantities not matching the ids, reads as 1.
func TestUUID2BuylistCSV(t *testing.T) {
	prev := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prev) })
	ck := mtgban.BuylistRecord{
		"a": {{CustomFields: map[string]string{"CKTitle": "A", "CKEdition": "Set", "CKFoil": "true"}}},
		"b": {{CustomFields: map[string]string{"CKEdition": "Set"}}},
	}
	scg := mtgban.BuylistRecord{
		"a": {{InstanceID: "1", CustomFields: map[string]string{
			"SCGName": "A", "SCGEdition": "Set", "SCGLanguage": "en", "SCGFinish": "foil"}}},
		"b": {{InstanceID: "2"}},
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Shorthand: "CK"}),
		mtgban.NewVendorFromBuylist(scg, mtgban.ScraperInfo{Shorthand: "SCG"}),
	}
	vendorsPtr.Store(&vendors)

	ids := []string{"a", "b", "c", "a"}
	for _, tc := range []struct {
		export func(*csv.Writer, []string, []string) error
		qtys   []string
		want   string
	}{
		{UUID2CKCSV, []string{"3", "2", "1", "0"}, "Title,Edition,Foil,Quantity\nA,Set,true,3\nA,Set,true,1\n"},
		{UUID2CKCSV, []string{"3"}, "Title,Edition,Foil,Quantity\nA,Set,true,1\nA,Set,true,1\n"},
		{UUID2SCGCSV, []string{"3", "2", "1", "0"}, "quantity,productid,name,set_name,language,finish\n3,1,A,Set,en,foil\n2,2,,,,\n1,1,A,Set,en,foil\n"},
		{UUID2SCGCSV, nil, "quantity,productid,name,set_name,language,finish\n1,1,A,Set,en,foil\n1,2,,,,\n1,1,A,Set,en,foil\n"},
	} {
		var buf bytes.Buffer
		err := tc.export(csv.NewWriter(&buf), ids, tc.qtys)
		if err != nil {
			t.Fatal(err)
		}
		if buf.String() != tc.want {
			t.Errorf("qtys %q: got\n%s\nwant\n%s", tc.qtys, buf.String(), tc.want)
		}
	}
}
