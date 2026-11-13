package main

import (
	"bytes"
	"encoding/csv"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
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
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(
		inventory, mtgban.ScraperInfo{Shorthand: "TCGPlayer"})}
	withPrices(t, sellers, currentPrices().vendors)

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
	if err := SimplePrice2CSV(backend(), currentPrices(), w, pm, uploaded, nil, false); err != nil {
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
	var sellers []mtgban.Seller
	for _, sh := range []string{"TCGPlayer", "TCGDirectLow", "TCGLow", "TCGSealed"} {
		sellers = append(sellers, mtgban.NewSellerFromInventory(
			mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: sh}))
	}
	withPrices(t, sellers, currentPrices().vendors)

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
		export          func(*matcher.Backend, *prices, *csv.Writer, []string, []string, []string) error
		condCol, qtyCol int
		labels          map[mtgban.Condition]string
	}{
		{UUID2TCGCSV, 7, 13, tcgConditionMap},
		{UUID2MKMCSV, 6, 1, mkmConditionMap},
	} {
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		err := tc.export(backend(), currentPrices(), w, ids, qtys, conds)
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

// decklistCSVFixture is a backend and prices both marketplace exports can write from.
func decklistCSVFixture(t *testing.T) (*matcher.Backend, *prices) {
	t.Helper()
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{
		{"Fixture Card Alpha", "1"}, {"Fixture, Card \"Beta\"", "2"},
	})
	b.UUIDs["FIXTUREA-1"].Edition, b.UUIDs["FIXTUREA-1"].Rarity, b.UUIDs["FIXTUREA-1"].Language = "Fixture Edition Alpha", "rare", "English"
	b.UUIDs["FIXTUREA-2"].Foil = true
	inventory := func(entries map[string][]mtgban.InventoryEntry) mtgban.InventoryRecord {
		out := mtgban.InventoryRecord{}
		for id, list := range entries {
			for i := range list {
				out.Add(id, &list[i])
			}
		}
		return out
	}
	seller := func(shorthand string, entries map[string][]mtgban.InventoryEntry) mtgban.Seller {
		return mtgban.NewSellerFromInventory(inventory(entries), mtgban.ScraperInfo{Shorthand: shorthand})
	}
	s := fixtureSite(t, b, []mtgban.Seller{
		seller("TCGPlayer", map[string][]mtgban.InventoryEntry{
			"FIXTUREA-1": {{Conditions: "NM", Price: 1.5, InstanceID: "111"}, {Conditions: "SP", Price: 1.25, InstanceID: "112"}},
			"FIXTUREA-2": {{Conditions: "SP", Price: 7, InstanceID: "222"}},
		}),
		seller("TCGDirectLow", map[string][]mtgban.InventoryEntry{"FIXTUREA-1": {{Conditions: "NM", Price: 1.4}}}),
		seller("TCGLow", map[string][]mtgban.InventoryEntry{"FIXTUREA-1": {{Conditions: "NM", Price: 1.1, OriginalID: "9001"}}}),
		seller("TCGSealed", nil),
		seller("MKMTrend", map[string][]mtgban.InventoryEntry{"FIXTUREA-1": {{Conditions: "NM", Price: 0.9, OriginalID: "5001"}}}),
		seller("MKMLow", map[string][]mtgban.InventoryEntry{"FIXTUREA-2": {{Conditions: "NM", Price: 3.3, OriginalID: "5002"}}}),
	}, nil)
	return b, s.prices()
}

// What each marketplace export writes, unchanged by the flush at its end.
func TestDecklistCSVBytes(t *testing.T) {
	b, p := decklistCSVFixture(t)
	ids := []string{"FIXTUREA-1", "FIXTUREA-2", "nope", "FIXTUREA-1", "FIXTUREA-1"}
	qtys := []string{"1", "2", "1", "3", "x"}
	conds := []string{"NM", "SP", "NM", "NM", "SP"}
	// Captured from the exports before they flushed and checked at their end.
	for _, c := range []struct {
		name   string
		export decklistExport
		want   string
	}{
		{"tcgplayer", UUID2TCGCSV, "TCGplayer Id,Product Line,Set Name,Product Name,Title,Number,Rarity,Condition,TCG Market Price,TCG Direct Low,TCG Low Price With Shipping,TCG Low Price,Total Quantity,Add to Quantity,TCG Marketplace Price,Photo URL\n" +
			"111,,,,,,,Near Mint,1.50,1.40,,1.10,,4,1.50,\n" +
			"222,,,,,,,Lightly Played Foil,7.00,0.00,,0.00,,2,7.00,\n" +
			"112,,,,,,,Lightly Played,1.25,0.00,,0.00,,1,1.25,\n"},
		{"cardmarket", UUID2MKMCSV, "cardmarketId,quantity,name,set,setCode,cn,condition,language,isFoil,isPlayset,isSigned,price,comment,nameDE,nameES,nameFR,nameIT,rarity,listedAt\n" +
			"5001,4,Fixture Card Alpha,Fixture Edition Alpha,FIXTUREA,1,NM,English,,,,0.90,,,,,,Rare,\n" +
			"5002,2,\"Fixture, Card \"\"Beta\"\"\",,FIXTUREA,2,EX,,Y,,,3.30,,,,,,,\n" +
			"5001,1,Fixture Card Alpha,Fixture Edition Alpha,FIXTUREA,1,EX,English,,,,0.90,,,,,,Rare,\n"},
	} {
		var buf bytes.Buffer
		if err := c.export(b, p, csv.NewWriter(&buf), ids, qtys, conds); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// No flush here: the client gets only what the export itself flushed.
		if buf.String() != c.want {
			t.Errorf("%s: got\n%q\nwant\n%q", c.name, buf.String(), c.want)
		}

		// A list with no card now reaches the client as its header row.
		buf.Reset()
		if err := c.export(b, p, csv.NewWriter(&buf), nil, nil, nil); err != nil {
			t.Fatalf("%s of nothing: %v", c.name, err)
		}
		if header, _, _ := strings.Cut(c.want, "\n"); buf.String() != header+"\n" {
			t.Errorf("%s of nothing wrote %q, want the header", c.name, buf.String())
		}
	}
}

// decklistExport is the shape of UUID2TCGCSV and UUID2MKMCSV.
type decklistExport func(*matcher.Backend, *prices, *csv.Writer, []string, []string, []string) error

// A write the client never got is an error, down to the last row.
func TestDecklistCSVReportsAFailedWrite(t *testing.T) {
	b, p := decklistCSVFixture(t)
	for name, export := range map[string]decklistExport{"tcgplayer": UUID2TCGCSV, "cardmarket": UUID2MKMCSV} {
		for _, ids := range [][]string{nil, {"FIXTUREA-1"}, {"FIXTUREA-1", "FIXTUREA-2"}} {
			err := export(b, p, csv.NewWriter(failingResponse{httptest.NewRecorder()}), ids, nil, nil)
			if err == nil {
				t.Errorf("%s of %d ids: a failed write returned nil", name, len(ids))
			}
		}
	}
}

// The CK and SCG exports write a row per id the vendor buys, from its first
// buylist entry; CK also skips a card with no CK title. A quantity of "0",
// or quantities not matching the ids, reads as 1.
func TestUUID2BuylistCSV(t *testing.T) {
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
	withPrices(t, currentPrices().sellers, vendors)

	ids := []string{"a", "b", "c", "a"}
	for _, tc := range []struct {
		export func(*prices, *csv.Writer, []string, []string) error
		qtys   []string
		want   string
	}{
		{UUID2CKCSV, []string{"3", "2", "1", "0"}, "Title,Edition,Foil,Quantity\nA,Set,true,3\nA,Set,true,1\n"},
		{UUID2CKCSV, []string{"3"}, "Title,Edition,Foil,Quantity\nA,Set,true,1\nA,Set,true,1\n"},
		{UUID2SCGCSV, []string{"3", "2", "1", "0"}, "quantity,productid,name,set_name,language,finish\n3,1,A,Set,en,foil\n2,2,,,,\n1,1,A,Set,en,foil\n"},
		{UUID2SCGCSV, nil, "quantity,productid,name,set_name,language,finish\n1,1,A,Set,en,foil\n1,2,,,,\n1,1,A,Set,en,foil\n"},
	} {
		var buf bytes.Buffer
		err := tc.export(currentPrices(), csv.NewWriter(&buf), ids, tc.qtys)
		if err != nil {
			t.Fatal(err)
		}
		if buf.String() != tc.want {
			t.Errorf("qtys %q: got\n%s\nwant\n%s", tc.qtys, buf.String(), tc.want)
		}
	}
}
