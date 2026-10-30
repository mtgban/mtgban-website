package main

import (
	"bytes"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

func TestVariantMapRowsNameTheCopyAndItsOriginal(t *testing.T) {
	skipWithoutDatastore(t)
	original, err := backend().GetUUID("1b3a28ad-41ca-587a-9feb-5f40154976da")
	if err != nil {
		t.Skip("matcher data not loaded")
	}
	rows, _ := variantMapRows(backend())
	byID := map[string]variantMapRow{}
	for _, r := range rows {
		byID[r.MtgbanID] = r
	}
	o, c := byID[original.UUID], byID[original.UUID+"_alt"]
	if o.MtgbanID == "" || c.MtgbanID == "" {
		t.Fatal("original or copy missing")
	}
	if o.Alias.IsAlt || !c.Alias.IsAlt || o.Alias.MtgjsonUUID != c.Alias.MtgjsonUUID {
		t.Errorf("original %+v, copy %+v", o, c)
	}
}

func TestWriteVariantMapIsTabSeparated(t *testing.T) {
	var buf bytes.Buffer
	rows := []variantMapRow{{Alias: timeseries.MagicVariant{MtgjsonUUID: "u", IsFoil: true, Language: "Japanese"}, MtgbanID: "u_f"}}
	if err := writeVariantMap(&buf, rows); err != nil {
		t.Fatal(err)
	}
	want := "mtgjson_uuid\tis_foil\tis_etched\tis_alt\tlanguage\tmtgban_id\nu\tt\tf\tf\tJapanese\tu_f\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}
