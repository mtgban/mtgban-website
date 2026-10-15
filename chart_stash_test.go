package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// stashDatasets is two wide datasets beside one with no wide column, the way
// the TCG Direct entry sits in the Magic datasets file.
var stashDatasets = []DatasetConfig{
	{PublicName: "TCG Low", Retail: []string{"TCGLow"}, Index: 2, Provider: 3},
	{PublicName: "TCG Market", Retail: []string{"TCGMarket"}, Index: 3, Provider: 4},
	{PublicName: "TCG Direct", Retail: []string{"TCGDirect"}, Index: 10, Provider: 7},
}

func TestStashAccumulateFilesNoColumnDatasetInExtra(t *testing.T) {
	accumulated := map[string]*timeseries.PriceRow{}
	card := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: "00000000-0000-0000-0000-000000000001"}}

	accumulatePrice(accumulated, card, stashDatasets[0], "2026-10-15", 1.5)
	accumulatePrice(accumulated, card, stashDatasets[2], "2026-10-15", 3.25)
	accumulatePrice(accumulated, card, DatasetConfig{Index: 11}, "2026-10-15", 9)

	if len(accumulated) != 1 {
		t.Fatalf("got %d rows, want 1", len(accumulated))
	}
	for _, row := range accumulated {
		if p := row.PriceForDataset(2); p == nil || *p != 1.5 {
			t.Errorf("wide column 2 = %v, want 1.5", p)
		}
		if got, ok := row.Extra[7]; !ok || got != 3.25 {
			t.Errorf("Extra[7] = %v (%t), want 3.25", got, ok)
		}
		if len(row.Extra) != 1 {
			t.Errorf("Extra = %v, want only provider 7 (no provider means nowhere to file it)", row.Extra)
		}
	}
}

func TestLongRowsForCarriesExtra(t *testing.T) {
	accumulated := map[string]*timeseries.PriceRow{}
	row := getRow(accumulated, "00000000-0000-0000-0000-000000000001", false, false, false, "", "2026-10-15")
	row.SetPriceForDataset(2, 1.5)
	row.SetExtra(7, 3.25)

	got := longRowsFor(row, 42, stashDatasets)
	want := map[int16]float64{3: 1.5, 7: 3.25}
	if len(got) != len(want) {
		t.Fatalf("got %d long rows %v, want %d", len(got), got, len(want))
	}
	for _, lp := range got {
		if lp.BanID != 42 || lp.Date != "2026-10-15" {
			t.Errorf("row %+v: want ban id 42 on 2026-10-15", lp)
		}
		if price, ok := want[lp.Provider]; !ok || price != lp.Price {
			t.Errorf("row %+v: want provider %d at %v", lp, lp.Provider, price)
		}
	}
}

func TestStashHasWideColumn(t *testing.T) {
	for index := range 10 {
		if !timeseries.HasWideColumn(index) {
			t.Errorf("index %d: want a wide column", index)
		}
	}
	for _, index := range []int{-1, 10, 11} {
		if timeseries.HasWideColumn(index) {
			t.Errorf("index %d: want no wide column", index)
		}
	}
}
