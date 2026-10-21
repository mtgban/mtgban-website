package main

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// A scraper or an old archive row can hand a chart NaN or ±Inf. JSON has no
// spelling for either, so one such point used to fail the whole encode: the
// API answered an empty 200 and the page drew nothing. It is a gap instead.
func TestChartPointMarshalsNonFiniteAsGap(t *testing.T) {
	data := []ChartPoint{
		{Price: 1, Known: true},
		{Price: math.NaN(), Known: true},
		{Price: math.Inf(1), Known: true},
		{Price: math.Inf(-1), Known: true},
		{Price: 2, Known: true},
	}
	got, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `[1,null,null,null,2]`
	if string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

// The API response is the place the empty 200 showed: the rest of the series
// has to arrive when one of its points is NaN.
func TestChartAPIResponseSurvivesANonFinitePoint(t *testing.T) {
	w := httptest.NewRecorder()
	writeChartAPIResponse(w, ChartAPIResponse{Datasets: []ChartAPIDataset{{
		Name: "TCG Low",
		Data: []ChartPoint{{Price: 3, Known: true}, {Price: math.NaN(), Known: true}, {Price: 4, Known: true}},
	}}})
	var resp ChartAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response %q is not JSON: %v", w.Body.String(), err)
	}
	want := []ChartPoint{{Price: 3, Known: true}, {}, {Price: 4, Known: true}}
	if len(resp.Datasets) != 1 || !slices.Equal(resp.Datasets[0].Data, want) {
		t.Errorf("datasets = %+v, want one with %+v", resp.Datasets, want)
	}
}

// strconv.ParseFloat reads "NaN" and "Inf", so the quoted legacy form could
// bring a non-finite price back in as a known one.
func TestChartPointReadsNonFiniteAsGap(t *testing.T) {
	for _, in := range []string{`"NaN"`, `NaN`, `"Inf"`, `"-Infinity"`, `"+inf"`} {
		var p ChartPoint
		if err := p.UnmarshalJSON([]byte(in)); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if p.Known {
			t.Errorf("%s read as known price %v, want a gap", in, p.Price)
		}
	}
}

// Postgres double precision holds NaN and Infinity, and the archive predates
// any guard, so a historic row can carry one into a chart.
func TestPriceAtTreatsNonFiniteAsGap(t *testing.T) {
	results := map[string]timeseries.ProviderPrices{
		"2026-09-24": {1: math.NaN(), 2: math.Inf(1), 3: 5},
	}
	for _, provider := range []int16{1, 2} {
		if got := priceAt(results, "2026-09-24", provider); got.Known {
			t.Errorf("provider %d: priceAt = %+v, want a gap", provider, got)
		}
	}
	if got := priceAt(results, "2026-09-24", 3); !got.Known || got.Price != 5 {
		t.Errorf("provider 3: priceAt = %+v, want a known 5", got)
	}
}

// finiteBackend holds the few cards the snapshot tests below price, so they run
// without the full card database.
func finiteBackend(ids ...string) *mtgmatcher.Backend {
	b := &mtgmatcher.Backend{UUIDs: map[string]*mtgmatcher.CardObject{}}
	for _, id := range ids {
		b.UUIDs[id] = &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: id}}
		b.AllUUIDs = append(b.AllUUIDs, id)
	}
	return b
}

// A non-finite scraped price never reaches the archive, on either side or
// through the scraper's own RetailPrice field, while the finite prices beside
// it still do.
func TestSnapshotDropsNonFinitePrices(t *testing.T) {
	b := finiteBackend("ok", "nan", "inf", "field")
	keepScrapers(t)
	withTCGCSVGames(t, 71, nil)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZS"}, PublicName: "Seller", Provider: timeseries.ProviderMKMLow},
		{Buylist: []string{"ZZV"}, PublicName: "Vendor", Provider: timeseries.ProviderSCGBuylist},
	})

	now := time.Now()
	inv := mtgban.InventoryRecord{
		"ok":    {{Price: 2, Conditions: "NM"}},
		"nan":   {{Price: math.NaN(), Conditions: "NM"}},
		"inf":   {{Price: math.Inf(1), Conditions: "NM"}},
		"field": {{Price: 1, Conditions: "SP", CustomFields: map[string]string{"RetailPrice": "NaN"}}},
	}
	bl := mtgban.BuylistRecord{
		"ok":  {{BuyPrice: 1, Conditions: "NM"}},
		"nan": {{BuyPrice: math.NaN(), Conditions: "NM"}},
		"inf": {{BuyPrice: math.Inf(-1), Conditions: "NM"}},
	}
	serve(
		[]mtgban.Seller{mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "ZZS", Shorthand: "ZZS", InventoryTimestamp: &now})},
		[]mtgban.Vendor{mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Name: "ZZV", Shorthand: "ZZV", BuylistTimestamp: &now})},
	)

	var visited int
	walkSnapshotPrices(b, now, func(card *mtgmatcher.CardObject, config DatasetConfig, _ string, price float64) {
		visited++
		if math.IsNaN(price) || math.IsInf(price, 0) {
			t.Errorf("%s visited %s at %v", config.PublicName, card.UUID, price)
		}
	})
	if visited != 2 {
		t.Errorf("visited %d prices, want the 2 finite ones", visited)
	}

	snapshot := collectNonMagicSnapshot(b, now, func(*mtgmatcher.CardObject) int64 { return 555 })
	date := now.Format("2006-01-02")
	want := []timeseries.LongPrice{
		{BanID: 555, Date: date, Provider: timeseries.ProviderMKMLow, Price: 2},
		{BanID: 555, Date: date, Provider: timeseries.ProviderSCGBuylist, Price: 1},
	}
	if !slices.Equal(snapshot.Rows, want) {
		t.Errorf("rows = %+v, want %+v", snapshot.Rows, want)
	}
}
