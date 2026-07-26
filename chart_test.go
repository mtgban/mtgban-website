package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

func fptr(f float64) *float64 { return &f }

// nRealUUIDs returns n distinct UUIDs from the loaded mtgmatcher pool, or skips
// the test when fewer are available. parseChartIDs is the only branch that
// requires real UUIDs to exercise the validation path; everything else in this
// file is data-independent.
func nRealUUIDs(t *testing.T, n int) []string {
	t.Helper()
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) < n {
		t.Skipf("mtgmatcher data not loaded (need %d UUIDs); skipping", n)
	}
	return uuids[:n]
}

// twoRealUUIDs is the common two-card case of nRealUUIDs.
func twoRealUUIDs(t *testing.T) (string, string) {
	t.Helper()
	ids := nRealUUIDs(t, 2)
	return ids[0], ids[1]
}

func TestParseChartIDsEmpty(t *testing.T) {
	if got, truncated := parseChartIDs(""); got != nil || truncated {
		t.Fatalf("expected (nil, false) for empty input, got (%v, %v)", got, truncated)
	}
	if got, truncated := parseChartIDs(",,"); got != nil || truncated {
		t.Fatalf("expected (nil, false) for all-empty parts, got (%v, %v)", got, truncated)
	}
}

func TestParseChartIDsSingle(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got, _ := parseChartIDs(a)
	if !reflect.DeepEqual(got, []string{a}) {
		t.Fatalf("expected [%s], got %v", a, got)
	}
}

func TestParseChartIDsTrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got, _ := parseChartIDs("  " + a + " , ," + b + "  ")
	want := []string{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDedupesPreservingOrder(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got, _ := parseChartIDs(a + "," + b + "," + a)
	want := []string{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDropsInvalid(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got, _ := parseChartIDs("not-a-real-uuid," + a + ",also-bogus")
	if !reflect.DeepEqual(got, []string{a}) {
		t.Fatalf("expected only [%s], got %v", a, got)
	}
}

func TestParseChartIDsAllInvalid(t *testing.T) {
	if got, truncated := parseChartIDs("not-a-real-uuid,nope"); got != nil || truncated {
		t.Fatalf("expected (nil, false) when nothing validates, got (%v, %v)", got, truncated)
	}
}

func TestParseChartIDsCapsRoster(t *testing.T) {
	maxCards := len(multiCardPalette)
	ids := nRealUUIDs(t, maxCards+2)

	// More distinct valid ids than the chart can render: keep the first
	// maxCards in order and flag the drop.
	got, truncated := parseChartIDs(strings.Join(ids, ","))
	if !reflect.DeepEqual(got, ids[:maxCards]) {
		t.Fatalf("expected first %d ids in order, got %v", maxCards, got)
	}
	if !truncated {
		t.Fatal("expected truncated=true when more than the cap resolve")
	}

	// Exactly the cap: full roster, nothing dropped.
	if got, truncated := parseChartIDs(strings.Join(ids[:maxCards], ",")); len(got) != maxCards || truncated {
		t.Fatalf("expected (%d ids, false) at the cap, got (%d ids, %v)", maxCards, len(got), truncated)
	}

	// A duplicate past the cap is skipped before the cap check, so it doesn't
	// count as dropping a renderable card.
	if got, truncated := parseChartIDs(strings.Join(ids[:maxCards], ",") + "," + ids[0]); len(got) != maxCards || truncated {
		t.Fatalf("expected a trailing duplicate not to flag truncation, got (%d ids, %v)", len(got), truncated)
	}
}

func TestCsvWithout(t *testing.T) {
	cases := []struct {
		name string
		csv  string
		drop string
		want string
	}{
		{"drop middle", "a,b,c", "b", "a,c"},
		{"drop first", "a,b,c", "a", "b,c"},
		{"drop last", "a,b,c", "c", "a,b"},
		{"drop only entry", "a", "a", ""},
		{"drop not present", "a,b,c", "z", "a,b,c"},
		{"empty input", "", "a", ""},
		{"skips empty parts", "a,,b,", "z", "a,b"},
		{"all entries dropped", "a,a,a", "a", ""},
		{"drop empty string is a no-op", "a,b", "", "a,b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := csvWithout(tc.csv, tc.drop); got != tc.want {
				t.Fatalf("csvWithout(%q, %q) = %q, want %q", tc.csv, tc.drop, got, tc.want)
			}
		})
	}
}

func TestMultiCardPaletteUniqueAndNonEmpty(t *testing.T) {
	if len(multiCardPalette) == 0 {
		t.Fatal("multiCardPalette is empty")
	}
	seen := map[string]bool{}
	for _, c := range multiCardPalette {
		if c == "" {
			t.Fatal("multiCardPalette contains empty entry")
		}
		if seen[c] {
			t.Fatalf("multiCardPalette has duplicate color %q", c)
		}
		seen[c] = true
	}
}

// dummyData returns a non-empty slice so a Dataset is considered to have data
// by mergeMultiCardDatasets. The actual values don't matter — the merge logic
// only checks len(ds.Data).
func dummyData() []string { return []string{"1"} }

func TestMergeMultiCardDatasetsEmpty(t *testing.T) {
	datasets, refs := mergeMultiCardDatasets(nil)
	if datasets != nil {
		t.Errorf("expected nil datasets, got %v", datasets)
	}
	if refs != nil {
		t.Errorf("expected nil refs, got %v", refs)
	}
}

func TestMergeMultiCardDatasetsOverridesNameAndColor(t *testing.T) {
	cards := []multiCardInput{
		{
			Name: "Black Lotus (LEA)",
			Datasets: []Dataset{
				{Name: "ignored", Color: "ignored", Reference: "TCG Low", Data: dummyData()},
			},
		},
	}
	out, refs := mergeMultiCardDatasets(cards)
	if len(out) != 1 {
		t.Fatalf("expected 1 dataset, got %d", len(out))
	}
	if out[0].Name != "Black Lotus (LEA)" {
		t.Errorf("Name not overridden: got %q", out[0].Name)
	}
	if out[0].Color != multiCardPalette[0] {
		t.Errorf("Color = %q, want palette[0] = %q", out[0].Color, multiCardPalette[0])
	}
	if out[0].Reference != "TCG Low" {
		t.Errorf("Reference should be preserved, got %q", out[0].Reference)
	}
	if !reflect.DeepEqual(refs, []string{"TCG Low"}) {
		t.Errorf("refs = %v, want [TCG Low]", refs)
	}
}

func TestMergeMultiCardDatasetsFiltersEmptyData(t *testing.T) {
	cards := []multiCardInput{
		{
			Name: "Card A",
			Datasets: []Dataset{
				{Reference: "TCG Low", Data: dummyData()},
				{Reference: "CK Buy", Data: nil},
				{Reference: "TCG Market", Data: []string{}},
			},
		},
	}
	out, refs := mergeMultiCardDatasets(cards)
	if len(out) != 1 {
		t.Fatalf("expected 1 non-empty dataset, got %d (%+v)", len(out), out)
	}
	if out[0].Reference != "TCG Low" {
		t.Errorf("kept the wrong dataset: %+v", out[0])
	}
	if !reflect.DeepEqual(refs, []string{"TCG Low"}) {
		t.Errorf("empty datasets should not contribute to refs; got %v", refs)
	}
}

func TestMergeMultiCardDatasetsPaletteRoundRobin(t *testing.T) {
	// One card per palette slot + two extras to force the wrap.
	n := len(multiCardPalette) + 2
	cards := make([]multiCardInput, n)
	for i := 0; i < n; i++ {
		cards[i] = multiCardInput{
			Name:     fmt.Sprintf("Card %d", i),
			Datasets: []Dataset{{Reference: "TCG Low", Data: dummyData()}},
		}
	}
	out, _ := mergeMultiCardDatasets(cards)
	if len(out) != n {
		t.Fatalf("expected %d datasets, got %d", n, len(out))
	}
	for i := 0; i < n; i++ {
		want := multiCardPalette[i%len(multiCardPalette)]
		if out[i].Color != want {
			t.Errorf("card %d: color = %q, want %q (wrap at index %d)", i, out[i].Color, want, len(multiCardPalette))
		}
	}
}

func TestMergeMultiCardDatasetsReferenceOrderFirstSeen(t *testing.T) {
	cards := []multiCardInput{
		{
			Name: "Card A",
			Datasets: []Dataset{
				{Reference: "TCG Low", Data: dummyData()},
				{Reference: "CK Buy", Data: dummyData()},
			},
		},
		{
			Name: "Card B",
			Datasets: []Dataset{
				// CK Buy is a repeat; TCG Market is new and should append.
				{Reference: "CK Buy", Data: dummyData()},
				{Reference: "TCG Market", Data: dummyData()},
				{Reference: "TCG Low", Data: dummyData()},
			},
		},
		{
			Name: "Card C",
			// Empty Data should NOT register a new reference.
			Datasets: []Dataset{
				{Reference: "SCG Buy", Data: nil},
			},
		},
	}
	_, refs := mergeMultiCardDatasets(cards)
	want := []string{"TCG Low", "CK Buy", "TCG Market"}
	if !reflect.DeepEqual(refs, want) {
		t.Errorf("refs = %v, want %v", refs, want)
	}
}

func TestGameTCGCategory(t *testing.T) {
	saved := Config.Game
	defer func() { Config.Game = saved }()

	Config.Game = "lorcana"
	if cat, ok := gameTCGCategory(); !ok || cat != 71 {
		t.Errorf("lorcana -> (%d, %v), want (71, true)", cat, ok)
	}
	// Magic charts off product_prices (mtgjson uuid), so it must NOT route to
	// the TCG path here — that keeps DisableChart and getDatasets on their
	// existing Magic behavior.
	Config.Game = "magic"
	if _, ok := gameTCGCategory(); ok {
		t.Error("magic should not have a TCG category")
	}
	Config.Game = "pokemon"
	if _, ok := gameTCGCategory(); ok {
		t.Error("an unwired game should not report a TCG category")
	}
}

func TestTCGSubTypesForFinish(t *testing.T) {
	if got := tcgSubTypesForFinish(false); !reflect.DeepEqual(got, []string{"Normal"}) {
		t.Errorf("non-foil = %v, want [Normal]", got)
	}
	// Foil accepts either foil sub-type, Cold Foil first so it wins ties.
	got := tcgSubTypesForFinish(true)
	if !reflect.DeepEqual(got, []string{"Cold Foil", "Holofoil"}) {
		t.Errorf("foil = %v, want [Cold Foil, Holofoil]", got)
	}
}

func TestBuildTCGDatasetsEmpty(t *testing.T) {
	if got := buildTCGDatasets(nil, []string{"Normal"}, []string{"2024-01-01"}); got != nil {
		t.Errorf("expected nil for no rows, got %v", got)
	}
}

// The dataset order and names must track tcgChartRefs (Market then Low) so this
// test doubles as a guard on that config.
func TestBuildTCGDatasetsProjectsColumnsOntoAxis(t *testing.T) {
	labels := []string{"2024-01-03", "2024-01-02", "2024-01-01"}
	rows := []timeseries.TCGPriceRow{
		{Date: "2024-01-03", SubTypeName: "Normal", MarketPrice: fptr(3), LowPrice: fptr(2.5)},
		{Date: "2024-01-01", SubTypeName: "Normal", MarketPrice: fptr(1), LowPrice: fptr(0.5)},
		// 2024-01-02 intentionally absent -> gap on both lines.
	}
	out := buildTCGDatasets(rows, []string{"Normal"}, labels)
	if len(out) != 2 {
		t.Fatalf("expected 2 datasets (Market, Low), got %d: %+v", len(out), out)
	}
	if out[0].Name != "TCGplayer Market" || out[1].Name != "TCGplayer Low" {
		t.Fatalf("dataset order/names off: %q, %q", out[0].Name, out[1].Name)
	}
	wantMarket := []string{"3", "Number.NaN", "1"}
	if !reflect.DeepEqual(out[0].Data, wantMarket) {
		t.Errorf("Market data = %v, want %v", out[0].Data, wantMarket)
	}
	wantLow := []string{"2.5", "Number.NaN", "0.5"}
	if !reflect.DeepEqual(out[1].Data, wantLow) {
		t.Errorf("Low data = %v, want %v", out[1].Data, wantLow)
	}
	if out[0].Reference != "TCGplayer Market" || out[0].Color == "" {
		t.Errorf("Reference/Color not set: %+v", out[0])
	}
}

func TestBuildTCGDatasetsDropsAllNullReference(t *testing.T) {
	labels := []string{"2024-01-01"}
	// Market is null everywhere -> its line is dropped; Low survives.
	rows := []timeseries.TCGPriceRow{
		{Date: "2024-01-01", SubTypeName: "Normal", MarketPrice: nil, LowPrice: fptr(4)},
	}
	out := buildTCGDatasets(rows, []string{"Normal"}, labels)
	if len(out) != 1 {
		t.Fatalf("expected only the Low dataset, got %d: %+v", len(out), out)
	}
	if out[0].Name != "TCGplayer Low" {
		t.Errorf("kept the wrong dataset: %q", out[0].Name)
	}
}

func TestBuildTCGDatasetsPrefersEarlierSubType(t *testing.T) {
	labels := []string{"2024-01-01"}
	// Same date under both foil sub-types; "Cold Foil" precedes "Holofoil" in the
	// preference list, so its price must win.
	rows := []timeseries.TCGPriceRow{
		{Date: "2024-01-01", SubTypeName: "Holofoil", MarketPrice: fptr(99)},
		{Date: "2024-01-01", SubTypeName: "Cold Foil", MarketPrice: fptr(10)},
	}
	out := buildTCGDatasets(rows, []string{"Cold Foil", "Holofoil"}, labels)
	if len(out) != 1 {
		t.Fatalf("expected 1 dataset (Market), got %d: %+v", len(out), out)
	}
	if !reflect.DeepEqual(out[0].Data, []string{"10"}) {
		t.Errorf("expected Cold Foil price 10 to win, got %v", out[0].Data)
	}
}

// chartEarliestDate feeds getDateAxisValues, which walks day-by-day from today
// back to the earliest it's handed — a zero time there builds a ~740k-entry axis
// back to year one. So the earliest must never be zero; the no-data fallbacks
// clamp to the lookback floor. Regression guard for the TCG path, which used to
// return a zero time when a card had no history.
func TestChartEarliestDateStaysBounded(t *testing.T) {
	saved := Config.Game
	defer func() { Config.Game = saved }()

	lb := timeseries.Lookback(30)
	// The Lorcana (TCG product-id) path and the Magic (uuid) path must both stay
	// bounded when no history is available.
	for _, game := range []string{"lorcana", "magic"} {
		Config.Game = game
		earliest := chartEarliestDate(context.Background(), "no-such-card-id", lb)
		if earliest.IsZero() {
			t.Fatalf("%s: chartEarliestDate returned a zero time", game)
		}
		if n := len(getDateAxisValues(earliest)); n > lb.Days()+2 {
			t.Errorf("%s: axis has %d labels, want a window-bounded count (<= %d)", game, n, lb.Days()+2)
		}
	}
}

func TestMergeMultiCardDatasetsCardWithNoDatasetsSkipsPaletteSlot(t *testing.T) {
	// A card whose Datasets slice is entirely empty still consumes a palette
	// index — this matches the original getDatasetsForMulti loop where an
	// empty getDatasets() result still advanced i.
	cards := []multiCardInput{
		{Name: "Card A", Datasets: nil},
		{Name: "Card B", Datasets: []Dataset{{Reference: "TCG Low", Data: dummyData()}}},
	}
	out, _ := mergeMultiCardDatasets(cards)
	if len(out) != 1 {
		t.Fatalf("expected 1 dataset, got %d", len(out))
	}
	if out[0].Color != multiCardPalette[1] {
		t.Errorf("second card should use palette[1] (%q), got %q",
			multiCardPalette[1], out[0].Color)
	}
}
