package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// nRealUUIDs returns n distinct UUIDs from the loaded mtgmatcher pool, or skips
// the test when fewer are available. parseChartIDs is the only branch that
// requires real UUIDs to exercise the validation path; everything else in this
// file is data-independent.
func nRealUUIDs(t *testing.T, n int) []string {
	t.Helper()
	uuids := backend().GetUUIDs()
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
	if got, truncated := parseChartIDs(backend(), ""); got != nil || truncated {
		t.Fatalf("expected (nil, false) for empty input, got (%v, %v)", got, truncated)
	}
	if got, truncated := parseChartIDs(backend(), ",,"); got != nil || truncated {
		t.Fatalf("expected (nil, false) for all-empty parts, got (%v, %v)", got, truncated)
	}
}

func TestParseChartIDsSingle(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got, _ := parseChartIDs(backend(), a)
	if !slices.Equal(got, []string{a}) {
		t.Fatalf("expected [%s], got %v", a, got)
	}
}

func TestParseChartIDsTrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got, _ := parseChartIDs(backend(), "  "+a+" , ,"+b+"  ")
	want := []string{a, b}
	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDedupesPreservingOrder(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got, _ := parseChartIDs(backend(), a+","+b+","+a)
	want := []string{a, b}
	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDropsInvalid(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got, _ := parseChartIDs(backend(), "not-a-real-uuid,"+a+",also-bogus")
	if !slices.Equal(got, []string{a}) {
		t.Fatalf("expected only [%s], got %v", a, got)
	}
}

func TestParseChartIDsAllInvalid(t *testing.T) {
	if got, truncated := parseChartIDs(backend(), "not-a-real-uuid,nope"); got != nil || truncated {
		t.Fatalf("expected (nil, false) when nothing validates, got (%v, %v)", got, truncated)
	}
}

func TestParseChartIDsCapsRoster(t *testing.T) {
	maxCards := len(multiCardPalette)
	ids := nRealUUIDs(t, maxCards+2)

	// More distinct valid ids than the chart can render: keep the first
	// maxCards in order and flag the drop.
	got, truncated := parseChartIDs(backend(), strings.Join(ids, ","))
	if !slices.Equal(got, ids[:maxCards]) {
		t.Fatalf("expected first %d ids in order, got %v", maxCards, got)
	}
	if !truncated {
		t.Fatal("expected truncated=true when more than the cap resolve")
	}

	// Exactly the cap: full roster, nothing dropped.
	if got, truncated := parseChartIDs(backend(), strings.Join(ids[:maxCards], ",")); len(got) != maxCards || truncated {
		t.Fatalf("expected (%d ids, false) at the cap, got (%d ids, %v)", maxCards, len(got), truncated)
	}

	// A duplicate past the cap is skipped before the cap check, so it doesn't
	// count as dropping a renderable card.
	if got, truncated := parseChartIDs(backend(), strings.Join(ids[:maxCards], ",")+","+ids[0]); len(got) != maxCards || truncated {
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
func dummyData() []ChartPoint { return []ChartPoint{{Price: 1, Known: true}} }

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
	if !slices.Equal(refs, []string{"TCG Low"}) {
		t.Errorf("refs = %v, want [TCG Low]", refs)
	}
}

// A card's label names its lines, so two printings of one card read apart;
// a card with no label falls back to its name.
func TestMergeMultiCardDatasetsPrefersLabel(t *testing.T) {
	cards := []multiCardInput{
		{Name: "Overgrown Farmland", Label: "Overgrown Farmland|FRA|185|nonfoil",
			Datasets: []Dataset{{Reference: "TCG Low", Data: dummyData()}}},
		{Name: "Overgrown Farmland",
			Datasets: []Dataset{{Reference: "TCG Low", Data: dummyData()}}},
	}
	out, _ := mergeMultiCardDatasets(cards)
	got := []string{out[0].Name, out[1].Name}
	want := []string{"Overgrown Farmland|FRA|185|nonfoil", "Overgrown Farmland"}
	if !slices.Equal(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
}

func TestMergeMultiCardDatasetsFiltersEmptyData(t *testing.T) {
	cards := []multiCardInput{
		{
			Name: "Card A",
			Datasets: []Dataset{
				{Reference: "TCG Low", Data: dummyData()},
				{Reference: "CK Buy", Data: nil},
				{Reference: "TCG Market", Data: []ChartPoint{}},
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
	if !slices.Equal(refs, []string{"TCG Low"}) {
		t.Errorf("empty datasets should not contribute to refs; got %v", refs)
	}
}

// A roster that resolved only one card is still drawn as a roster: its lines
// keep the card's id and their reference, which the page's legend keys on.
func TestPlotSeriesDrawsALoneRosterCardAsARoster(t *testing.T) {
	withDatasets(t, []DatasetConfig{
		{PublicName: "TCG Low", Provider: timeseries.ProviderTCGLow, Color: "red"},
	})
	buildProviderRegistry()

	day := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	series := []chartSeries{{
		CardID: "ban:1",
		Name:   "Card A",
		Prices: map[string]timeseries.ProviderPrices{day: {timeseries.ProviderTCGLow: 1}},
	}}
	plot := plotSeries(testSite.datastore(), series, timeseries.Lookback(30), true)
	if len(plot.datasets) != 1 {
		t.Fatalf("got %d datasets, want 1", len(plot.datasets))
	}
	got := plot.datasets[0]
	if got.CardID != "ban:1" || got.Reference != "TCG Low" || got.Name != "Card A" {
		t.Errorf("dataset = %q / %q / %q, want ban:1 / TCG Low / Card A", got.CardID, got.Reference, got.Name)
	}
	if !slices.Equal(plot.references, []string{"TCG Low"}) {
		t.Errorf("references = %v, want [TCG Low]", plot.references)
	}
}

// A roster of one card's printings reads apart in the datasets the page and
// the API draw: each line is labelled by its printing, whether it was named
// by uuid or by TCGplayer id, while the checkpoints still match the name.
func TestRosterDatasetsLabelEachPrinting(t *testing.T) {
	skipWithoutDatastore(t)
	withDatasets(t, []DatasetConfig{
		{PublicName: "TCG Low", Provider: timeseries.ProviderTCGLow, Color: "red"},
	})
	buildProviderRegistry()
	// Without an archive a Magic printing resolves from the matcher alone.
	prev := PricesArchiveDB
	t.Cleanup(func() { PricesArchiveDB = prev })
	PricesArchiveDB = nil

	b := backend()
	uuid, tcgID, other := twoPrintingsOfOneCard(t)
	ids := []string{uuid, "tcg:" + strconv.Itoa(tcgID)}
	byUUID, err := matcherTarget(context.Background(), b, uuid)
	if err != nil {
		t.Fatal(err)
	}
	byTCGID, err := targetFromTCGID(context.Background(), b, tcgID)
	if err != nil {
		t.Fatal(err)
	}
	series := chartTargetCache{ids[0]: byUUID, ids[1]: byTCGID}.series(context.Background(), b, ids)

	// The prices fetchRosterPrices would have read.
	day := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	for i := range series {
		series[i].Prices = map[string]timeseries.ProviderPrices{day: {timeseries.ProviderTCGLow: 1}}
	}
	plot := plotSeries(testSite.datastore(), series, timeseries.Lookback(30), true)

	var want []string
	for _, id := range []string{uuid, other} {
		co, err := b.GetUUID(id)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, co.String())
	}
	var got []string
	for _, ds := range chartAPIDatasets(plot.datasets) {
		got = append(got, ds.Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
	if series[0].Name != series[1].Name {
		t.Errorf("names = %q / %q, want the card's name on both", series[0].Name, series[1].Name)
	}
}

// twoPrintingsOfOneCard finds a card printed plain in two sets, the second
// sold under a TCGplayer id the matcher resolves to it: the first printing's
// uuid, the second's TCGplayer id and its uuid.
func twoPrintingsOfOneCard(t *testing.T) (string, int, string) {
	t.Helper()
	b := backend()
	first := map[string]*mtgmatcher.CardObject{}
	for _, uuid := range slices.Sorted(slices.Values(b.GetUUIDs())) {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed || co.Foil || co.Etched {
			continue
		}
		seen, ok := first[co.Name]
		if !ok {
			first[co.Name] = co
			continue
		}
		if seen.SetCode == co.SetCode {
			continue
		}
		tcgID, err := strconv.Atoi(co.Identifiers["tcgplayerProductId"])
		if err != nil {
			continue
		}
		matched, err := b.MatchID(strconv.Itoa(tcgID))
		if err != nil || matched != uuid {
			continue
		}
		return seen.UUID, tcgID, uuid
	}
	t.Skip("no card printed plain in two sets")
	return "", 0, ""
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
	if !slices.Equal(refs, want) {
		t.Errorf("refs = %v, want %v", refs, want)
	}
}

func TestMergeMultiCardDatasetsCardWithNoDatasetsSkipsPaletteSlot(t *testing.T) {
	// A card whose Datasets slice is entirely empty still consumes a palette
	// index: a card's color is its place in the roster.
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

// withDatasets publishes datasets as if read from a datasets file for the
// duration of a test, restoring the config, the published datasets and the
// derived provider registry afterwards.
func withDatasets(t *testing.T, datasets []DatasetConfig) {
	t.Helper()
	withConfigCopy(t)
	prevDatasets := datasetsPtr.Load()
	prevRegistry := chartProviders()
	t.Cleanup(func() {
		datasetsPtr.Store(prevDatasets)
		providerRegistry.Store(&prevRegistry)
	})
	Config().DatasetsPath = "datasets.json"
	datasetsPtr.Store(&datasets)
}

// The config owns the whole display: which providers chart, under what name and
// color, in what order.
func TestBuildProviderRegistryMirrorsConfig(t *testing.T) {
	withDatasets(t, []DatasetConfig{
		{PublicName: "Custom Market Name", Index: 3, Provider: timeseries.ProviderTCGMarket, Color: "pink"},
		{PublicName: "Card Kingdom Buylist", Index: 1, Provider: timeseries.ProviderCKBuylist, Color: "blue"},
		{PublicName: "Cardmarket Trend", Index: 5, Provider: timeseries.ProviderMKMTrend, Color: "grey"},
	})
	buildProviderRegistry()

	want := []providerDisplay{
		{timeseries.ProviderTCGMarket, "Custom Market Name", "pink"},
		{timeseries.ProviderCKBuylist, "Card Kingdom Buylist", "blue"},
		{timeseries.ProviderMKMTrend, "Cardmarket Trend", "grey"},
	}
	if !slices.Equal(chartProviders(), want) {
		t.Errorf("registry = %+v, want %+v", chartProviders(), want)
	}
}

// Nothing is substituted for a dataset missing its provider id: the chart drops
// it, which is how a config mistake becomes visible instead of silent.
func TestBuildProviderRegistrySkipsDatasetsWithoutProvider(t *testing.T) {
	withDatasets(t, []DatasetConfig{
		{PublicName: "TCGplayer Low", Index: 2, Provider: timeseries.ProviderTCGLow, Color: "red"},
		{PublicName: "No provider id", Index: 6, Color: "black"},
	})
	buildProviderRegistry()

	want := []providerDisplay{{timeseries.ProviderTCGLow, "TCGplayer Low", "red"}}
	if !slices.Equal(chartProviders(), want) {
		t.Errorf("registry = %+v, want %+v", chartProviders(), want)
	}
}

func TestBuildProviderRegistryEmptyConfig(t *testing.T) {
	withDatasets(t, nil)
	buildProviderRegistry()

	if len(chartProviders()) != 0 {
		t.Errorf("a config with no datasets should register no providers: %+v", chartProviders())
	}
}

// Two datasets can share a provider (the same column charted under two names);
// the first one wins so the legend has no duplicate series.
func TestBuildProviderRegistryDeduplicates(t *testing.T) {
	withDatasets(t, []DatasetConfig{
		{PublicName: "TCGplayer Low", Index: 2, Provider: timeseries.ProviderTCGLow, Color: "red"},
		{PublicName: "TCGplayer Low (sealed)", Index: 8, Provider: timeseries.ProviderTCGLow, Color: "green"},
	})
	buildProviderRegistry()

	want := []providerDisplay{{timeseries.ProviderTCGLow, "TCGplayer Low", "red"}}
	if !slices.Equal(chartProviders(), want) {
		t.Errorf("registry = %+v, want %+v", chartProviders(), want)
	}
}

// Charts read the registry while a config reload or an admin save rebuilds
// it, so the rebuild must not race them. Run with -race.
func TestProviderRegistryRebuildDoesNotRaceCharts(t *testing.T) {
	withDatasets(t, []DatasetConfig{
		{PublicName: "TCGplayer Low", Index: 2, Provider: timeseries.ProviderTCGLow, Color: "red"},
	})
	buildProviderRegistry()
	results := syntheticSeries(30, []int16{timeseries.ProviderTCGLow}, 1)
	labels := getDateAxisValues(earliestChartedDate(results, timeseries.Lookback(30)))

	stop := make(chan struct{})
	var readers, started sync.WaitGroup
	defer readers.Wait()
	defer close(stop)
	for range 4 {
		started.Add(1)
		readers.Go(func() {
			chartDatasetsFrom(results, labels)
			started.Done()
			for {
				select {
				case <-stop:
					return
				default:
					chartDatasetsFrom(results, labels)
				}
			}
		})
	}
	// Rebuilt only once every reader is charting, or 20 fast rebuilds can
	// finish before any reader runs.
	started.Wait()
	for range 200 {
		buildProviderRegistry()
	}
}

// A roster read that panics is reported and costs only its card, which
// counts as a failed read, while the rest of the roster keeps its answers.
// A card more than may be read at once panics, so the roster only finishes
// if a read that panics gives its slot back.
func TestFetchRosterPricesSurvivesAPanickingRead(t *testing.T) {
	posts := serverWebhook(t)
	prev := PricesArchiveDB
	t.Cleanup(func() { PricesArchiveDB = prev })
	// A client with no pool behind it panics on its first query.
	PricesArchiveDB = &timeseries.Client{}

	panicking := chartRosterConcurrency + 1
	roster := make([]chartSeries, panicking, panicking+1)
	for i := range roster {
		banID := int64(i + 1)
		roster[i] = chartSeries{CardID: fmt.Sprintf("ban:%d", banID), target: &chartTarget{BanID: banID}}
	}
	// No identity to read by, so it answers without asking the archive.
	roster = append(roster, chartSeries{CardID: "none", target: &chartTarget{UUID: "none"}})

	done := make(chan []chartSeries, 1)
	go func() { done <- fetchRosterPrices(context.Background(), roster, timeseries.Lookback(30)) }()
	var series []chartSeries
	select {
	case series = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the roster still reads after 10s: a read that panicked kept its slot")
	}

	for _, cs := range series[:panicking] {
		if !errors.Is(cs.Err, errRosterReadPanicked) {
			t.Errorf("%s: err = %v, want it counted as a failed read", cs.CardID, cs.Err)
		}
	}
	if series[panicking].Err != nil {
		t.Errorf("%s: err = %v, want its answer kept", series[panicking].CardID, series[panicking].Err)
	}

	message, _, source := panicReport(t, posts)
	if message != "runtime error: invalid memory address or nil pointer dereference" {
		t.Errorf("message = %q, want the read's panic", message)
	}
	if !strings.HasPrefix(source, "source job: chart roster read ban:") {
		t.Errorf("source = %q, want the read", source)
	}
}

// TestMagicVariantAltCopy pins that the Alternate Fourth Edition copy and the
// printing it copies file under two variants, and that mtgjson's own
// isAlternative flag, which every flagged card's uuid already carries, does not.
func TestMagicVariantAltCopy(t *testing.T) {
	original, err := backend().GetUUID("1b3a28ad-41ca-587a-9feb-5f40154976da")
	if err != nil {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	copied, err := backend().GetUUID(original.UUID + "_alt")
	if err != nil {
		t.Fatal(err)
	}

	accumulated := map[string]*timeseries.PriceRow{}
	getRow(accumulated, original, "2026-10-25").SetPriceForDataset(4, 4.34)
	getRow(accumulated, copied, "2026-10-25").SetPriceForDataset(4, 285.01)
	if len(accumulated) != 2 {
		t.Fatalf("got %d rows for %s and its copy, want 2", len(accumulated), original.UUID)
	}
	for _, row := range accumulated {
		want := 4.34
		if row.IsAlt {
			want = 285.01
		}
		if got := row.PriceForDataset(4); got == nil || *got != want {
			t.Errorf("is_alt=%v row priced %v, want %v", row.IsAlt, got, want)
		}
	}

	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || !co.IsAlternative || strings.Contains(uuid, "_alt") {
			continue
		}
		if magicVariant(co).IsAlt {
			t.Errorf("%s is filed as an _alt copy for mtgjson's isAlternative", uuid)
		}
		return
	}
	t.Error("no card carries mtgjson's isAlternative")
}
