package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// twoRealUUIDs returns two distinct UUIDs from the loaded mtgmatcher pool, or
// skips the test if fewer than two are available. parseChartIDs is the only
// branch that requires real UUIDs to exercise the validation path; everything
// else in this file is data-independent.
func twoRealUUIDs(t *testing.T) (string, string) {
	t.Helper()
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) < 2 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	return uuids[0], uuids[1]
}

func TestParseChartIDsEmpty(t *testing.T) {
	if got := parseChartIDs(""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
	if got := parseChartIDs(",,"); got != nil {
		t.Fatalf("expected nil for all-empty parts, got %v", got)
	}
}

func TestParseChartIDsSingle(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got := parseChartIDs(a)
	if !reflect.DeepEqual(got, []string{a}) {
		t.Fatalf("expected [%s], got %v", a, got)
	}
}

func TestParseChartIDsTrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got := parseChartIDs("  " + a + " , ," + b + "  ")
	want := []string{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDedupesPreservingOrder(t *testing.T) {
	a, b := twoRealUUIDs(t)
	got := parseChartIDs(a + "," + b + "," + a)
	want := []string{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParseChartIDsDropsInvalid(t *testing.T) {
	a, _ := twoRealUUIDs(t)
	got := parseChartIDs("not-a-real-uuid," + a + ",also-bogus")
	if !reflect.DeepEqual(got, []string{a}) {
		t.Fatalf("expected only [%s], got %v", a, got)
	}
}

func TestParseChartIDsAllInvalid(t *testing.T) {
	if got := parseChartIDs("not-a-real-uuid,nope"); got != nil {
		t.Fatalf("expected nil when nothing validates, got %v", got)
	}
}

func TestInList(t *testing.T) {
	cases := []struct {
		name     string
		haystack []string
		needle   string
		want     bool
	}{
		{"present", []string{"a", "b", "c"}, "b", true},
		{"absent", []string{"a", "b", "c"}, "z", false},
		{"empty slice", nil, "a", false},
		{"empty needle in slice", []string{"", "x"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inList(tc.haystack, tc.needle); got != tc.want {
				t.Fatalf("inList(%v, %q) = %v, want %v", tc.haystack, tc.needle, got, tc.want)
			}
		})
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

func TestSetReleaseCheckpointsSortedAndReleaseOnly(t *testing.T) {
	editions := GetEditions()
	if len(editions.AllEditionsKeys) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}

	// Anchor far enough in the past that several modern sets fall in-window.
	earliest := time.Now().AddDate(-5, 0, 0)
	out := setReleaseCheckpoints(earliest)
	if len(out) == 0 {
		t.Skip("no set releases in window; skipping")
	}

	// Dates are stored as "YYYY-MM-DD"; lexical sort == chronological sort.
	if !sort.SliceIsSorted(out, func(i, j int) bool {
		return out[i].Date < out[j].Date
	}) {
		t.Fatal("setReleaseCheckpoints output is not sorted by Date")
	}

	// No per-card context should appear: multi-chart mode has no single card
	// to attribute reprints/bans to, so the Type and Source must reflect that.
	for _, c := range out {
		if c.Date == "" {
			t.Errorf("checkpoint with empty Date: %+v", c)
		}
		// Reprint markers carry a non-empty Source (the card name being
		// reprinted). Release markers shouldn't reference a card.
		lower := strings.ToLower(c.Type)
		if strings.Contains(lower, "reprint") || strings.Contains(lower, "ban") || strings.Contains(lower, "unban") {
			t.Errorf("unexpected per-card checkpoint type %q in set-release output", c.Type)
		}
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
