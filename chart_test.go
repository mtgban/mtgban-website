package main

import (
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
