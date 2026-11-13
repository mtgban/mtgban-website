package metricsreport

import (
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// A trend needs 14 counted days in each window; below that the cell says why and gives no word.
func TestPreviousTextNeedsCountedDaysInBothWindows(t *testing.T) {
	wall := Signal{Section: SectionWalls, Label: "w", Count: 60, Previous: 30}
	cases := []struct {
		days, prevDays int
		text, trend    string
	}{
		{30, 30, "30 in 30 counted days, up", TrendUp},
		{30, 14, "30 in 14 counted days, flat", TrendFlat}, // 2 a day against 2.1, inside the band
		{30, 13, "30 in 13 counted days; the earlier period was not fully counted, so no trend", ""},
		{30, 0, "the earlier period was not counted, so no trend", ""},
		{14, 30, "30 in 30 counted days, up", TrendUp},
		{13, 30, "30; this period has 13 counted days, too few to compare", ""},
	}
	for _, tc := range cases {
		text, trend := PreviousText(wall, tc.days, tc.prevDays)
		if text != tc.text || trend != tc.trend {
			t.Errorf("%d and %d days: %q, %q; want %q, %q", tc.days, tc.prevDays, text, trend, tc.text, tc.trend)
		}
	}
}

// A count is compared per counted day, so a full window against a half one is not "up" for the same pace.
func TestPreviousTextIsPerCountedDay(t *testing.T) {
	cases := []struct {
		count, previous int64
		days, prevDays  int
		trend           string
	}{
		{60, 30, 30, 15, TrendFlat},    // 2 a day both times
		{1974, 990, 30, 15, TrendFlat}, // 65.8 a day against 66
		{66, 30, 30, 15, TrendFlat},    // 10% up is still flat
		{67, 30, 30, 15, TrendUp},
		{54, 30, 30, 15, TrendFlat}, // 10% down is still flat
		{53, 30, 30, 15, TrendDown},
		{90, 90, 90, 90, TrendFlat},
	}
	for _, tc := range cases {
		s := Signal{Section: SectionWalls, Count: tc.count, Previous: tc.previous}
		if _, trend := PreviousText(s, tc.days, tc.prevDays); trend != tc.trend {
			t.Errorf("%d in %d days against %d in %d: %q, want %q", tc.count, tc.days, tc.previous, tc.prevDays, trend, tc.trend)
		}
	}
}

// A rate row compares its rates: the same rate over windows of unequal coverage reads flat.
func TestPreviousTextComparesRates(t *testing.T) {
	empty := Signal{Section: SectionFailures, Count: 2000, Denom: 29000, Previous: 1000, PrevDenom: 14500}
	text, trend := PreviousText(empty, 30, 15)
	if trend != TrendFlat || text != "1000 of 14500 (6.9%), flat" {
		t.Errorf("equal rates: %q, %q", text, trend)
	}
	// 6.82% against 6.80%: noise, flat
	if _, trend := PreviousText(Signal{Section: SectionFailures, Count: 1974, Denom: 29022, Previous: 990, PrevDenom: 14520}, 30, 15); trend != TrendFlat {
		t.Errorf("6.80%% against 6.82%%: %q", trend)
	}
	empty.Count = 2201
	if _, trend := PreviousText(empty, 30, 15); trend != TrendUp {
		t.Errorf("a rate past the band: %q", trend)
	}
	empty.PrevDenom = 49
	if text, trend := PreviousText(empty, 30, 30); trend != "" || text != "1000 of 49, too few to compare rates" {
		t.Errorf("too few before: %q, %q", text, trend)
	}
}

// Only walls and failures get a trend; growing shows its Previous; the rest nothing.
func TestPreviousTextBySection(t *testing.T) {
	if text, trend := PreviousText(Signal{Section: SectionGrowing, Previous: 50}, 30, 30); text != "50" || trend != "" {
		t.Errorf("growing: %q, %q", text, trend)
	}
	for _, s := range []Signal{{Section: SectionMobile, Previous: 5}, {Section: SectionDepth}, {Section: SectionNew}, {Section: SectionWalls, NotMeasured: true}} {
		if text, trend := PreviousText(s, 30, 30); text != "" || trend != "" {
			t.Errorf("%+v: %q, %q", s, text, trend)
		}
	}
}

func TestWindowDaysAndComparable(t *testing.T) {
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 30), tot(2, "metrics.flush", "", "", 1, 15), tot(3, "metrics.flush", "", "", 1, 2)}
	if d, p := WindowDays(totals, w30); d != 30 || p != 30 {
		t.Errorf("30-day window: %d, %d", d, p)
	}
	if d, p := WindowDays(totals, Window{Days: 60}); d != 60 || p != 17 {
		t.Errorf("60-day window: %d, %d", d, p)
	}
	for _, tc := range []struct {
		d, p int
		want bool
	}{{14, 14, true}, {13, 14, false}, {14, 13, false}, {0, 0, false}} {
		if Comparable(tc.d, tc.p) != tc.want {
			t.Errorf("Comparable(%d, %d) != %v", tc.d, tc.p, tc.want)
		}
	}
}

// "New" needs the counter to have run 14 days in the window before, not one.
func TestInvestNewNeedsCountedDaysBefore(t *testing.T) {
	names := append(investNames(), observability.Name{Name: "news.three_day", Report: observability.ReportContext, Area: "news", Help: "h"})
	for _, tc := range []struct {
		before int
		want   bool
	}{{0, false}, {1, false}, {13, false}, {14, true}, {30, true}} {
		totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(0, "news.three_day", "", "on", 60, 12)}
		if tc.before > 0 {
			totals = append(totals, tot(1, "metrics.flush", "", "", 1, tc.before))
		}
		if got := section(Invest(names, totals, nil, w30), "new"); (len(got) == 1) != tc.want {
			t.Errorf("%d counted days before: %+v", tc.before, got)
		}
	}
}

// Growing needs 14 counted days in each of the last two 30-day periods, New 14 in the window before.
func TestReachOf(t *testing.T) {
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(1, "metrics.flush", "", "", 1, 13), tot(2, "metrics.flush", "", "", 1, 30)}
	r := ReachOf(totals, w30)
	if r.Growing || r.GrowingDays != [2]int{30, 13} || r.New || r.NewDays != 13 {
		t.Errorf("30 days: %+v", r)
	}
	totals[1].Days = 14
	if r := ReachOf(totals, w30); !r.Growing || !r.New {
		t.Errorf("14 days before: %+v", r)
	}
	// a 60-day window's window before is periods 2 and 3
	if r := ReachOf(totals, Window{Days: 60}); r.NewDays != 30 || !r.New || r.GrowingDays != [2]int{30, 14} {
		t.Errorf("60 days: %+v", r)
	}
}

// Measured counts the units that could be classed, and the most days of the ones that could not.
func TestMeasured(t *testing.T) {
	names := Expand([]observability.Name{option("search.sort", "search", "alpha", "retail"), option("news.syp_sort", "newspaper/syp", "edition")}, Lists{})
	totals := []observability.DayTotal{tot(0, "page.view", "", "search", 900, 9), tot(0, "page.view", "", "newspaper/syp", 90, 4)}
	if m, most := Measured(names, totals, w30); m != 0 || most != 9 {
		t.Errorf("young: %d measured, most %d", m, most)
	}
	totals[0].Days = 30
	if m, most := Measured(names, totals, w30); m != 2 || most != 4 {
		t.Errorf("search measured: %d, most %d", m, most)
	}
}

// The flat band: within flatPercent of the earlier figure, either way, is flat; past it is a word; zero cases.
func TestTrendOfFlatBand(t *testing.T) {
	cases := []struct {
		now, before int64
		want        string
	}{
		{110, 100, TrendFlat}, {111, 100, TrendUp},
		{90, 100, TrendFlat}, {89, 100, TrendDown},
		{100, 100, TrendFlat},
		{1, 0, TrendUp}, {0, 0, TrendFlat}, {0, 5, TrendDown},
	}
	for _, tc := range cases {
		if got := trendOf(tc.now, tc.before); got != tc.want {
			t.Errorf("%d against %d: %q, want %q", tc.now, tc.before, got, tc.want)
		}
	}
	if flatPercent != 10 {
		t.Errorf("flatPercent = %d, the ruling is 10", flatPercent)
	}
	// through PreviousText: a count row from an earlier zero is up
	if _, trend := PreviousText(Signal{Section: SectionWalls, Count: 3}, 30, 30); trend != TrendUp {
		t.Errorf("from zero: %q", trend)
	}
	if _, trend := PreviousText(Signal{Section: SectionWalls, Count: 0}, 30, 30); trend != TrendFlat {
		t.Errorf("both zero: %q", trend)
	}
}
