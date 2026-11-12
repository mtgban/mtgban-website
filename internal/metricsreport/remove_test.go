package metricsreport

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func tot(period int, name, scope, value string, n int64, days int) observability.DayTotal {
	last := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -period*30)
	return observability.DayTotal{Period: period, Name: name, Scope: scope, Value: value, N: n, Days: days, First: last.AddDate(0, 0, -(days - 1)), Last: last}
}

func find(cs []Candidate, name, scope, value string) (Candidate, bool) {
	for _, c := range cs {
		if c.Name == name && c.Scope == scope && c.Value == value {
			return c, true
		}
	}
	return Candidate{}, false
}

var w30 = Window{Days: 30, Signed: true, Humans: true}

func option(name, page string, enum ...string) observability.Name {
	return observability.Name{Name: name, Family: observability.FamilyServer, Values: observability.ValueEnum, Enum: enum,
		Area: "search", Page: page, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "option", Help: "h"}
}

// finite fails the test on any rate that is NaN or infinite.
func finite(t *testing.T, cs []Candidate) {
	t.Helper()
	for _, c := range cs {
		if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) {
			t.Errorf("%s %s %s: rate %v", c.Name, c.Scope, c.Value, c.Rate)
		}
	}
}

func TestRemoveClasses(t *testing.T) {
	names := []observability.Name{
		option("search.sort", "search", "chrono", "alpha", "retail", "buylist"),
		option("news.syp_sort", "newspaper/syp", "edition"),
		option("sleepers.gap", "sleepers/gap", "custom"),
		{Name: "ui.row.velocity", Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"open"},
			Area: "search", Page: "search", Report: observability.ReportCandidate, Kind: "control", Help: "h"},
		{Name: "search.result", Family: observability.FamilyServer, Values: observability.ValueEnum, Enum: []string{"empty"},
			Area: "search", Page: "search", Report: observability.ReportSignal, Help: "h"},
	}
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30),
		tot(0, "page.view", "", "search", 10000, 30),
		tot(0, "page.view", "", "newspaper/syp", 400, 20),
		tot(0, "page.view", "", "sleepers/gap", 90, 13),
		tot(0, "search.sort", "", "chrono", 9000, 30),
		tot(0, "search.sort", "", "retail", 49, 12),  // 0.49% of 10,000
		tot(0, "search.sort", "", "buylist", 50, 12), // 0.50%: in use
		tot(1, "search.sort", "", "alpha", 3, 1),     // only before the window
	}
	got := Remove(names, nil, totals, nil, w30)
	finite(t, got)

	want := map[[2]string]string{
		{"search.sort", "alpha"}:     "unused",
		{"search.sort", "retail"}:    "rare",
		{"news.syp_sort", "edition"}: "unused_so_far",
		{"sleepers.gap", "custom"}:   "not_measured", // 13 days, under 14
		{"ui.row.velocity", "open"}:  "not_measured", // no ui.load at all
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for key, class := range want {
		c, ok := find(got, key[0], "", key[1])
		if !ok || c.Class != class {
			t.Errorf("%s %s: class %q found %v, want %q", key[0], key[1], c.Class, ok, class)
		}
		if c.Changes != -1 || c.Requests != -1 {
			t.Errorf("%s %s: changes %d requests %d, want -1 and -1 on a name's row", key[0], key[1], c.Changes, c.Requests)
		}
	}
	alpha, _ := find(got, "search.sort", "", "alpha")
	if alpha.Count != 0 || alpha.Denom != 10000 || alpha.DaysMeasured != 30 || alpha.LastSeen.IsZero() {
		t.Errorf("alpha = %+v: the count is the window's, last seen reaches before it", alpha)
	}
	retail, _ := find(got, "search.sort", "", "retail")
	if retail.Count != 49 || retail.Rate >= rareRequestShare {
		t.Errorf("retail = %+v", retail)
	}
	syp, _ := find(got, "news.syp_sort", "", "edition")
	if syp.DaysMeasured != 20 {
		t.Errorf("the syp sort measured %d days, want 20", syp.DaysMeasured)
	}
	if got[0].Class != "unused" || got[len(got)-1].Class != "not_measured" {
		t.Errorf("order: first %q last %q", got[0].Class, got[len(got)-1].Class)
	}
}

func TestRemoveReviewed(t *testing.T) {
	names := []observability.Name{option("search.sort", "search", "alpha")}
	totals := []observability.DayTotal{tot(0, "page.view", "", "search", 10000, 30)}
	reviews := []Review{
		{Name: "search.sort", Value: "alpha", Verdict: "keep", Note: "the bot sorts this way"},
		{Name: "search.sort", Value: "gone", Verdict: "remove"}, // no such unit
	}
	got := Remove(names, nil, totals, reviews, w30)
	if len(got) != 1 || got[0].Class != "reviewed" || got[0].Verdict != "keep" || got[0].Note != "the bot sorts this way" || got[0].Denom != 10000 {
		t.Fatalf("got %+v", got)
	}
}

// A control is rare under 1 use per 1,000 loads of its page.
func TestRemoveRareControl(t *testing.T) {
	ctl := observability.Name{Name: "ui.row.tab", Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"sellers", "buyers"},
		Area: "search", Page: "search", Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	totals := []observability.DayTotal{
		tot(0, "ui.load", "search", "", 5000, 30),
		tot(0, "ui.row.tab", "", "sellers", 4, 3), // 0.8 per 1,000
		tot(0, "ui.row.tab", "", "buyers", 5, 3),  // 1.0 per 1,000: in use
	}
	got := Remove([]observability.Name{ctl}, nil, totals, nil, w30)
	if len(got) != 1 || got[0].Value != "sellers" || got[0].Class != "rare" || got[0].Denom != 5000 {
		t.Fatalf("got %+v", got)
	}
}

// A page is unused or not; it is never rare.
func TestRemovePages(t *testing.T) {
	pages := Expand([]observability.Name{{Name: "page.view", Family: observability.FamilyServer, Values: observability.ValuePage,
		Area: "site", Report: observability.ReportCandidate, Kind: "page", Help: "h"}},
		Lists{Pages: []string{"search", "screener", "reverse"}})
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30),
		tot(0, "page.view", "", "search", 99999, 30),
		tot(0, "page.view", "", "reverse", 1, 1), // one view in a hundred thousand: still not rare
	}
	got := Remove(pages, nil, totals, nil, w30)
	if len(got) != 1 || got[0].Value != "screener" || got[0].Class != "unused" || got[0].DaysMeasured != 30 {
		t.Fatalf("got %+v", got)
	}
}

// A 90-day window sums periods 0 to 2 and ignores 3 to 5 for the count.
func TestRemoveSumsTheWindowsPeriods(t *testing.T) {
	names := []observability.Name{option("search.sort", "search", "alpha")}
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "search", 1000, 30), tot(1, "page.view", "", "search", 1000, 30), tot(2, "page.view", "", "search", 1000, 30),
		tot(3, "page.view", "", "search", 1000, 30),
		tot(4, "search.sort", "", "alpha", 500, 9),
	}
	got := Remove(names, nil, totals, nil, Window{Days: 90})
	if len(got) != 1 || got[0].Class != "unused" || got[0].Denom != 3000 || got[0].DaysMeasured != 90 {
		t.Fatalf("got %+v", got)
	}
}

func TestRemoveDenominators(t *testing.T) {
	cand := func(name string, family observability.Family, page, denom, value string) observability.Name {
		return observability.Name{Name: name, Family: family, Values: observability.ValueEnum, Enum: []string{value},
			Area: "a", Page: page, Denom: denom, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "option", Help: "h"}
	}
	names := []observability.Name{
		cand("upload.option", observability.FamilyServer, "upload", "upload.source", "lowval"), // Denom wins over Page
		cand("export.decklist", observability.FamilyServer, "search,sealed", "", "tcgplayer"),  // a two-page list
		cand("view.toggle", observability.FamilyServer, "*", "", "to_mobile"),                  // every page
		cand("ui.row.velocity", observability.FamilyUI, "search, sealed", "", "open"),          // a list with a space
		cand("ui.palette.open", observability.FamilyUI, "*", "", "slash"),
		cand("discord.message", observability.FamilyServer, "", "", "brackets"), // neither: days flushed
	}
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30),
		tot(0, "page.view", "", "upload", 9000, 30), // not upload.option's denominator
		tot(0, "page.view", "", "search", 700, 30),
		tot(0, "page.view", "", "sealed", 300, 18),
		tot(0, "page.view", "", "other", 50, 9),
		tot(0, "upload.source", "", "text", 150, 30),
		tot(0, "upload.source", "", "file_csv", 50, 22),
		tot(0, "ui.load", "search", "", 4000, 30),
		tot(0, "ui.load", "sealed", "", 1000, 30),
		tot(0, "ui.load", "sets", "", 500, 30),
		tot(0, "upload.option", "", "lowval", 1, 1),      // 1 of 200 is 0.5%: in use; of 9,000 it would be rare
		tot(0, "export.decklist", "", "tcgplayer", 4, 2), // 4 of 1,000: rare
		tot(0, "view.toggle", "", "to_mobile", 5, 3),     // 5 of 10,050: rare
		tot(0, "ui.row.velocity", "", "open", 4, 2),      // 0.8 per 1,000 of 5,000: rare
		tot(0, "ui.palette.open", "", "slash", 5, 2),     // 0.9 per 1,000 of 5,500: rare
		tot(0, "discord.message", "", "card", 7, 5),      // the bot runs here, so brackets is judged
	}
	got := Remove(names, nil, totals, nil, w30)
	finite(t, got)
	want := map[string]struct {
		class string
		denom int64
		days  int
	}{
		"export.decklist": {"rare", 1000, 30},  // search 700 + sealed 300; days are the fuller page's
		"view.toggle":     {"rare", 10050, 30}, // every page.view row, other included
		"ui.row.velocity": {"rare", 5000, 30},  // ui.load search + sealed, not sets
		"ui.palette.open": {"rare", 5500, 30},  // every ui.load row
		"discord.message": {"unused", 0, 30},   // no count denominator, 30 flushed days
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d (upload.option is in use against upload.source): %+v", len(got), len(want), got)
	}
	for _, c := range got {
		w, ok := want[c.Name]
		if !ok || c.Class != w.class || c.Denom != w.denom || c.DaysMeasured != w.days {
			t.Errorf("%s = class %q denom %d days %d, want %+v", c.Name, c.Class, c.Denom, c.DaysMeasured, w)
		}
	}
}

// A set Denom with no rows is not measured; the Page is no fallback for it.
func TestRemoveDenomNameWithNoRowsIsNotMeasured(t *testing.T) {
	n := option("upload.option", "upload", "lowval")
	n.Denom = "upload.source"
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30),
		tot(0, "page.view", "", "upload", 9000, 30),
	}
	got := Remove([]observability.Name{n}, nil, totals, nil, w30)
	if len(got) != 1 || got[0].Class != "not_measured" || got[0].Denom != 0 || got[0].DaysMeasured != 0 || got[0].RateText != "" {
		t.Fatalf("got %+v", got)
	}
}

// A ui. name with no Page or Denom is measured only on days with a ui.load.
func TestRemoveUINameWithNoPageNeedsAnyLoad(t *testing.T) {
	n := observability.Name{Name: "ui.help.open", Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"guide", "faq"},
		Area: "site", Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 43200, 30), tot(0, "ui.help.open", "", "faq", 3, 2)}
	got := Remove([]observability.Name{n}, nil, totals, nil, w30)
	if c, ok := find(got, "ui.help.open", "", "guide"); !ok || c.Class != "not_measured" || c.DaysMeasured != 0 {
		t.Fatalf("no ui.load: got %+v", got)
	}
	totals = append(totals, tot(0, "ui.load", "home", "", 800, 20))
	got = Remove([]observability.Name{n}, nil, totals, nil, w30)
	if c, ok := find(got, "ui.help.open", "", "guide"); len(got) != 1 || !ok || c.Class != "unused_so_far" || c.DaysMeasured != 20 || c.Denom != 0 {
		t.Fatalf("ui.load on 20 days: got %+v", got)
	}
	// ui.load on more days than the counter flushed is capped by the flushes.
	totals = []observability.DayTotal{tot(0, "metrics.flush", "", "", 100, 16), tot(0, "ui.load", "home", "", 800, 30), tot(0, "ui.help.open", "", "faq", 3, 2)}
	got = Remove([]observability.Name{n}, nil, totals, nil, w30)
	if c, ok := find(got, "ui.help.open", "", "guide"); len(got) != 1 || !ok || c.DaysMeasured != 16 {
		t.Fatalf("flushed on 16 days: got %+v", got)
	}
}

// A candidate with no value is one candidate, whatever scopes its rows carry.
func TestRemoveValueNoneIsOneCandidate(t *testing.T) {
	reverse := observability.Name{Name: "search.reverse", Family: observability.FamilyServer, Values: observability.ValueNone,
		Scope: observability.ScopeEnum, Scopes: []string{"search", "sealed", "sets"},
		Area: "search", Page: "search", Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "option", Help: "h"}
	if u := Units(reverse); len(u) != 1 || u[0] != (Unit{"search.reverse", "", ""}) {
		t.Fatalf("units = %v, want the name alone", u)
	}
	byScope := reverse
	byScope.Unit = observability.UnitScope
	if u := Units(byScope); len(u) != 1 || u[0] != (Unit{"search.reverse", "", ""}) {
		t.Errorf("a ValueNone name is one unit whatever its Unit says: %v", u)
	}
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "search", 2000, 30),
		tot(0, "search.reverse", "search", "", 3, 2),
		tot(0, "search.reverse", "sealed", "", 2, 1),
	}
	got := Remove([]observability.Name{reverse}, nil, totals, nil, w30)
	if len(got) != 1 || got[0].Scope != "" || got[0].Value != "" || got[0].Count != 5 || got[0].Class != "rare" {
		t.Fatalf("got %+v, want one rare candidate with the count of every scope", got)
	}
	marked := Remove([]observability.Name{reverse}, nil, totals, []Review{{Name: "search.reverse", Verdict: "keep"}}, w30)
	if len(marked) != 1 || marked[0].Class != "reviewed" {
		t.Errorf("a review keyed by the name alone marks it: %+v", marked)
	}
}

func TestUnits(t *testing.T) {
	base := observability.Name{Name: "search.view", Report: observability.ReportCandidate,
		Scope: observability.ScopeEnum, Scopes: []string{"SearchDefaultTab", "SearchDefaultView"},
		Values: observability.ValueEnum, Enum: []string{"a", "b", "c"}}
	byValue, byScope, both, bare := base, base, base, observability.Name{Name: "search.reverse", Report: observability.ReportCandidate}
	byValue.Unit, byScope.Unit, both.Unit = observability.UnitValue, observability.UnitScope, observability.UnitScopeAndValue
	if u := Units(byValue); len(u) != 3 || u[0] != (Unit{"search.view", "", "a"}) {
		t.Errorf("by value: %v", u)
	}
	if u := Units(byScope); len(u) != 2 || u[1] != (Unit{"search.view", "SearchDefaultView", ""}) {
		t.Errorf("by scope: %v", u)
	}
	if u := Units(both); len(u) != 6 || u[5] != (Unit{"search.view", "SearchDefaultView", "c"}) {
		t.Errorf("by scope and value: %v", u)
	}
	if u := Units(bare); len(u) != 1 || u[0] != (Unit{"search.reverse", "", ""}) {
		t.Errorf("no value: %v", u)
	}
	signal := base
	signal.Report = observability.ReportSignal
	if Units(signal) != nil {
		t.Error("only a candidate has units")
	}
	withOther := base
	withOther.Unit, withOther.Enum = observability.UnitValue, []string{"a", "other"}
	if u := Units(withOther); len(u) != 1 || u[0] != (Unit{"search.view", "", "a"}) {
		t.Errorf("other is a catch-all, never a unit: %v", u)
	}
	onlyOther := withOther
	onlyOther.Enum = []string{"other"}
	if u := Units(onlyOther); u != nil {
		t.Errorf("a name whose only value is other has no value units: %v", u)
	}
	onlyOther.Unit = observability.UnitScope
	if u := Units(onlyOther); len(u) != 2 {
		t.Errorf("by scope, other in the enum does not matter: %v", u)
	}
	bucket := base
	bucket.Values, bucket.Enum = observability.ValueBucket, []string{"0", "1-9", "10+"}
	for _, unit := range []observability.UnitKind{observability.UnitValue, observability.UnitScope, observability.UnitScopeAndValue} {
		bucket.Unit = unit
		if u := Units(bucket); len(u) != 1 || u[0] != (Unit{"search.view", "", ""}) {
			t.Errorf("a bucket name is one unit, the name: %v", u)
		}
	}
	empty := base
	empty.Unit, empty.Enum = observability.UnitScopeAndValue, nil
	if u := Units(empty); len(u) != 2 || u[0] != (Unit{"search.view", "SearchDefaultTab", ""}) {
		t.Errorf("an empty enum is the single entry \"\": %v", u)
	}
}

// A unit's count sums every row matching its key, across the dimension it leaves blank.
func TestRemoveCountsAUnitAcrossTheOtherDimension(t *testing.T) {
	base := observability.Name{Name: "search.view", Family: observability.FamilyServer, Page: "search",
		Scope: observability.ScopeEnum, Scopes: []string{"SearchDefaultTab", "SearchDefaultView"},
		Values: observability.ValueEnum, Enum: []string{"a", "b", "c"},
		Area: "settings", Report: observability.ReportCandidate, Kind: "setting", Help: "h"}
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "search", 1000, 30),
		tot(0, "search.view", "SearchDefaultTab", "a", 2, 2),
		tot(0, "search.view", "SearchDefaultTab", "b", 3, 3),
	}

	byScope := base
	byScope.Unit = observability.UnitScope
	got := Remove([]observability.Name{byScope}, nil, totals, nil, w30)
	if _, ok := find(got, "search.view", "SearchDefaultTab", ""); ok {
		t.Errorf("SearchDefaultTab counts 5 and is in use: %+v", got)
	}
	if c, ok := find(got, "search.view", "SearchDefaultView", ""); !ok || c.Count != 0 || c.Class != "unused" {
		t.Errorf("SearchDefaultView: %+v", got)
	}

	byValue := base
	byValue.Unit = observability.UnitValue
	byValue.Page = ""
	byValue.Denom = "search.result"
	withDenom := append(slices.Clone(totals), tot(0, "search.result", "search", "found", 1000, 30))
	got = Remove([]observability.Name{byValue}, nil, withDenom, nil, w30)
	if c, ok := find(got, "search.view", "", "a"); !ok || c.Count != 2 || c.Class != "rare" {
		t.Errorf("value a has count 2 whatever the scope: %+v", got)
	}
	if c, ok := find(got, "search.view", "", "c"); !ok || c.Class != "unused" {
		t.Errorf("value c is unused: %+v", got)
	}

	both := base
	both.Unit = observability.UnitScopeAndValue
	reviews := []Review{{Name: "search.view", Scope: "SearchDefaultTab", Value: "a", Verdict: "watch"}}
	got = Remove([]observability.Name{both}, nil, totals, reviews, w30)
	if c, ok := find(got, "search.view", "SearchDefaultTab", "c"); !ok || c.Class != "unused" {
		t.Errorf("(SearchDefaultTab, c) is unused: %+v", got)
	}
	if c, ok := find(got, "search.view", "SearchDefaultTab", "a"); !ok || c.Count != 2 || c.Class != "reviewed" {
		t.Errorf("(SearchDefaultTab, a) has count 2: %+v", got)
	}
}

// A server candidate with no Page or Denom is judged by the days the counter flushed, never rare,
// and only once its own name has a row: with none, nothing shows the feature runs on this site.
func TestRemoveServerNameWithNoPage(t *testing.T) {
	n := option("discord.store_link", "", "ck", "tcg")
	flush30 := tot(0, "metrics.flush", "", "", 43200, 30)
	cases := []struct {
		label  string
		totals []observability.DayTotal
		ck     string // ck's class, "" for in use
		basis  string
		days   int
	}{
		{"no row of the name at all", []observability.DayTotal{flush30}, "not_measured", noRowsBasis, 0},
		{"a row only before the window", []observability.DayTotal{flush30, tot(1, "discord.store_link", "", "tcg", 9, 4)}, "not_measured", noRowsBasis, 0},
		{"a row of another value", []observability.DayTotal{flush30, tot(0, "discord.store_link", "", "tcg", 9, 4)}, "unused", "days the counter flushed", 30},
		{"a row of an unlisted value", []observability.DayTotal{flush30, tot(0, "discord.store_link", "", "other", 1, 1)}, "unused", "days the counter flushed", 30},
		{"nine rows", []observability.DayTotal{flush30, tot(0, "discord.store_link", "", "ck", 9, 4)}, "", "", 0},
		{"flushed on 10 days", []observability.DayTotal{tot(0, "metrics.flush", "", "", 14400, 10), tot(0, "discord.store_link", "", "tcg", 9, 4)}, "not_measured", "days the counter flushed", 10},
	}
	for _, tc := range cases {
		got := Remove([]observability.Name{n}, nil, tc.totals, nil, w30)
		finite(t, got)
		c, ok := find(got, "discord.store_link", "", "ck")
		switch {
		case tc.ck == "" && ok:
			t.Errorf("%s: got %+v, want ck in use", tc.label, c)
		case tc.ck != "" && (!ok || c.Class != tc.ck || c.Denom != 0 || c.RateText != "" || c.Basis != tc.basis || c.DaysMeasured != tc.days):
			t.Errorf("%s: got %+v, want %s on %q over %d days", tc.label, c, tc.ck, tc.basis, tc.days)
		}
	}
	// A ui. name with ui.load on every day and no row of its own is not measured either.
	ui := observability.Name{Name: "ui.help.open", Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"guide"},
		Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	got := Remove([]observability.Name{ui}, nil, []observability.DayTotal{flush30, tot(0, "ui.load", "home", "", 800, 30)}, nil, w30)
	if len(got) != 1 || got[0].Class != "not_measured" || got[0].Basis != noRowsBasis {
		t.Errorf("ui. name with no rows: %+v", got)
	}
}

// A page- or Denom-gated name with no row of its own keeps its rule: the traffic is the evidence.
func TestRemoveGatedNameWithNoRowsIsStillJudged(t *testing.T) {
	paged := option("sets.sort", "sets", "date")
	denomed := option("search.sort", "", "alpha")
	denomed.Denom = "search.result"
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "sets", 900, 30),
		tot(0, "search.result", "", "found", 900, 30),
	}
	got := Remove([]observability.Name{paged, denomed}, nil, totals, nil, w30)
	if len(got) != 2 || got[0].Class != "unused" || got[1].Class != "unused" {
		t.Errorf("got %+v", got)
	}
}

// Rare rows rank by how far under their own family's line they are.
func TestRemoveRareOrderIsRelativeToTheLine(t *testing.T) {
	ctl := observability.Name{Name: "a.control", Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"v"},
		Page: "search", Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	names := []observability.Name{ctl, option("b.option", "search", "v"), option("c.option", "search", "v")}
	totals := []observability.DayTotal{
		tot(0, "ui.load", "search", "", 10000, 30),
		tot(0, "page.view", "", "search", 10000, 30),
		tot(0, "a.control", "", "v", 8, 3), // 0.8 per 1,000: 0.8 of its line
		tot(0, "b.option", "", "v", 10, 3), // 0.1%: 0.2 of its line
		tot(0, "c.option", "", "v", 40, 3), // 0.4%: 0.8 of its line, a tie broken by name
	}
	got := Remove(names, nil, totals, nil, w30)
	var order []string
	for _, c := range got {
		order = append(order, c.Name)
	}
	if want := []string{"b.option", "a.control", "c.option"}; !slices.Equal(order, want) {
		t.Errorf("order %v, want %v", order, want)
	}
}

// The text is rounded down, so a rare row never prints its line, and rare is decided on integers.
func TestRateTextNeverReachesTheLine(t *testing.T) {
	cases := []struct {
		ui           bool
		count, denom int64
		text         string
		rare         bool
	}{
		{true, 24, 25000, "0.9 per 1,000 loads", true},    // 0.96
		{true, 95, 100000, "0.9 per 1,000 loads", true},   // 0.95
		{true, 999, 1000000, "0.9 per 1,000 loads", true}, // 0.999
		{true, 5, 5000, "1.0 per 1,000 loads", false},
		{false, 495, 100000, "0.49% of requests", true},   // 0.495%
		{false, 4999, 1000000, "0.49% of requests", true}, // 0.4999%
		{false, 50, 10000, "0.50% of requests", false},
		{false, 1, 200, "0.50% of requests", false},
		{false, 1, 3, "33.33% of requests", false},
	}
	for _, tc := range cases {
		family, word := observability.FamilyServer, "requests"
		if tc.ui {
			family, word = observability.FamilyUI, "loads"
		}
		if got := rateText(tc.ui, tc.count, tc.denom, word, false); got != tc.text {
			t.Errorf("%d of %d: %q, want %q", tc.count, tc.denom, got, tc.text)
		}
		if got := isRare(family, tc.count, tc.denom); got != tc.rare {
			t.Errorf("%d of %d: rare %v, want %v", tc.count, tc.denom, got, tc.rare)
		}
	}
	if rareLoadsLine != 1 || rareRequestsLine != 5 {
		t.Errorf("lines %d and %d per 1,000, want 1 and 5", rareLoadsLine, rareRequestsLine)
	}
}

// The days measured edges: 13 and 14 for measured at all, the window's length and one less for unused.
func TestRemoveDaysMeasuredBoundaries(t *testing.T) {
	n := option("search.sort", "search", "alpha")
	cases := []struct {
		w     Window
		days  []int // page.view days in each window period
		class string
	}{
		{w30, []int{13}, "not_measured"},
		{w30, []int{14}, "unused_so_far"},
		{w30, []int{29}, "unused_so_far"},
		{w30, []int{30}, "unused"},
		{Window{Days: 90}, []int{30, 30, 29}, "unused_so_far"},
		{Window{Days: 90}, []int{30, 30, 30}, "unused"},
		{Window{Days: 90}, []int{0, 0, 13}, "not_measured"},
		{Window{Days: 180}, []int{30, 30, 30, 30, 30, 30}, "unused"},
	}
	for _, tc := range cases {
		var totals []observability.DayTotal
		sum := 0
		for p, d := range tc.days {
			if d > 0 {
				totals = append(totals, tot(p, "page.view", "", "search", 500, d))
			}
			sum += d
		}
		got := Remove([]observability.Name{n}, nil, totals, nil, tc.w)
		if len(got) != 1 || got[0].Class != tc.class || got[0].DaysMeasured != sum {
			t.Errorf("%d-day window, days %v: got %+v, want %s on %d days", tc.w.Days, tc.days, got, tc.class, sum)
		}
	}
}

// A denominator with rows that sum to zero measures days but has no rate.
func TestRemoveZeroDenominator(t *testing.T) {
	n := option("search.sort", "search", "alpha")
	totals := []observability.DayTotal{tot(0, "page.view", "", "search", 0, 30)}
	got := Remove([]observability.Name{n}, nil, totals, nil, w30)
	if len(got) != 1 || got[0].Class != "unused" || got[0].Denom != 0 || got[0].Rate != 0 || got[0].RateText != "" {
		t.Fatalf("zero total: got %+v", got)
	}
	totals = append(totals, tot(0, "search.sort", "", "alpha", 3, 2))
	got = Remove([]observability.Name{n}, nil, totals, nil, w30)
	if len(got) != 0 {
		t.Fatalf("uses against a zero denominator are in use, never rare: %+v", got)
	}
}

// The names whose Denom is wider than their population are never rare.
func TestRemoveWiderDenomIsNeverRare(t *testing.T) {
	mk := func(name string) observability.Name {
		n := option(name, "", "x", "y")
		n.Denom = "upload.mode"
		return n
	}
	totals := []observability.DayTotal{
		tot(0, "upload.mode", "", "retail", 8000, 30),
		tot(0, "upload.mode", "", "buylist", 1000, 30),
		tot(0, "upload.option", "", "x", 1, 1),
		tot(0, "upload.sorting", "", "x", 1, 1),
	}
	got := Remove([]observability.Name{mk("upload.option"), mk("upload.sorting")}, nil, totals, nil, w30)
	if _, ok := find(got, "upload.option", "", "x"); ok {
		t.Errorf("upload.option x is in use, not rare: %+v", got)
	}
	if c, ok := find(got, "upload.sorting", "", "x"); !ok || c.Class != "rare" {
		t.Errorf("upload.sorting x with the same numbers is rare: %+v", got)
	}
	y, ok := find(got, "upload.option", "", "y")
	if !ok || y.Class != "unused" || y.RateText != "0.00% of upload.mode (of a wider population; see help)" {
		t.Errorf("upload.option y = %+v", y)
	}
	if c, _ := find(got, "upload.sorting", "", "x"); c.RateText != "0.01% of upload.mode" {
		t.Errorf("upload.sorting rate text %q", c.RateText)
	}
}

func TestWiderDenomMatchesTheRegistry(t *testing.T) {
	reg := map[string]observability.Name{}
	for _, n := range observability.All() {
		reg[n.Name] = n
	}
	for name, denom := range widerDenom {
		n, ok := reg[name]
		if !ok || n.Denom != denom || n.Report != observability.ReportCandidate {
			t.Errorf("%s: registered %v with Denom %q, want a candidate with Denom %q", name, ok, n.Denom, denom)
		}
	}
	if len(widerDenom) != 3 {
		t.Errorf("the list holds %d names, want api.option, upload.option and upload.price_source", len(widerDenom))
	}
}

func TestRemoveRateText(t *testing.T) {
	ui := func(name, page, denom string) observability.Name {
		return observability.Name{Name: name, Family: observability.FamilyUI, Values: observability.ValueEnum, Enum: []string{"v"},
			Page: page, Denom: denom, Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	}
	withDenom := option("search.sort", "", "v")
	withDenom.Denom = "search.result"
	names := []observability.Name{ui("ui.row.tab", "search", ""), ui("ui.palette.mode", "", "ui.palette.open"), option("sets.sort", "sets", "v"), withDenom}
	totals := []observability.DayTotal{
		tot(0, "ui.load", "search", "", 5000, 30),
		tot(0, "ui.palette.open", "", "slash", 5000, 30),
		tot(0, "page.view", "", "sets", 10000, 30),
		tot(0, "search.result", "", "found", 1000, 30),
		tot(0, "ui.row.tab", "", "v", 4, 3),
		tot(0, "ui.palette.mode", "", "v", 4, 3),
		tot(0, "sets.sort", "", "v", 49, 3),
		tot(0, "search.sort", "", "v", 4, 3),
	}
	got := Remove(names, nil, totals, nil, w30)
	want := map[string]string{
		"ui.row.tab":      "0.8 per 1,000 loads",
		"ui.palette.mode": "0.8 per 1,000 ui.palette.open",
		"sets.sort":       "0.49% of requests",
		"search.sort":     "0.40% of search.result",
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, c := range got {
		if c.RateText != want[c.Name] || c.Class != "rare" {
			t.Errorf("%s: %q class %q, want %q rare", c.Name, c.RateText, c.Class, want[c.Name])
		}
	}
	if c, _ := find(got, "ui.row.tab", "", "v"); c.Rate != 0.0008 || c.Basis != "ui.load on search" {
		t.Errorf("a control's rate is a fraction too: %+v", c)
	}
}

func TestRemoveOrder(t *testing.T) {
	names := []observability.Name{
		option("b.unused", "big", "v"),
		option("a.unused", "small", "v"),
		option("c.unused", "small", "v"),
		option("a.rare", "big", "v"),
		option("b.rare", "big", "v"),
		option("a.sofar", "short", "v"),
		option("b.sofar", "shorter", "v"),
		option("a.none", "nowhere", "v"),
	}
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "big", 100000, 30),
		tot(0, "page.view", "", "small", 1000, 30),
		tot(0, "page.view", "", "short", 1000, 15),
		tot(0, "page.view", "", "shorter", 1000, 20),
		tot(0, "a.rare", "", "v", 400, 9), // 0.4%
		tot(0, "b.rare", "", "v", 100, 9), // 0.1%
	}
	reviews := []Review{{Name: "c.unused", Value: "v", Verdict: "keep"}}
	got := Remove(names, nil, totals, reviews, w30)
	var order []string
	for _, c := range got {
		order = append(order, c.Name)
	}
	want := []string{"b.unused", "a.unused", "b.rare", "a.rare", "b.sofar", "a.sofar", "a.none", "c.unused"}
	if !slices.Equal(order, want) {
		t.Errorf("order %v, want %v", order, want)
	}
}

// The same input in any order gives the same slice.
func TestRemoveIsDeterministic(t *testing.T) {
	names := Expand([]observability.Name{
		option("search.sort", "search,sealed", "chrono", "alpha", "retail"),
		{Name: "page.view", Values: observability.ValuePage, Report: observability.ReportCandidate, Kind: "page", Help: "h"},
		{Name: "alerts.create", Values: observability.ValueEnum, Enum: []string{"retail"}, Scope: observability.ScopePage,
			Page: "search,alerts", Report: observability.ReportCandidate, Unit: observability.UnitScope, Kind: "control", Help: "h"},
	}, Lists{Pages: []string{"search", "sealed", "alerts", "home"}})
	totals := []observability.DayTotal{
		tot(0, "metrics.flush", "", "", 43200, 30),
		tot(0, "page.view", "", "search", 10000, 30),
		tot(0, "page.view", "", "sealed", 3000, 25),
		tot(0, "page.view", "", "alerts", 50, 16),
		tot(1, "page.view", "", "home", 50, 16),
		tot(0, "search.sort", "", "retail", 20, 5),
		tot(0, "search.sort", "sealed", "retail", 20, 5),
		tot(1, "search.sort", "", "alpha", 1, 1),
		tot(0, "alerts.create", "search", "retail", 2, 2),
	}
	first := Remove(names, nil, totals, nil, w30)
	finite(t, first)
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := slices.Clone(totals)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := Remove(names, nil, shuffled, nil, w30); !slices.Equal(got, first) {
			t.Fatalf("shuffled input gave %+v, want %+v", got, first)
		}
	}
}

// Stock and state names are standing counts and settings, not candidates in this phase.
func TestRemoveSkipsStockAndState(t *testing.T) {
	stock := option("stock.rows", "", "v")
	stock.Family = observability.FamilyStock
	state := option("state.set", "", "v")
	state.Family = observability.FamilyState
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 43200, 30)}
	if got := Remove([]observability.Name{stock, state}, nil, totals, nil, w30); got != nil {
		t.Errorf("got %+v", got)
	}
}

// Every candidate carries its registry Help, area and kind unchanged.
func TestRemoveCarriesHelp(t *testing.T) {
	n := option("arbit.toggle", "arbit", "tradable")
	n.Area, n.Kind = "arbit", "option"
	n.Help = "An on/off option set away from the page's default, chosen by the reader, defaults not counted."
	got := Remove([]observability.Name{n}, nil, []observability.DayTotal{tot(0, "page.view", "", "arbit", 900, 30)}, nil, w30)
	if len(got) != 1 || got[0].Help != n.Help || got[0].Area != "arbit" || got[0].Kind != "option" || got[0].Basis != "page.view on arbit" {
		t.Fatalf("got %+v", got)
	}
}

func TestRemoveDegrades(t *testing.T) {
	if Remove(nil, nil, nil, nil, w30) != nil {
		t.Error("an empty registry has no candidates")
	}
	names := []observability.Name{option("search.sort", "search", "alpha", "chrono")}
	got := Remove(names, []observability.Setting{{Name: "UploadSorting", Path: "upload", Class: "preference"}}, nil, nil, w30)
	if len(got) != 3 || got[0].Class != "not_measured" || got[1].Class != "not_measured" || got[2].Class != "not_measured" ||
		got[2].Name != "state.set" || got[2].Scope != "UploadSorting" || got[2].Value != "" {
		t.Errorf("with no rows at all every candidate is not measured, a setting's row included: %+v", got)
	}
	if got := Remove(names, nil, []observability.DayTotal{tot(0, "page.view", "", "search", 10000, 30)}, nil, Window{}); len(got) != 2 || got[0].Class != "not_measured" {
		t.Errorf("a zero window measures nothing: %+v", got)
	}
}

func TestExpand(t *testing.T) {
	in := []observability.Name{
		{Name: "page.view", Values: observability.ValuePage},
		{Name: "go.click", Scope: observability.ScopeStore, Values: observability.ValueEnum, Enum: []string{"r"}},
		{Name: "http.status", Scope: observability.ScopeRoute},
		{Name: "alerts.create", Scope: observability.ScopePage, Page: "search, alerts"},
		{Name: "settings.values_fetch", Scope: observability.ScopePage},
		{Name: "any.page", Scope: observability.ScopePage, Page: "*"},
		{Name: "arbit.source", Values: observability.ValueStore, Scope: observability.ScopeSetting},
	}
	out := Expand(in, Lists{Pages: []string{"search", "home"}, Stores: []string{"CK"}, Routes: []string{"home"}})
	if !slices.Equal(out[0].Enum, []string{"search", "home"}) || !slices.Equal(out[1].Scopes, []string{"CK"}) || !slices.Equal(out[2].Scopes, []string{"home"}) {
		t.Errorf("out = %+v", out)
	}
	if in[0].Enum != nil || !slices.Equal(out[1].Enum, []string{"r"}) {
		t.Error("the input is not modified and a real enum is kept")
	}
	if !slices.Equal(out[3].Scopes, []string{"search", "alerts"}) {
		t.Errorf("a ScopePage name with a Page list takes that list: %v", out[3].Scopes)
	}
	if !slices.Equal(out[4].Scopes, []string{"search", "home"}) || !slices.Equal(out[5].Scopes, []string{"search", "home"}) {
		t.Errorf("an empty or * Page takes every page: %v %v", out[4].Scopes, out[5].Scopes)
	}
	if !slices.Equal(out[6].Enum, []string{"CK"}) || out[6].Scopes != nil {
		t.Errorf("a store value is listed and a setting scope left alone: %+v", out[6])
	}
	if in[3].Scopes != nil || Expand(nil, Lists{}) != nil {
		t.Error("the input is not modified and nil stays nil")
	}
}

func TestTierLine(t *testing.T) {
	rows := []observability.DayTotal{
		{Name: "search.sort", Value: "alpha", Tier: "Legacy", N: 3},
		{Name: "search.sort", Value: "alpha", Tier: "Any", N: 12},
		{Name: "search.sort", Value: "retail", Tier: "Any", N: 99},
	}
	if got := TierLine(rows, Unit{"search.sort", "", "alpha"}); got != "Any 12, Legacy 3" {
		t.Errorf("got %q", got)
	}
	if got := TierLine(rows, Unit{"search.sort", "", "chrono"}); got != "" {
		t.Errorf("no rows gives %q, want empty", got)
	}
	tie := []observability.DayTotal{
		{Name: "n", Scope: "a", Tier: "Vintage", N: 2},
		{Name: "n", Scope: "b", Tier: "Modern", N: 1},
		{Name: "n", Scope: "b", Tier: "Modern", N: 1},
	}
	if got := TierLine(tie, Unit{Name: "n"}); got != "Modern 2, Vintage 2" {
		t.Errorf("a tie goes by tier name and a unit sums its scopes: %q", got)
	}
}

func TestThresholdsAreTheSpecs(t *testing.T) {
	if rarePerThousandLoads != 1.0 || rareRequestShare != 0.005 || rareReaderShare != 0.01 || rareReaderDays != 3 ||
		minDaysMeasured != 14 || newAfterDays != 30 || growthFactor != 1.5 || growthFloor != 50 {
		t.Error("a threshold moved from the roadmap's starting value")
	}
	if minRateDenom != 50 || periodDays != 30 {
		t.Error("a threshold moved from this plan's starting value")
	}
}

// A per-page unit is rated against its own page's views, never the busier page on its list.
func TestRemovePerPageUnitUsesItsOwnPage(t *testing.T) {
	create := observability.Name{Name: "alerts.create", Family: observability.FamilyServer, Scope: observability.ScopePage, Page: "search,alerts",
		Values: observability.ValueEnum, Enum: []string{"retail", "buylist"},
		Unit: observability.UnitScope, Area: "alerts", Report: observability.ReportCandidate, Kind: "control", Help: "h"}
	names := Expand([]observability.Name{create}, Lists{Pages: []string{"alerts", "search", "sets"}})
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "search", 100000, 30),
		tot(0, "page.view", "", "alerts", 100, 20),
		tot(0, "alerts.create", "alerts", "retail", 10, 10), // 10% of the alerts page
		tot(0, "alerts.create", "search", "retail", 10, 10), // 0.01% of search
	}
	got := Remove(names, nil, totals, nil, w30)
	if c, ok := find(got, "alerts.create", "alerts", ""); ok {
		t.Errorf("10 of 100 alerts views is in use, not %q against %d", c.Class, c.Denom)
	}
	c, ok := find(got, "alerts.create", "search", "")
	if !ok || c.Class != ClassRare || c.Denom != 100000 || c.DaysMeasured != 30 || c.Basis != "page.view on search" {
		t.Errorf("on search: %+v", c)
	}
	// a quiet page is measured on its own days
	totals[2].N = 0
	if c, ok := find(Remove(names, nil, totals, nil, w30), "alerts.create", "alerts", ""); !ok || c.Class != ClassUnusedSoFar || c.Denom != 100 || c.DaysMeasured != 20 {
		t.Errorf("unused on alerts: %+v", c)
	}
}

// A review no candidate carries is an orphan, in the reviews' order.
func TestOrphans(t *testing.T) {
	reviews := []Review{{Name: "old.name", Value: "x"}, {Name: "page.view", Value: "search"}, {Name: "page.view", Value: "hidden"}}
	cands := []Candidate{{Name: "page.view", Value: "search", Class: ClassReviewed}, {Name: "page.view", Value: "sets", Class: ClassUnused}}
	got := Orphans(reviews, cands)
	if len(got) != 2 || got[0].Name != "old.name" || got[1].Value != "hidden" {
		t.Errorf("got %+v", got)
	}
	if Orphans(nil, cands) != nil {
		t.Error("no reviews, no orphans")
	}
}

func settingsFixture() []observability.Setting {
	return []observability.Setting{
		{Name: "UploadSorting", Storage: "cookie", Path: "upload", Kind: "enum", Enum: []string{"setchrono", "highprice"}, Class: "preference", Area: "upload", Fact: "upload.sorting"},
		{Name: "UploadMaxQty", Storage: "cookie", Path: "upload", Kind: "number", Default: "0", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "maxqty"},
		{Name: "UploadMargin", Storage: "cookie", Path: "upload", Kind: "number", Default: "10", Class: "preference", Area: "upload"},
		{Name: "UploadMinVal", Storage: "cookie", Path: "upload", Kind: "number", Default: "1", Class: "preference", Area: "upload"},
		{Name: "ArbitVendorsList", Storage: "cookie", Path: "arbit", Kind: "list", Class: "preference", Area: "arbit", Fact: "arbit.excluded_vendors", FactScope: "arbit"},
		{Name: "SearchMiscOpts.noSussy", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "noSussy"},
		{Name: "NewspaperList", Storage: "cookie", Path: "newspaper", Kind: "list", Class: "preference", Area: "news"},
		{Name: "SleepersEditionList", Storage: "cookie", Path: "sleepers", Kind: "list", Class: "preference", Area: "sleepers"},
		{Name: "uploadTab", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	}
}

var w90 = Window{Days: 90, Signed: true, Humans: true} // periods 0 to 2 are the window, 3 to 5 the one before

func settingsTotals() []observability.DayTotal {
	return []observability.DayTotal{
		tot(0, "state.reader", "upload", "", 300, 30), tot(1, "state.reader", "upload", "", 300, 30),
		tot(2, "state.reader", "upload", "", 300, 30), // 900 reader-days on 90 days
		tot(3, "state.reader", "upload", "", 300, 30), // the window before: not in the denominator
		tot(0, "state.reader", "root", "", 600, 30), tot(1, "state.reader", "root", "", 600, 30),
		tot(2, "state.reader", "root", "", 600, 30),
		tot(0, "state.reader", "arbit", "", 100, 20),              // 20 days measured
		tot(0, "state.reader", "sleepers", "", 50, 10),            // under 14 days
		tot(0, "state.set", "UploadSorting", "highprice", 40, 30), // 40 of 900: in use
		tot(0, "state.set", "UploadMaxQty", "set", 1, 1),
		tot(2, "state.set", "UploadMaxQty", "set", 1, 1),          // 2 of 900: rare
		tot(0, "state.set", "UploadMargin", "set", 5, 5),          // 5 of 900: under 1% but 3 or more reader-days
		tot(3, "state.set", "UploadMinVal", "set", 4, 4),          // only before the window
		tot(0, "state.set", "SearchMiscOpts.noSussy", "on", 2, 2), // 2 of 1800: rare
		tot(0, "ui.settings.change", "UploadMaxQty", "set", 4, 1),
		tot(0, "upload.value_set", "", "maxqty", 31, 9),
		tot(0, "upload.value_set", "", "minval", 7, 3),
		tot(0, "upload.sorting", "", "highprice", 12, 5),
		tot(0, "upload.sorting", "", "setchrono", 3, 2),
		tot(0, "upload.sorting", "", "other", 50, 5), // a value outside the setting's Enum
		tot(0, "arbit.excluded_vendors", "arbit", "0", 500, 20),
		tot(0, "arbit.excluded_vendors", "arbit", "1-4", 6, 4),
		tot(0, "arbit.excluded_vendors", "reverse", "1-4", 99, 9),
		tot(0, "search.misc", "search", "noSussy", 8, 2), // a fact scoped by its path: every scope counts
		tot(1, "search.misc", "sealed", "noSussy", 3, 1),
		tot(0, "search.misc", "search", "skipEmpty", 50, 9),
	}
}

var changeName = []observability.Name{{Name: "ui.settings.change", Family: observability.FamilyUI, Report: observability.ReportContext}}

func TestRemoveClassesSettings(t *testing.T) {
	got := Remove(changeName, settingsFixture(), settingsTotals(), nil, w90)
	finite(t, got)

	if c, ok := find(got, "state.set", "UploadMaxQty", ""); !ok || c.Class != "rare" || c.Count != 2 || c.Denom != 900 || c.DaysMeasured != 90 ||
		c.Changes != 4 || c.Requests != 31 || c.Kind != "setting" || c.Area != "upload" || c.Help != "kept in a cookie, read on the upload page" ||
		!c.LastSeen.Equal(tot(0, "", "", "", 0, 1).Last) || c.RateText != "0.22% of reader-days" || c.NoRate != "" ||
		c.On != (CountedOn{Kind: OnReaders, Pages: "upload"}) || c.Basis != "state.reader on upload" {
		t.Errorf("UploadMaxQty = %+v", c)
	}
	if c, ok := find(got, "state.set", "UploadMinVal", ""); !ok || c.Class != "unused" || c.Count != 0 || c.Denom != 900 || c.Changes != 0 || c.Requests != -1 ||
		!c.LastSeen.Equal(tot(3, "", "", "", 0, 1).Last) {
		t.Errorf("UploadMinVal = %+v", c)
	}
	if c, ok := find(got, "state.set", "ArbitVendorsList", ""); !ok || c.Class != "unused_so_far" || c.DaysMeasured != 20 || c.Requests != 6 {
		t.Errorf("ArbitVendorsList = %+v", c)
	}
	if c, ok := find(got, "state.set", "SearchMiscOpts.noSussy", ""); !ok || c.Class != "rare" || c.Denom != 1800 || c.Requests != 11 ||
		c.Help != "kept in a cookie, read on every page" || c.RateText != "0.11% of reader-days" {
		t.Errorf("SearchMiscOpts.noSussy = %+v", c)
	}
	if c, ok := find(got, "state.set", "SleepersEditionList", ""); !ok || c.Class != "not_measured" || c.DaysMeasured != 10 {
		t.Errorf("SleepersEditionList = %+v", c)
	}
	if c, ok := find(got, "state.set", "NewspaperList", ""); !ok || c.Class != "not_measured" || c.Denom != 0 || c.DaysMeasured != 0 ||
		c.NoRate != NoRateEmpty || c.RateText != "" {
		t.Errorf("NewspaperList = %+v", c)
	}
	for _, absent := range []string{"uploadTab", "UploadSorting", "UploadMargin"} { // transient; in use; in use
		if c, ok := find(got, "state.set", absent, ""); ok {
			t.Errorf("%s is no candidate, got class %s", absent, c.Class)
		}
	}
	if len(got) != 6 {
		t.Errorf("%d rows, want the six settings above and nothing for ui.settings.change", len(got))
	}
	// the rare rows rank by their rate against the 1% line: 2 of 1800 before 2 of 900
	var rare []string
	for _, c := range got {
		if c.Class == ClassRare {
			rare = append(rare, c.Scope)
		}
	}
	if !slices.Equal(rare, []string{"SearchMiscOpts.noSussy", "UploadMaxQty"}) {
		t.Errorf("rare rows in order %v", rare)
	}
}

// The rare line is decided on integers: exactly 1% is not rare, and 3 reader-days are not rare however few.
func TestRemoveSettingRareEdges(t *testing.T) {
	setting := []observability.Setting{{Name: "UploadMaxQty", Storage: "cookie", Path: "upload", Kind: "number", Class: "preference", Area: "upload"}}
	for _, c := range []struct {
		count, denom int64
		rare         bool
	}{
		{2, 200, false},    // exactly 1%
		{2, 201, true},     // just under
		{3, 100000, false}, // three reader-days
		{1, 99, false},     // over 1%
	} {
		totals := []observability.DayTotal{
			tot(0, "state.reader", "upload", "", c.denom, 30),
			tot(0, "state.set", "UploadMaxQty", "set", c.count, 1),
		}
		row, ok := find(Remove(nil, setting, totals, nil, w30), "state.set", "UploadMaxQty", "")
		if ok != c.rare || (ok && row.Class != ClassRare) {
			t.Errorf("%d of %d: listed %v as %q, want rare %v", c.count, c.denom, ok, row.Class, c.rare)
		}
	}
}

func TestRemoveSettingRequestsForAnEnumSkipTheDefault(t *testing.T) {
	reviews := []Review{{Name: "state.set", Scope: "UploadSorting", Verdict: "keep"}}
	c, ok := find(Remove(nil, settingsFixture(), settingsTotals(), reviews, w90), "state.set", "UploadSorting", "")
	if !ok || c.Requests != 15 {
		t.Errorf("UploadSorting = %+v, want Requests 15: highprice and setchrono, not other", c)
	}
	withDefault := settingsFixture()[:1]
	withDefault[0].Default = "setchrono"
	if c, _ := find(Remove(nil, withDefault, settingsTotals(), reviews, w90), "state.set", "UploadSorting", ""); c.Requests != 12 {
		t.Errorf("with setchrono the default: Requests %d, want 12", c.Requests)
	}
}

func TestRemoveSettingWithoutTheChangeCounter(t *testing.T) {
	got := Remove(nil, settingsFixture(), settingsTotals(), nil, w90)
	if len(got) == 0 {
		t.Fatal("no setting rows")
	}
	for _, c := range got {
		if c.Changes != -1 {
			t.Errorf("%s: Changes %d with no ui.settings.change registered", c.Scope, c.Changes)
		}
	}
}

func TestRemoveSettingReviewed(t *testing.T) {
	reviews := []Review{{Name: "state.set", Scope: "UploadMinVal", Verdict: "keep", Note: "used by presets"}}
	c, ok := find(Remove(changeName, settingsFixture(), settingsTotals(), reviews, w90), "state.set", "UploadMinVal", "")
	if !ok || c.Class != ClassReviewed || c.Verdict != "keep" || c.Note != "used by presets" || c.Denom != 900 || c.DaysMeasured != 90 {
		t.Errorf("UploadMinVal = %+v", c)
	}
}

func TestRemoveWithNoSettings(t *testing.T) {
	names := []observability.Name{option("search.sort", "search", "chrono", "alpha"), option("news.syp_sort", "newspaper/syp", "edition")}
	totals := append(settingsTotals(), tot(0, "page.view", "", "search", 10000, 30), tot(0, "search.sort", "", "alpha", 3, 3))
	without := Remove(names, nil, totals, nil, w90)
	with := Remove(names, settingsFixture(), totals, nil, w90)
	var named []Candidate
	for _, c := range with {
		if c.Name != "state.set" {
			named = append(named, c)
		}
	}
	if len(without) == 0 || !slices.Equal(without, named) {
		t.Errorf("settings changed the name rows:\n%+v\n%+v", without, named)
	}
	for _, c := range without {
		if c.Changes != -1 || c.Requests != -1 {
			t.Errorf("%s: Changes %d Requests %d, want -1 on a name's row", c.Name, c.Changes, c.Requests)
		}
	}
}
