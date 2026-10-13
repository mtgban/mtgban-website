// news_test.go
package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

// The delayed edition is built by rewriting "0 DAY" into "3 DAY" in the live
// query. That rewrite is the only thing standing between the two tiers, and it
// fails silently: a page whose query lost the literal, or grew a second one,
// would serve the live slice to the delayed tier with nothing logged.
func TestNewspaperQueriesCarryExactlyOneDelayInterval(t *testing.T) {
	for _, page := range newspaperPagesInitial {
		if page.Query == "" {
			continue
		}
		if got := strings.Count(page.Query, "0 DAY"); got != 1 {
			t.Errorf("%s: query has %d occurrences of \"0 DAY\", want exactly 1", page.Option, got)
		}

		delayed := strings.ReplaceAll(page.Query, "0 DAY", "3 DAY")
		if strings.Contains(delayed, "0 DAY") {
			t.Errorf("%s: delayed query still asks for the live slice", page.Option)
		}
		if !strings.Contains(delayed, "3 DAY") {
			t.Errorf("%s: delayed query lost its interval", page.Option)
		}
	}
}

// A slice is only worth showing if it holds rows the page can display, so the
// row filter has to reach every SELECT that picks a calc_date -- not just the
// outer query. Miss one and an edition lands on a slice whose rows the outer
// filter then deletes, which is what left four pages blank.
func TestNewspaperCalcDateFilterReachesEverySliceLookup(t *testing.T) {
	const rowFilter = "pct_drop_7d <> 0"
	fragment := newspaperCalcDateFilter("some_table", rowFilter)

	for i, lookup := range strings.Split(fragment, "SELECT ")[1:] {
		if strings.HasPrefix(lookup, "MAX(calc_date)") || strings.HasPrefix(lookup, "MIN(calc_date)") {
			if !strings.Contains(lookup, rowFilter) {
				t.Errorf("slice lookup %d picks a calc_date without the page's row filter", i)
			}
		}
	}

	if !strings.HasPrefix(fragment, rowFilter) {
		t.Error("fragment does not apply the row filter to the rows it returns")
	}
}

// Pages without a row filter still need a valid predicate in those lookups.
func TestNewspaperCalcDateFilterWithoutRowFilter(t *testing.T) {
	fragment := newspaperCalcDateFilter("some_table", "")

	if !strings.HasPrefix(fragment, "TRUE") {
		t.Error("fragment should stand in TRUE when a page has no row filter")
	}
	if strings.Count(fragment, "0 DAY") != 1 {
		t.Error("fragment should carry exactly one delay interval")
	}
}

// A game missing from gameMap leaves the newspaper empty and logs which game
// it was, rather than panicking: the entry only names the rows to read. The
// lookup comes before the database check, so no database is needed here.
func TestCacheNewspaperLogsAGameMissingFromGameMap(t *testing.T) {
	prevGame, prevSkip, prevLog := Config().Game, SkipNewspaper, log.Writer()
	t.Cleanup(func() {
		Config().Game, SkipNewspaper = prevGame, prevSkip
		log.SetOutput(prevLog)
	})
	var logged bytes.Buffer
	log.SetOutput(&logged)
	Config().Game, SkipNewspaper = "nosuchgame", false

	newSite().cacheNewspaper()

	log.SetOutput(prevLog)
	if !strings.Contains(logged.String(), `"nosuchgame" is missing from gameMap`) {
		t.Errorf("log = %q, want a line naming the missing game", logged.String())
	}
}

// newsRowCols are a spike_score row's columns, as getResults reads them.
var newsRowCols = []string{"calc_date", "product_id", "ranking", "product_name", "set_name", "product_number", "variant", "bucket_name", "bucket_rank", "current_price"}

// A matched row takes the card's name, edition, number and rarity, keeps its
// calc_date in Date, and maps the report's own columns.
func TestNewspaperRowKeepsRarityApart(t *testing.T) {
	co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{
		UUID: "u-ragavan", Name: "Ragavan, Nimble Pilferer", SetCode: "MH2", Number: "138", Rarity: "mythic",
	}, Edition: "Modern Horizons 2"}
	b := &mtgmatcher.Backend{UUIDs: map[string]*mtgmatcher.CardObject{"u-ragavan": co}}
	raw := []string{"2026-10-13T00:00:00Z", "u-ragavan", "1", "RAGAVAN", "MH2", "138", "Normal", "$50+", "1", "64.99"}

	got, ok := newspaperRow(b, newsRowCols, raw, true)
	want := NewspaperResult{
		Date: "2026-10-13T00:00:00Z", UUID: "u-ragavan", Ranking: 1,
		CardName: "Ragavan, Nimble Pilferer", Edition: "Modern Horizons 2", Number: "138",
		Variant: "Normal", Rarity: "mythic", BucketName: "$50+", BucketRank: 1, CurrentPrice: 64.99,
	}
	if !ok || got != want {
		t.Errorf("matched row = %+v, %t\nwant %+v", got, ok, want)
	}

	// Unmatched, the row keeps its own values and has no rarity.
	got, ok = newspaperRow(b, newsRowCols, raw, false)
	if !ok || got.Date != "2026-10-13T00:00:00Z" || got.CardName != "RAGAVAN" || got.Edition != "MH2" || got.Rarity != "" {
		t.Errorf("unmatched row = %+v, %t", got, ok)
	}
}

// A row whose id matches no card is dropped and logged.
func TestNewspaperRowDropsAnUnknownID(t *testing.T) {
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	saved := LogPages["Newspaper"]
	t.Cleanup(func() { LogPages["Newspaper"] = saved })
	var logged bytes.Buffer
	LogPages["Newspaper"] = log.New(&logged, "", 0)

	b := &mtgmatcher.Backend{UUIDs: map[string]*mtgmatcher.CardObject{}}
	raw := []string{"2026-10-13", "999", "1", "Nope", "XXX", "1", "Normal", "$2+", "1", "2"}
	if got, ok := newspaperRow(b, newsRowCols, raw, true); ok {
		t.Errorf("unknown id kept: %+v", got)
	}
	if !strings.Contains(logged.String(), "match 999 Normal") {
		t.Errorf("log = %q", logged.String())
	}
}

// newsInitialPage is a report as newspaperPagesInitial declares it.
func newsInitialPage(t *testing.T, option string) NewspaperPage {
	t.Helper()
	for _, page := range newspaperPagesInitial {
		if page.Option == option {
			return page
		}
	}
	t.Fatalf("no newspaper page %q", option)
	return NewspaperPage{}
}

// Each report's price and change columns are dollar and percent columns it shows.
func TestNewspaperReportsNameTheirColumns(t *testing.T) {
	has := func(page NewspaperPage, field string, perc bool) bool {
		return slices.ContainsFunc(page.Head, func(h Heading) bool {
			return h.Field == field && (perc && h.IsPerc || !perc && h.IsDollar)
		})
	}
	for _, page := range newspaperPagesInitial {
		if page.Priced != "" && !has(page, page.Priced, false) {
			t.Errorf("%s: Priced %q is not a dollar column", page.Option, page.Priced)
		}
		if page.PercChanged != "" && !has(page, page.PercChanged, true) {
			t.Errorf("%s: PercChanged %q is not a percent column", page.Option, page.PercChanged)
		}
	}
	for option, want := range map[string][2]string{
		"combined_spike_score":       {"tcg_market_price", ""},
		"spike_score":                {"current_price", ""},
		"greatest_increase_listings": {"", "pct_gain_7d"},
		"greatest_decrease_listings": {"", "pct_drop_7d"},
		"greatest_increase_buylist":  {"ck_buy_price", "pct_increase_7d"},
		"greatest_decrease_buylist":  {"ck_buy_price", "pct_decrease_7d"},
	} {
		page := newsInitialPage(t, option)
		if got := [2]string{page.Priced, page.PercChanged}; got != want {
			t.Errorf("%s: Priced, PercChanged = %q, want %q", option, got, want)
		}
	}
}

// newsWithRows is a report with a live edition and the filter values cached from it.
func newsWithRows(t *testing.T, option string, rows []NewspaperResult) NewspaperPage {
	t.Helper()
	page := newsInitialPage(t, option)
	page.Results = rows
	page.AvailableEditions, page.PossibleFinish = newspaperFilterValues(rows)
	return page
}

// boundOf is a bound for a query literal.
func boundOf(v float64) *float64 { return &v }

// newsRankings lists rows' rankings in order.
func newsRankings(rows []NewspaperResult) []int {
	out := []int{}
	for _, r := range rows {
		out = append(out, r.Ranking)
	}
	return out
}

// newsFilterPage takes buckets, a price and a change.
var newsFilterPage = NewspaperPage{Option: "fixture", HasBucket: true, Priced: "current_price", PercChanged: "pct_gain_7d"}

// newsFilterRows span two sets, every rarity letter, both finishes, one row with no rarity and one with no change; changes are fractions.
func newsFilterRows() []NewspaperResult {
	return []NewspaperResult{
		{Ranking: 1, UUID: "a", CardName: "Alpha", Edition: "Bloomburrow", Variant: "Normal", Rarity: "mythic", BucketName: "$50+", CurrentPrice: 60, WeeklyPctChange: 0.5},
		{Ranking: 2, UUID: "b", CardName: "Bravo", Edition: "Bloomburrow", Variant: "Foil", Rarity: "rare", BucketName: "$20+", CurrentPrice: 25, WeeklyPctChange: -0.05},
		{Ranking: 3, UUID: "c", CardName: "Charlie", Edition: "Duskmourn", Variant: "Normal", Rarity: "uncommon", BucketName: "$2+", CurrentPrice: 2.5, WeeklyPctChange: 0.3333},
		{Ranking: 4, UUID: "d", CardName: "Delta", Edition: "Duskmourn", Variant: "Normal", Rarity: "common", BucketName: "$2+", CurrentPrice: 2.5, WeeklyPctChange: 0},
		{Ranking: 5, UUID: "e", CardName: "Echo", Edition: "Duskmourn", Variant: "Foil", Rarity: "", BucketName: "$5+", CurrentPrice: 7, WeeklyPctChange: 0.03},
	}
}

// newsFilterBackend knows the two fixture sets by name, for the skip list.
func newsFilterBackend() *mtgmatcher.Backend {
	blb := &mtgmatcher.Set{Code: "BLB", Name: "Bloomburrow"}
	dsk := &mtgmatcher.Set{Code: "DSK", Name: "Duskmourn"}
	return &mtgmatcher.Backend{
		Sets:           map[string]*mtgmatcher.Set{"BLB": blb, "DSK": dsk},
		NormalizedSets: map[string]*mtgmatcher.Set{mtgmatcher.Normalize("Bloomburrow"): blb, mtgmatcher.Normalize("Duskmourn"): dsk},
	}
}

// Each filter alone and together; a row with no rarity passes a rarity filter, as on the page.
func TestNewsFilter(t *testing.T) {
	b := newsFilterBackend()
	for _, tc := range []struct {
		name string
		q    newsQuery
		want []int
	}{
		{"no filter", newsQuery{}, []int{1, 2, 3, 4, 5}},
		{"set", newsQuery{Set: "Duskmourn"}, []int{3, 4, 5}},
		{"rarity", newsQuery{Rarity: "M"}, []int{1, 5}},
		{"rarity pair", newsQuery{Rarity: "M/R"}, []int{1, 2, 5}},
		{"other rarity pair", newsQuery{Rarity: "U/C"}, []int{3, 4, 5}},
		{"finish", newsQuery{Finish: "Foil"}, []int{2, 5}},
		{"bucket", newsQuery{Bucket: "$2+"}, []int{3, 4}},
		{"min price", newsQuery{MinPrice: boundOf(7)}, []int{1, 2, 5}},
		{"max price", newsQuery{MaxPrice: boundOf(7)}, []int{3, 4, 5}},
		{"price bounds are inclusive", newsQuery{MinPrice: boundOf(2.5), MaxPrice: boundOf(2.5)}, []int{3, 4}},
		{"min change", newsQuery{MinChange: boundOf(0)}, []int{1, 3, 5}},
		{"max change", newsQuery{MaxChange: boundOf(0)}, []int{2}},
		{"change bounds are inclusive percents", newsQuery{MinChange: boundOf(3), MaxChange: boundOf(33.33)}, []int{3, 5}},
		{"min change in percent", newsQuery{MinChange: boundOf(40)}, []int{1}},
		{"skip a set", newsQuery{SkipSets: []string{"BLB"}}, []int{3, 4, 5}},
		{"skip sets", newsQuery{SkipSets: []string{"DSK", "XXX"}}, []int{1, 2}},
		{"together", newsQuery{Set: "Duskmourn", Finish: "Normal", MinPrice: boundOf(2)}, []int{3, 4}},
		{"nothing", newsQuery{Set: "Bloomburrow", Rarity: "C"}, []int{}},
	} {
		got := newsRankings(newsFilter(b, newsFilterPage, newsFilterRows(), tc.q))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A change bound is in percent: the stored fraction times 100, to two decimals.
func TestNewsFilterChangeIsPercent(t *testing.T) {
	for _, tc := range []struct {
		change, min float64
		keep        bool
	}{
		{0.2, 20, true},
		{0.2, 21, false},
		{0.29, 29, true},
	} {
		rows := []NewspaperResult{{Ranking: 1, WeeklyPctChange: tc.change}}
		got := len(newsFilter(newsFilterBackend(), newsFilterPage, rows, newsQuery{MinChange: boundOf(tc.min)})) == 1
		if got != tc.keep {
			t.Errorf("change %v, min_change=%v: kept %t, want %t", tc.change, tc.min, got, tc.keep)
		}
	}
}

// A row with no value in a bound's column fails the bound and passes without one.
func TestNewsFilterNoValueFailsABound(t *testing.T) {
	rows := []NewspaperResult{{Ranking: 1, CurrentPrice: 5, WeeklyPctChange: 0.1}, {Ranking: 2}}
	for _, tc := range []struct {
		name string
		q    newsQuery
		want []int
	}{
		{"no bound", newsQuery{}, []int{1, 2}},
		{"min price 0", newsQuery{MinPrice: boundOf(0)}, []int{1}},
		{"max price", newsQuery{MaxPrice: boundOf(100)}, []int{1}},
		{"max change", newsQuery{MaxChange: boundOf(100)}, []int{1}},
	} {
		got := newsRankings(newsFilter(newsFilterBackend(), newsFilterPage, rows, tc.q))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A report that names no price or change column ignores those bounds.
func TestNewsFilterIgnoresBoundsWithoutAColumn(t *testing.T) {
	q := newsQuery{MinPrice: boundOf(100), MaxChange: boundOf(-100)}
	got := newsRankings(newsFilter(newsFilterBackend(), NewspaperPage{}, newsFilterRows(), q))
	if !slices.Equal(got, []int{1, 2, 3, 4, 5}) {
		t.Errorf("got %v", got)
	}
}

// The sort is the page's: numeric when either side is a nonzero number, else
// by text, descending unless asked otherwise, ties kept in their order.
func TestNewsFilterSorts(t *testing.T) {
	b := newsFilterBackend()
	for _, tc := range []struct {
		sort, dir string
		want      []int
	}{
		{"", "", []int{1, 2, 3, 4, 5}},
		{"current_price", "", []int{1, 2, 5, 3, 4}},
		{"current_price", "asc", []int{3, 4, 5, 2, 1}},
		{"pct_gain_7d", "desc", []int{1, 3, 5, 4, 2}},
		{"product_name", "asc", []int{1, 2, 3, 4, 5}},
		{"product_name", "desc", []int{5, 4, 3, 2, 1}},
		{"ranking", "desc", []int{5, 4, 3, 2, 1}},
	} {
		got := newsRankings(newsFilter(b, newsFilterPage, newsFilterRows(), newsQuery{Sort: tc.sort, Dir: tc.dir}))
		if !slices.Equal(got, tc.want) {
			t.Errorf("sort %q dir %q: got %v, want %v", tc.sort, tc.dir, got, tc.want)
		}
	}
}

// newsFilter answers a new slice and leaves the one it read, the cached one, as it was.
func TestNewsFilterLeavesItsInputAlone(t *testing.T) {
	rows := newsFilterRows()
	out := newsFilter(newsFilterBackend(), newsFilterPage, rows, newsQuery{Sort: "current_price", Dir: "asc"})
	out[0].CardName = "changed"
	if got := newsRankings(rows); !slices.Equal(got, []int{1, 2, 3, 4, 5}) || rows[2].CardName != "Charlie" {
		t.Errorf("input changed: %+v", rows)
	}
}

// A bound is blank, a finite number, or an error; the page reads 0 and errors as none.
func TestNewsParseBound(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want *float64
		bad  bool
	}{
		{"", nil, false},
		{"  ", nil, false},
		{"5", boundOf(5), false},
		{" -2.5 ", boundOf(-2.5), false},
		{"0", boundOf(0), false},
		{"cheap", nil, true},
		{"NaN", nil, true},
		{"Inf", nil, true},
		{"-inf", nil, true},
	} {
		got, err := newsParseBound(tc.in)
		if (err != nil) != tc.bad || (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("newsParseBound(%q) = %v, %v", tc.in, got, err)
		}
	}
	// The page's links send 0 for an unset bound, and a bad one reads as none.
	for in, want := range map[string]*float64{"": nil, "0": nil, "x": nil, "3": boundOf(3)} {
		got := newsPageBound(in)
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Errorf("newsPageBound(%q) = %v", in, got)
		}
	}
}

// The page reads its report through newsFilter: the bounds now apply, the
// table still pages at 25, and a sort leaves the cached slice in rank order.
func TestNewspaperPageFiltersAndPages(t *testing.T) {
	withSigMode(t, true, false)
	db, err := timeseries.SQLConfig{Host: "127.0.0.1", Port: 1, User: "none", Password: "none", DBName: "none"}.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	prevDB, prevPages := NewNewspaperDB, newspaperPagesPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB = prevDB
		newspaperPagesPtr.Store(prevPages)
	})
	NewNewspaperDB = db

	var rows []NewspaperResult
	for i := 1; i <= 30; i++ {
		rows = append(rows, NewspaperResult{Ranking: i, UUID: fmt.Sprint("u-", i), CardName: fmt.Sprint("Card ", i), Edition: "Bloomburrow", Variant: "Normal", Rarity: "rare", BucketName: "$2+", CurrentPrice: float64(i)})
	}
	pages := []NewspaperPage{newsWithRows(t, "spike_score", rows)}
	newspaperPagesPtr.Store(&pages)

	get := func(query string) string {
		rec := httptest.NewRecorder()
		testSite.Newspaper(rec, httptest.NewRequest(http.MethodGet, "/newspaper?"+query, nil))
		return rec.Body.String()
	}
	rank := func(n int) string { return fmt.Sprintf(`<span class="news-rank">%d</span>`, n) }

	first := get("page=spike_score")
	if !strings.Contains(first, rank(1)) || !strings.Contains(first, rank(25)) || strings.Contains(first, rank(26)) {
		t.Error("page 1 is not ranks 1 to 25")
	}
	second := get("page=spike_score&index=2")
	if !strings.Contains(second, rank(26)) || !strings.Contains(second, rank(30)) || strings.Contains(second, rank(25)) {
		t.Error("page 2 is not ranks 26 to 30")
	}
	bounded := get("page=spike_score&min_price=10&max_price=12")
	for n := 1; n <= 30; n++ {
		if got, want := strings.Contains(bounded, rank(n)), n >= 10 && n <= 12; got != want {
			t.Errorf("min_price=10&max_price=12: rank %d shown %t, want %t", n, got, want)
		}
	}
	if !strings.Contains(bounded, `name="min_price" value="10"`) {
		t.Error("the price inputs are not drawn with the bound")
	}
	zero := get("page=spike_score&min_price=0&max_price=0")
	if !strings.Contains(zero, rank(1)) || !strings.Contains(zero, rank(25)) {
		t.Error("a 0 bound, which the page's links send for none, filtered rows")
	}
	get("page=spike_score&sort=current_price&dir=desc")
	if GetNewspaperPages()[0].Results[0].Ranking != 1 {
		t.Error("the page sorted the cached slice in place")
	}
}
