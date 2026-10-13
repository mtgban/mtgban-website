// news_test.go
package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
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
