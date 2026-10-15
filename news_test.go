// news_test.go
package main

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/url"
	"strings"
	"testing"
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

// TestNewspaperTier opens the Newspaper tiers, 0day, 1day and 3day, and dev
// mode with signing off, and nothing else.
func TestNewspaperTier(t *testing.T) {
	tierSig := func(tier string) string {
		return base64.StdEncoding.EncodeToString([]byte(url.Values{"NewsEnabled": {tier}}.Encode()))
	}
	withSigMode(t, false, true)
	for _, tc := range []struct {
		desc string
		sig  string
		want bool
	}{
		{"0day", tierSig("0day"), true},
		{"1day", tierSig("1day"), true},
		{"3day", tierSig("3day"), true},
		{"an empty tier", tierSig(""), false},
		{"an unknown tier", tierSig("7day"), false},
		{"a page flag", tierSig("true"), false},
		{"no signature", "", false},
	} {
		got := newspaperTier(tc.sig)
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.desc, got, tc.want)
		}
	}

	withSigMode(t, true, false)
	if !newspaperTier("") {
		t.Error("dev mode with signing off: refused")
	}
	withSigMode(t, true, true)
	if newspaperTier("") {
		t.Error("dev mode with signing on: granted with no signature")
	}
}
