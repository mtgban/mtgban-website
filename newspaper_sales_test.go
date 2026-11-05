package main

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

// TestJudgeNewspaperSales alarms on the real signed-out day and not the real
// signed-in ones, and on a pull that stopped, not on a normal wait for the next.
func TestJudgeNewspaperSales(t *testing.T) {
	date := func(month time.Month, day, hour int) time.Time {
		return time.Date(2026, month, day, hour, 0, 0, 0, time.UTC)
	}
	for _, tc := range []struct {
		desc           string
		newest         time.Time
		rows, overFive int64
		now            time.Time
		want           string
	}{
		{"signed out, measured", date(10, 13, 0), 86093, 0, date(10, 14, 7), "TCGplayer logins look expired"},
		{"signed in, measured", date(11, 4, 0), 94075, 9142, date(11, 5, 7), ""},
		{"first signed-in day, measured", date(10, 14, 0), 93942, 9239, date(10, 15, 7), ""},
		{"under the share", date(11, 4, 0), 94075, 900, date(11, 5, 7), "TCGplayer logins look expired"},
		{"a day with no rows is not signed out", date(11, 4, 0), 0, 0, date(11, 5, 7), ""},
		{"just before the next pull", date(11, 4, 0), 94075, 9142, date(11, 6, 6), ""},
		{"a whole pull missed", date(11, 3, 0), 94075, 9142, date(11, 6, 1), "no new sale day since 2026-11-03"},
		{"stopped wins over signed out", date(11, 3, 0), 86093, 0, date(11, 6, 1), "no new sale day"},
	} {
		day := tc.newest.AddDate(0, 0, -1)
		result, problem := judgeNewspaperSales(tc.newest, day, tc.rows, tc.overFive, tc.now)
		if !strings.Contains(result, tc.newest.Format(time.DateOnly)) {
			t.Errorf("%s: result %q does not name the newest day", tc.desc, result)
		}
		if tc.want == "" && problem != "" {
			t.Errorf("%s: got problem %q, want none", tc.desc, problem)
		}
		if tc.want != "" && !strings.Contains(problem, tc.want) {
			t.Errorf("%s: got problem %q, want %q", tc.desc, problem, tc.want)
		}
	}
}

// newspaperSalesAnswers answers checkNewspaperSales's queries: the newest day,
// then each day in turn, as rows and those over five orders.
func newspaperSalesAnswers(newest driver.Value, days ...[2]int64) func(string) (*fakeRows, error) {
	return func(query string) (*fakeRows, error) {
		if query == newspaperNewestSaleQuery {
			return &fakeRows{cols: []string{"max"}, vals: [][]driver.Value{{newest}}}, nil
		}
		day := days[0]
		days = days[1:]
		return &fakeRows{cols: []string{"rows", "over"}, vals: [][]driver.Value{{day[0], day[1]}}}, nil
	}
}

// newspaperSalesRow runs the check and returns the job's dashboard row.
func newspaperSalesRow(t *testing.T) (result, problem string) {
	t.Helper()
	checkNewspaperSales()
	for _, row := range backgroundJobs.Rows() {
		if row.Name == jobNewspaperSales {
			return row.Result, row.Problem
		}
	}
	t.Fatal("the job has no row")
	return "", ""
}

// TestCheckNewspaperSales judges the newest day once it has rows enough, else
// the day before, across every game, and the job's row clears when the pull is
// healthy again.
func TestCheckNewspaperSales(t *testing.T) {
	setTestJobs(t)
	yesterday := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	newest := yesterday.Format(time.DateOnly)
	before := yesterday.AddDate(0, 0, -1).Format(time.DateOnly)
	f := &fakeNewspaper{}
	withFakeNewspaper(t, f)
	for _, tc := range []struct {
		desc   string
		days   [][2]int64
		read   []string
		result string
		alarm  bool
	}{
		{"newest signed out, with rows enough", [][2]int64{{10606, 0}}, []string{newest}, "0 of 10606", true},
		{"newest signed in, measured partway", [][2]int64{{10606, 372}}, []string{newest}, "372 of 10606", false},
		{"newest just started", [][2]int64{{4423, 141}, {94075, 9142}}, []string{newest, before}, "9142 of 94075", false},
		{"newest just started, the day before signed out", [][2]int64{{4423, 141}, {86093, 0}}, []string{newest, before}, "0 of 86093", true},
	} {
		f.queries = nil
		f.answer = newspaperSalesAnswers(yesterday, tc.days...)
		result, problem := newspaperSalesRow(t)
		if !strings.Contains(result, tc.result) {
			t.Errorf("%s: got result %q, want %q", tc.desc, result, tc.result)
		}
		if (problem != "") != tc.alarm {
			t.Errorf("%s: got problem %q, want one: %v", tc.desc, problem, tc.alarm)
		}
		var read []string
		for _, q := range f.seen()[1:] {
			read = append(read, q.args[0].(string))
		}
		if !slices.Equal(read, tc.read) {
			t.Errorf("%s: read %v, want %v", tc.desc, read, tc.read)
		}
		if args := f.seen()[0].args; len(args) != 0 {
			t.Errorf("%s: the newest day's query has args %v, want it across every game", tc.desc, args)
		}
	}
}

// TestCheckNewspaperSalesReportsAFailedRead tells a broken database, and a table
// with no sales, apart from a clean run.
func TestCheckNewspaperSalesReportsAFailedRead(t *testing.T) {
	setTestJobs(t)
	f := &fakeNewspaper{answer: func(string) (*fakeRows, error) { return nil, errors.New("connection lost") }}
	withFakeNewspaper(t, f)
	_, problem := newspaperSalesRow(t)
	if !strings.Contains(problem, "connection lost") {
		t.Errorf("got problem %q", problem)
	}

	f.answer = newspaperSalesAnswers(nil)
	_, problem = newspaperSalesRow(t)
	if !strings.Contains(problem, "no sales") {
		t.Errorf("no sales: got problem %q", problem)
	}
}

// TestNewspaperSalesJobRunsOnOneSite schedules the check only on the Magic site
// with a newspaper: every site reads the same table, so one alarm is enough.
func TestNewspaperSalesJobRunsOnOneSite(t *testing.T) {
	withConfigCopy(t)
	prevDB, prevSkip := NewNewspaperDB, SkipNewspaper
	t.Cleanup(func() { NewNewspaperDB, SkipNewspaper = prevDB, prevSkip })
	db := sql.OpenDB(&fakeNewspaper{})
	t.Cleanup(func() { db.Close() })
	for _, tc := range []struct {
		desc string
		game matcher.Game
		db   *sql.DB
		skip bool
		want bool
	}{
		{"magic", DefaultGame, db, false, true},
		{"another game", matcher.GameLorcana, db, false, false},
		{"no database", DefaultGame, nil, false, false},
		{"-nonews", DefaultGame, db, true, false},
	} {
		setTestJobs(t)
		Config().Game = tc.game
		NewNewspaperDB, SkipNewspaper = tc.db, tc.skip
		testSite.scheduleCrons()
		got := false
		for _, row := range backgroundJobs.Rows() {
			got = got || row.Name == jobNewspaperSales
		}
		if got != tc.want {
			t.Errorf("%s: scheduled %v, want %v", tc.desc, got, tc.want)
		}
	}
}
