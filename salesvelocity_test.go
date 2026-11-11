package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

// setTestSalesVelocity files cards as the loaded sales in a store of the test's own.
func setTestSalesVelocity(t *testing.T, cards map[string]*salesvelocity.Sales) {
	t.Helper()
	store := &salesvelocity.Store{}
	store.Publish(&salesvelocity.Snapshot{
		Day:    time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
		Cards:  cards,
		Window: salesvelocity.Window,
	})
	setSalesVelocityStore(t, store)
}

// setSalesVelocityStore makes store the loaded sales until the test ends.
func setSalesVelocityStore(t *testing.T, store *salesvelocity.Store) {
	t.Helper()
	prev := salesVelocityStore
	t.Cleanup(func() { salesVelocityStore = prev })
	salesVelocityStore = store
}

// TestLoadSalesVelocityWaitsForADatastore keeps the loader off the newspaper
// before a datastore loads and for a game gameMap lacks.
func TestLoadSalesVelocityWaitsForADatastore(t *testing.T) {
	withConfigCopy(t)
	prevDB, prevSkip := NewNewspaperDB, SkipNewspaper
	t.Cleanup(func() { NewNewspaperDB, SkipNewspaper = prevDB, prevSkip })
	conn := &refusingConnector{}
	db := sql.OpenDB(conn)
	t.Cleanup(func() { db.Close() })
	NewNewspaperDB, SkipNewspaper = db, false
	Config().Game = DefaultGame

	s := newSite()
	s.loadSalesVelocity()
	if n := conn.dials.Load(); n != 0 {
		t.Errorf("queried the newspaper %d times with no datastore loaded", n)
	}

	s.ds.Store(&datastore{backend: &matcher.Backend{AllUUIDs: []string{"a-card"}}})
	Config().Game = "nosuchgame"
	s.loadSalesVelocity()
	if n := conn.dials.Load(); n != 0 {
		t.Errorf("queried the newspaper %d times for a game gameMap lacks", n)
	}

	Config().Game = DefaultGame
	s.loadSalesVelocity()
	if conn.dials.Load() == 0 {
		t.Error("did not query the newspaper once a datastore was loaded")
	}
}

// salesQuery is one query the fake newspaper saw, and whether a transaction was open.
type salesQuery struct {
	sql  string
	args []driver.Value
	inTx bool
}

// fakeNewspaper records each query and transaction and answers canned rows; with block set, each query waits on it.
type fakeNewspaper struct {
	mu      sync.Mutex
	queries []salesQuery
	txs     []driver.TxOptions
	open    bool
	answer  func(query string) (*fakeRows, error)
	entered chan struct{}
	block   chan struct{}
}

func (f *fakeNewspaper) Connect(context.Context) (driver.Conn, error) { return fakeConn{f}, nil }
func (f *fakeNewspaper) Driver() driver.Driver                        { return nil }

// seen is a copy of the queries recorded so far.
func (f *fakeNewspaper) seen() []salesQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.queries)
}

type fakeConn struct{ f *fakeNewspaper }

func (c fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (c fakeConn) Close() error                        { return nil }
func (c fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("no plain begin") }

func (c fakeConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.txs = append(c.f.txs, opts)
	c.f.open = true
	return c, nil
}

func (c fakeConn) Commit() error   { return c.end() }
func (c fakeConn) Rollback() error { return c.end() }

func (c fakeConn) end() error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.open = false
	return nil
}

func (c fakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.mu.Lock()
	q := salesQuery{sql: query, inTx: c.f.open}
	for _, arg := range args {
		q.args = append(q.args, arg.Value)
	}
	c.f.queries = append(c.f.queries, q)
	c.f.mu.Unlock()
	if c.f.entered != nil {
		select {
		case c.f.entered <- struct{}{}:
		default:
		}
	}
	if c.f.block != nil {
		select {
		case <-c.f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.f.answer(query)
}

// fakeRows is a canned result set.
type fakeRows struct {
	cols []string
	vals [][]driver.Value
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if len(r.vals) == 0 {
		return io.EOF
	}
	copy(dest, r.vals[0])
	r.vals = r.vals[1:]
	return nil
}

// TestLoadSalesVelocityReadsInOneSnapshot reads the window and the lookback in one
// read-only repeatable read, over the dates each covers, and ends it.
func TestLoadSalesVelocityReadsInOneSnapshot(t *testing.T) {
	newest := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		switch query {
		case salesvelocity.DayQuery, salesvelocity.GlobalDayQuery:
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{newest}}}, nil
		case salesvelocity.WindowQuery:
			return &fakeRows{cols: []string{"p", "v", "c", "o", "d"}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}}, nil
	}}
	s := withFakeNewspaper(t, f)
	s.loadSalesVelocity()

	queries := f.seen()
	want := []salesQuery{
		{sql: salesvelocity.WindowQuery, args: []driver.Value{"2026-09-13", "2026-10-12", "Magic: The Gathering"}, inTx: true},
		{sql: salesvelocity.LastQuery, args: []driver.Value{"2025-10-13", "2026-10-12", "Magic: The Gathering"}, inTx: true},
	}
	if len(queries) != len(want)+2 {
		t.Fatalf("got %d queries, want the two days and %d more", len(queries), len(want))
	}
	for i, w := range want {
		q := queries[i+2]
		if q.sql != w.sql || !slices.Equal(q.args, w.args) || q.inTx != w.inTx {
			t.Errorf("query %d: got args %v in a transaction %v, want %v, %v", i, q.args, q.inTx, w.args, w.inTx)
		}
	}
	if len(f.txs) != 1 || f.txs[0].Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !f.txs[0].ReadOnly {
		t.Errorf("transactions: got %+v, want one read-only repeatable read", f.txs)
	}
	if f.open {
		t.Error("the transaction is still open after the read")
	}
}

// withFakeNewspaper makes f the newspaper of a magic site with a datastore, restoring the globals when the test ends.
func withFakeNewspaper(t *testing.T, f *fakeNewspaper) *site {
	t.Helper()
	withConfigCopy(t)
	prevDB, prevSkip := NewNewspaperDB, SkipNewspaper
	db := sql.OpenDB(f)
	t.Cleanup(func() {
		db.Close()
		NewNewspaperDB, SkipNewspaper = prevDB, prevSkip
	})
	NewNewspaperDB, SkipNewspaper = db, false
	Config().Game = DefaultGame
	setSalesVelocityStore(t, &salesvelocity.Store{})

	s := newSite()
	s.ds.Store(&datastore{backend: &matcher.Backend{AllUUIDs: []string{"a-card"}}})
	return s
}

// TestLoadSalesVelocityReadsOneGame reads the newest sale day for the site's
// own game and for every game, then the sales to the day before it, the last
// complete one, for the site's game only.
func TestLoadSalesVelocityReadsOneGame(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		if query == salesvelocity.DayQuery || query == salesvelocity.GlobalDayQuery {
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{day}}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}}, nil
	}}
	s := withFakeNewspaper(t, f)
	setTestJobs(t)
	Config().Game = matcher.GameLorcana

	s.loadSalesVelocity()
	queries := f.seen()
	if len(queries) != 4 {
		t.Fatalf("got %d queries, want 4", len(queries))
	}
	if queries[0].sql != salesvelocity.DayQuery || !slices.Equal(queries[0].args, []driver.Value{gameMap[matcher.GameLorcana], int64(salesvelocity.Window)}) {
		t.Errorf("first query: got %q %v, want the day query scoped to %q", queries[0].sql, queries[0].args, gameMap[matcher.GameLorcana])
	}
	if queries[1].sql != salesvelocity.GlobalDayQuery || !slices.Equal(queries[1].args, []driver.Value{int64(salesvelocity.Window)}) {
		t.Errorf("second query: got %q %v, want the day query across every game", queries[1].sql, queries[1].args)
	}
	for _, q := range queries[2:] {
		if len(q.args) != 3 || q.args[1] != "2026-10-11" || q.args[2] != gameMap[matcher.GameLorcana] {
			t.Errorf("got args %v, want the day and %q", q.args, gameMap[matcher.GameLorcana])
		}
	}
	problem := ""
	for _, row := range backgroundJobs.Rows() {
		if row.Name == jobSalesVelocity {
			problem = row.Problem
		}
	}
	if !strings.HasPrefix(problem, "failed to load 2026-10-11") {
		t.Errorf("a load matching no card: reported %q, want a failure on the day before %s", problem, day.Format(time.DateOnly))
	}
	s.loadSalesVelocity()
	if n := len(f.seen()); n != 6 {
		t.Errorf("the failed day retried at once: got %d queries, want only the two day queries more", n)
	}
}

// TestLoadSalesVelocityEndsOnEveryGamesCompleteDay ends a game's window on the
// day before the newest sale of any game, not of its own: the newspaper writes
// a day for every game at once, so a game that sold nothing on it is complete.
func TestLoadSalesVelocityEndsOnEveryGamesCompleteDay(t *testing.T) {
	skipWithoutDatastore(t)
	cardID, productID := counterspellProduct(t, backend())
	gameNewest := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	globalNewest := gameNewest.AddDate(0, 0, 1)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		switch query {
		case salesvelocity.DayQuery:
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{gameNewest}}}, nil
		case salesvelocity.GlobalDayQuery:
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{globalNewest}}}, nil
		case salesvelocity.WindowQuery:
			return &fakeRows{cols: []string{"p", "v", "c", "o", "d"}, vals: [][]driver.Value{
				{productID, "Normal", int64(3), int64(2), int64(1)},
			}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}, vals: [][]driver.Value{{productID, "Normal", gameNewest}}}, nil
	}}
	s := withFakeNewspaper(t, f)
	s.ds.Store(testSite.datastore())

	s.loadSalesVelocity()
	snap := salesVelocityStore.Snapshot()
	if snap == nil || !snap.Day.Equal(gameNewest) {
		t.Fatalf("snapshot: got %+v, want one for %s, the day before every game's newest", snap, gameNewest.Format(time.DateOnly))
	}
	_, found := salesVelocityStore.Snapshot().For(cardID)
	if !found {
		t.Errorf("%s: no sales filed", cardID)
	}
	want := map[string][]driver.Value{
		salesvelocity.WindowQuery: {"2026-10-05", "2026-11-03", "Magic: The Gathering"},
		salesvelocity.LastQuery:   {"2025-11-04", "2026-11-03", "Magic: The Gathering"},
	}
	for _, q := range f.seen() {
		w, bounded := want[q.sql]
		if bounded && !slices.Equal(q.args, w) {
			t.Errorf("got args %v, want %v", q.args, w)
		}
		delete(want, q.sql)
	}
	if len(want) != 0 {
		t.Errorf("never ran %d of the window and lookback", len(want))
	}
}

// TestLoadSalesVelocityAfterADatastoreReload reads a day already loaded
// again once the datastore changes, since its card ids key the snapshot.
func TestLoadSalesVelocityAfterADatastoreReload(t *testing.T) {
	skipWithoutDatastore(t)
	_, productID := counterspellProduct(t, backend())
	newest := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		switch query {
		case salesvelocity.DayQuery, salesvelocity.GlobalDayQuery:
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{newest}}}, nil
		case salesvelocity.WindowQuery:
			return &fakeRows{cols: []string{"p", "v", "c", "o", "d"}, vals: [][]driver.Value{
				{productID, "Normal", int64(3), int64(2), int64(1)},
			}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}, vals: [][]driver.Value{{productID, "Normal", newest}}}, nil
	}}
	s := withFakeNewspaper(t, f)
	s.ds.Store(testSite.datastore())
	s.loadSalesVelocity()
	if salesVelocityStore.Snapshot() == nil {
		t.Fatal("no snapshot")
	}

	s.loadSalesVelocity()
	if n := len(f.seen()); n != 6 {
		t.Errorf("same datastore: got %d queries, want the day's two only", n)
	}
	s.ds.Store(&datastore{backend: &matcher.Backend{AllUUIDs: []string{"a-card"}}})
	s.loadSalesVelocity()
	if n := len(f.seen()); n != 10 {
		t.Errorf("new datastore: got %d queries, want the window and lookback read again", n)
	}
}

// TestLoadSalesVelocityNoSalesYet reports no problem and stores no snapshot
// when the day query finds no sales for this deployment's game.
func TestLoadSalesVelocityNoSalesYet(t *testing.T) {
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		return &fakeRows{cols: []string{"sale_date"}}, nil
	}}
	s := withFakeNewspaper(t, f)
	setTestJobs(t)

	s.loadSalesVelocity()
	if n := len(f.seen()); n != 1 {
		t.Fatalf("got %d queries, want only the day query", n)
	}
	for _, row := range backgroundJobs.Rows() {
		if row.Name == jobSalesVelocity && row.Problem != "" {
			t.Errorf("reported a problem: %s", row.Problem)
		}
	}
	if snap := salesVelocityStore.Snapshot(); snap != nil {
		t.Errorf("stored a snapshot: %+v", snap)
	}
}

// TestLoadSalesVelocityClearsAPastProblem reports a run that had nothing to
// load, so a failed read's problem clears once the newspaper answers again.
func TestLoadSalesVelocityClearsAPastProblem(t *testing.T) {
	newest := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	dayRows := func() *fakeRows {
		return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{newest}}}
	}
	var answer func(string) (*fakeRows, error)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) { return answer(query) }}
	s := withFakeNewspaper(t, f)
	salesVelocityStore.Publish(&salesvelocity.Snapshot{Day: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), Window: salesvelocity.Window, Backend: weak.Make(s.backend())})
	setTestJobs(t)

	for _, next := range []struct {
		name   string
		answer func(string) (*fakeRows, error)
	}{
		{"the day already loaded", func(string) (*fakeRows, error) { return dayRows(), nil }},
		{"no sales", func(string) (*fakeRows, error) { return &fakeRows{cols: []string{"sale_date"}}, nil }},
	} {
		answer = func(string) (*fakeRows, error) { return nil, errors.New("connection reset") }
		s.loadSalesVelocity()
		failed := jobRow(t, jobSalesVelocity)
		if !strings.HasPrefix(failed.Problem, "cannot read the newspaper") {
			t.Fatalf("%s: a failed read reported %q", next.name, failed.Problem)
		}

		answer = next.answer
		s.loadSalesVelocity()
		row := jobRow(t, jobSalesVelocity)
		if row.Problem != "" || row.Result == "" {
			t.Errorf("%s: the next run left result %q, problem %q; want a result and no problem", next.name, row.Result, row.Problem)
		}
	}
}

// TestRefreshNewspaperLoadsSalesVelocity checks for a new sale day when the
// pages refresh, and the sales job shares their schedule on the dashboard.
func TestRefreshNewspaperLoadsSalesVelocity(t *testing.T) {
	f := &fakeNewspaper{answer: func(string) (*fakeRows, error) {
		return &fakeRows{cols: []string{"sale_date"}}, nil
	}}
	s := withFakeNewspaper(t, f)
	s.refreshNewspaper()
	queries := f.seen()
	if len(queries) == 0 || queries[len(queries)-1].sql != salesvelocity.DayQuery {
		t.Errorf("the refresh ended without the day query: %d queries", len(queries))
	}

	setTestJobs(t)
	testSite.scheduleCrons()
	next := map[string]bool{}
	for _, row := range backgroundJobs.Rows() {
		next[row.Name] = true
	}
	if !next[jobSalesVelocity] || !next[jobNewspaper] {
		t.Errorf("want both jobs on the dashboard: %v", next)
	}
}

// TestLoadSalesVelocityRunsOnce lets one load at a time reach the newspaper:
// a second call while the first is querying returns at once.
func TestLoadSalesVelocityRunsOnce(t *testing.T) {
	f := &fakeNewspaper{
		entered: make(chan struct{}, 1),
		block:   make(chan struct{}),
		answer:  func(string) (*fakeRows, error) { return nil, errors.New("no sales here") },
	}
	s := withFakeNewspaper(t, f)

	var wg sync.WaitGroup
	release := sync.OnceFunc(func() { close(f.block) })
	t.Cleanup(func() {
		release()
		wg.Wait()
	})
	wg.Go(s.loadSalesVelocity)
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first load never queried the newspaper")
	}

	second := make(chan struct{})
	wg.Go(func() {
		s.loadSalesVelocity()
		close(second)
	})
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("the second load waited on the first")
	}
	if n := len(f.seen()); n != 1 {
		t.Errorf("got %d queries while one load ran, want 1", n)
	}
	release()
}

// counterspellProduct is a Counterspell printing whose TCGplayer id matches back to it as Normal.
func counterspellProduct(t *testing.T, b *matcher.Backend) (cardID string, productID int64) {
	t.Helper()
	ids, err := b.SearchEquals("Counterspell")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		co, err := b.GetUUID(id)
		if err != nil || co.Foil || co.Etched {
			continue
		}
		pid, err := strconv.ParseInt(co.Identifiers["tcgplayerProductId"], 10, 64)
		if err != nil {
			continue
		}
		matched, err := b.Match(&matcher.InputCard{ID: strconv.FormatInt(pid, 10), Finish: "Normal"})
		if err == nil && matched == co.UUID {
			return co.UUID, pid
		}
	}
	t.Fatal("no Counterspell printing matches back from its TCGplayer id")
	return "", 0
}

// TestLoadSalesVelocityPublishes files a load's sales under the matched card,
// and a second run on the same sale day reads only the day.
func TestLoadSalesVelocityPublishes(t *testing.T) {
	skipWithoutDatastore(t)
	cardID, productID := counterspellProduct(t, backend())
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	lastSale := day.AddDate(0, 0, -1)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		switch query {
		case salesvelocity.DayQuery, salesvelocity.GlobalDayQuery:
			return &fakeRows{cols: []string{"sale_date"}, vals: [][]driver.Value{{day}}}, nil
		case salesvelocity.WindowQuery:
			return &fakeRows{cols: []string{"p", "v", "c", "o", "d"}, vals: [][]driver.Value{
				{productID, "Normal", int64(69), int64(31), int64(18)},
			}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}, vals: [][]driver.Value{{productID, "Normal", lastSale}}}, nil
	}}
	s := withFakeNewspaper(t, f)
	s.ds.Store(testSite.datastore())

	s.loadSalesVelocity()
	if n := len(f.seen()); n != 4 {
		t.Fatalf("got %d queries, want the two days, the window and the lookback", n)
	}
	got, found := salesVelocityStore.Snapshot().For(cardID)
	want := salesvelocity.Sales{Copies: 69, Orders: 31, Days: 18, LastSale: lastSale}
	if !found || got != want {
		t.Errorf("%s: got %+v, %v; want %+v", cardID, got, found, want)
	}
	if snap := salesVelocityStore.Snapshot(); snap == nil || !snap.Day.Equal(day.AddDate(0, 0, -1)) {
		t.Errorf("snapshot: got %+v, want one for the day before %s", snap, day.Format(time.DateOnly))
	}

	s.loadSalesVelocity()
	queries := f.seen()
	if len(queries) != 6 || queries[4].sql != salesvelocity.DayQuery || queries[5].sql != salesvelocity.GlobalDayQuery {
		t.Errorf("second run on the same day: got %d queries, want only the two day queries after the first 4", len(queries))
	}
}

// TestSearchMetadataCarriesSalesVelocity fills a card's rate and details from
// the sales it is handed, and leaves them empty without.
func TestSearchMetadataCarriesSalesVelocity(t *testing.T) {
	skipWithoutDatastore(t)
	ds := currentDatastore()
	cardID := randomUUID(ds.backend, false)
	co, err := ds.backend.GetUUID(cardID)
	if err != nil {
		t.Fatal(err)
	}
	v := salesvelocity.Sales{Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	sales := &salesvelocity.Snapshot{Cards: map[string]*salesvelocity.Sales{co.UUID: &v}, Window: salesvelocity.Window}
	wantRate, wantDetail, _ := sales.View(co.UUID)
	if wantRate == "" {
		t.Fatal("the snapshot has no rate for the card")
	}
	metadata, _ := searchMetadata(ds, currentPrices(), sales, []string{cardID}, false)
	card := metadata[cardID]
	if card.Velocity != wantRate || card.VelocityDetail != wantDetail {
		t.Errorf("got %q, %q; want %q, %q", card.Velocity, card.VelocityDetail, wantRate, wantDetail)
	}

	metadata, _ = searchMetadata(ds, currentPrices(), nil, []string{cardID}, false)
	card = metadata[cardID]
	if card.Velocity != "" || card.VelocityDetail != "" {
		t.Errorf("no data: got %q, %q", card.Velocity, card.VelocityDetail)
	}
}

// velocityPageVars is one card on a results page, its velocity read from the snapshot.
func velocityPageVars(canVelocity, showUpsell bool) PageVars {
	const cardID = "velocity-card"
	rate, detail, _ := salesVelocityStore.Snapshot().View(cardID)
	return PageVars{
		ShowUpsell: showUpsell,
		SearchVars: SearchVars{
			CondKeys:     []mtgban.Condition{"NM"},
			AllKeys:      []string{cardID},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{},
			CanVelocity:  canVelocity,
		},
		Metadata: map[string]GenericCard{cardID: {Name: "Some Card", Edition: "Some Set", Velocity: rate, VelocityDetail: detail}},
	}
}

const velocityUpsell = "Increase your tier to unlock sales velocity"

const velocitySortTip = "Increase your tier to sort by sales velocity"

// velocityPages renders vars on both layouts.
func velocityPages(t *testing.T, vars PageVars) map[string]string {
	t.Helper()
	return map[string]string{"desktop": renderDesktopSearch(t, vars), "mobile": renderMobileSearch(t, vars)}
}

// TestSearchShowsSalesVelocity shows the row to a reader with the flag, the
// upsell to one without, and neither for a card with no data.
func TestSearchShowsSalesVelocity(t *testing.T) {
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{
		"velocity-card": {Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)},
	})
	for name, page := range velocityPages(t, velocityPageVars(true, true)) {
		for _, want := range []string{"TCGplayer sales", "2.3/day", "Sold on TCGplayer, last 30 days", ">days with a sale<", ">2026-10-11<"} {
			if strings.Count(page, want) != 1 {
				t.Errorf("%s: want %q once, rendered:\n%s", name, want, page)
			}
		}
		if strings.Contains(page, velocityUpsell) {
			t.Errorf("%s: upsell shown to a reader with the row", name)
		}
	}

	for name, page := range velocityPages(t, velocityPageVars(false, true)) {
		if strings.Count(page, velocityUpsell) != 1 {
			t.Errorf("%s: want the upsell once, rendered:\n%s", name, page)
		}
		for _, mark := range []string{"TCGplayer sales", "2.3/day", "Sold on TCGplayer", "2026-10-11"} {
			if strings.Contains(page, mark) {
				t.Errorf("%s: %q shown to a reader without the newspaper tier", name, mark)
			}
		}
	}

	for name, page := range velocityPages(t, velocityPageVars(false, false)) {
		if strings.Contains(page, velocityUpsell) || strings.Contains(page, "TCGplayer sales") {
			t.Errorf("%s: a reader hiding upsells still sees one", name)
		}
	}

	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{})
	for _, canVelocity := range []bool{true, false} {
		for name, page := range velocityPages(t, velocityPageVars(canVelocity, true)) {
			if strings.Contains(page, "TCGplayer sales") || strings.Contains(page, velocityUpsell) {
				t.Errorf("%s: row or upsell shown for a card with no sales data", name)
			}
		}
	}
}

// TestMobileSalesRowOpensBuyers gives a card with no buylist a Buyers panel to
// hold the row, saying there are no offers, and no panel without a row.
func TestMobileSalesRowOpensBuyers(t *testing.T) {
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{"velocity-card": {Copies: 69, Orders: 31, Days: 18}})
	sellers := func(vars PageVars) PageVars {
		vars.FoundSellers = map[string]map[mtgban.Condition][]SearchEntry{
			"velocity-card": {"NM": {{ScraperName: "Some Store", Price: 1}}},
		}
		return vars
	}
	page := renderMobileSearch(t, sellers(velocityPageVars(true, true)))
	if !strings.Contains(page, `id="buyers-velocity-card"`) || !strings.Contains(page, "No offers") {
		t.Errorf("want a Buyers panel with no offers, rendered:\n%s", page)
	}
	page = renderMobileSearch(t, sellers(velocityPageVars(false, false)))
	if strings.Contains(page, `id="buyers-velocity-card"`) {
		t.Errorf("want no Buyers panel without a row, rendered:\n%s", page)
	}
}

// setCounterspellVelocity files the same sales for every Counterspell printing.
func setCounterspellVelocity(t *testing.T) {
	t.Helper()
	ids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(ids) == 0 {
		t.Fatalf("no Counterspell printings to file sales for: %v", err)
	}
	cards := map[string]*salesvelocity.Sales{}
	for _, id := range ids {
		cards[id] = &salesvelocity.Sales{Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	}
	setTestSalesVelocity(t, cards)
}

// TestSearchGatesSalesVelocityByTier shows the row only to a verified newspaper tier, and the upsell to the others.
func TestSearchGatesSalesVelocityByTier(t *testing.T) {
	skipWithoutDatastore(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	setCounterspellVelocity(t)
	page := func(cookie string) string {
		req := httptest.NewRequest(http.MethodGet, "/search?q=Counterspell", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		}
		w := httptest.NewRecorder()
		testSite.Search(w, req)
		return w.Body.String()
	}

	withSigMode(t, true, false)
	if !strings.Contains(page(""), `class="sales-velocity"`) {
		t.Error("dev mode with signing off: no row")
	}

	signingEnabled(t, true)
	reader := func(news string) url.Values {
		fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
		if news != "" {
			fields.Set("NewsEnabled", news)
		}
		return fields
	}
	for _, news := range []string{"1day", "3day"} {
		got := page(signedAs(t, reader(news), time.Now().Add(time.Hour)))
		if !strings.Contains(got, `class="sales-velocity"`) {
			t.Errorf("a signed NewsEnabled=%s sees no row", news)
		}
		if strings.Contains(got, velocityUpsell) {
			t.Errorf("a signed NewsEnabled=%s sees the upsell", news)
		}
	}

	forgedFields := reader("1day")
	forgedFields.Set("Expires", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
	forgedFields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(forgedFields.Encode()))
	for name, cookie := range map[string]string{
		"anonymous":              "",
		"signed, no NewsEnabled": signedAs(t, reader(""), time.Now().Add(time.Hour)),
		"forged NewsEnabled":     forged,
	} {
		got := page(cookie)
		if !strings.Contains(got, `class="result-card-name"`) {
			t.Fatalf("%s: the page shows no results to check", name)
		}
		if strings.Contains(got, `class="sales-velocity"`) {
			t.Errorf("%s: sees the row", name)
		}
		if !strings.Contains(got, velocityUpsell) {
			t.Errorf("%s: sees no upsell", name)
		}
	}
}

// TestOEmbedLeavesOutSalesVelocity keeps the row and the upsell out of the unfurl everyone reads.
func TestOEmbedLeavesOutSalesVelocity(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	openSearch(t)
	setCounterspellVelocity(t)

	w := httptest.NewRecorder()
	target := "/search/oembed?format=json&url=" + url.QueryEscape("https://mtgban.com/search?q=Counterspell")
	testSite.SearchOEmbed(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("answered %d, want 200", w.Code)
	}
	for _, mark := range []string{"sales-velocity", "2.3/day", "Sold on TCGplayer", velocityUpsell} {
		if strings.Contains(w.Body.String(), mark) {
			t.Errorf("the preview carries %q", mark)
		}
	}
}

// velocityCard is a card object filed under the uuid the tests file sales for.
func velocityCard() *matcher.CardObject {
	co := &matcher.CardObject{}
	co.UUID = "velocity-card"
	return co
}

// TestVelocityFilterParses reads both keys and operators, any case and negated,
// always locked, and drops what is not a rate.
func TestVelocityFilterParses(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()
	for _, tc := range []struct {
		query, name, value string
		limit              float64
		negate             bool
	}{
		{"v>1", "locked_velocity_greater_than", "1", 1, false},
		{"velocity>0.5", "locked_velocity_greater_than", "0.5", 0.5, false},
		{"v<2", "locked_velocity_less_than", "2", 2, false},
		{"VELOCITY<2", "locked_velocity_less_than", "2", 2, false},
		{"-v>1", "locked_velocity_greater_than", "1", 1, true},
	} {
		config := parseSearchPage(ds, currentPrices(), tc.query, false, false, nil, nil, nil)
		if len(config.CardFilters) != 1 {
			t.Fatalf("%s: got %d filters", tc.query, len(config.CardFilters))
		}
		got := config.CardFilters[0]
		if got.Name != tc.name || got.Negate != tc.negate || !slices.Equal(got.Values, []string{tc.value}) || got.Value != tc.limit {
			t.Errorf("%s: got %+v", tc.query, got)
		}
	}
	for _, query := range []string{"v>fast", "v:1", "velocity:1", "v>nan", "v<NaN", "v>inf", "v<-Inf"} {
		config := parseSearchPage(ds, currentPrices(), query, false, false, nil, nil, nil)
		if len(config.CardFilters) != 0 {
			t.Errorf("%s: got filters %+v", query, config.CardFilters)
		}
	}
}

// TestVelocityFilterCompares judges the rate the row shows, skips a card with
// no data, and matches nothing until unlocked.
func TestVelocityFilterCompares(t *testing.T) {
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{"velocity-card": {Copies: 69, Orders: 31, Days: 18}})
	co := velocityCard()
	missing := &matcher.CardObject{}
	missing.UUID = "no-data"
	for _, tc := range []struct {
		desc string
		name string
		neg  bool
		card *matcher.CardObject
		val  float64
		skip bool
	}{
		{"over the limit", "velocity_greater_than", false, co, 1, false},
		{"at the limit", "velocity_greater_than", false, co, 2.3, true},
		{"under the limit", "velocity_greater_than", false, co, 5, true},
		{"less than a higher rate", "velocity_less_than", false, co, 5, false},
		{"at the limit, less than", "velocity_less_than", false, co, 2.3, true},
		{"less than a lower rate", "velocity_less_than", false, co, 1, true},
		{"negated", "velocity_greater_than", true, co, 5, false},
		{"no data, greater", "velocity_greater_than", false, missing, 0, true},
		{"no data, less", "velocity_less_than", false, missing, 5, true},
		{"no data, negated", "velocity_greater_than", true, missing, 1, false},
		{"locked, greater", "locked_velocity_greater_than", false, co, 1, true},
		{"locked, less", "locked_velocity_less_than", false, co, 5, true},
		{"locked, negated", "locked_velocity_greater_than", true, co, 5, true},
		{"locked, negated, no data", "locked_velocity_greater_than", true, missing, 5, true},
	} {
		filters := []FilterElem{{Name: tc.name, Negate: tc.neg, Value: tc.val, Sales: salesVelocityStore.Snapshot()}}
		got := shouldSkipCard(nil, nil, tc.card, filters)
		if got != tc.skip {
			t.Errorf("%s: skip = %v, want %v", tc.desc, got, tc.skip)
		}
	}
}

// TestUnlockVelocityReachesPools opens the filters of a pool's subquery too,
// and says whether any stayed locked.
func TestUnlockVelocityReachesPools(t *testing.T) {
	locked := func() []FilterElem {
		return []FilterElem{{Name: "pool", Pool: &SearchConfig{CardFilters: []FilterElem{{Name: "locked_velocity_greater_than"}}}}}
	}
	filters := locked()
	if !lockedVelocity(filters) {
		t.Error("a pool's locked filter reads as unlocked")
	}
	sales := &salesvelocity.Snapshot{}
	unlockVelocity(filters, sales)
	opened := filters[0].Pool.CardFilters[0]
	if lockedVelocity(filters) || opened.Name != "velocity_greater_than" || opened.Sales != sales {
		t.Errorf("still locked, or judging other sales: %+v", opened)
	}
	if lockedVelocity([]FilterElem{{Name: "name"}}) {
		t.Error("a query with no velocity filter reads as locked")
	}
}

// TestSearchGatesVelocityFilterByTier finds the cards for a newspaper tier on
// the page and the export, and nothing, with the notice, for anyone else.
func TestSearchGatesVelocityFilterByTier(t *testing.T) {
	skipWithoutDatastore(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	setCounterspellVelocity(t)
	const results = `class="result-card-name"`
	render := func(query, cookie string, mobile bool) string {
		req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(query), nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		}
		if mobile {
			req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		}
		w := httptest.NewRecorder()
		testSite.Search(w, req)
		return w.Body.String()
	}
	page := func(query, cookie string) string { return render(query, cookie, false) }

	signingEnabled(t, true)
	fields := func(news string) url.Values {
		reader := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
		if news != "" {
			reader.Set("NewsEnabled", news)
		}
		return reader
	}
	tier := signedAs(t, fields("1day"), time.Now().Add(time.Hour))
	got := page("Counterspell v>1", tier)
	if !strings.Contains(got, results) || strings.Contains(got, VelocityLockedMessage) {
		t.Error("a newspaper tier finds nothing over the rate, or sees the notice")
	}
	if strings.Contains(page("Counterspell v>5", tier), results) {
		t.Error("a newspaper tier finds cards under the rate")
	}
	if strings.Contains(page(`in:(Counterspell v>5)`, tier), results) {
		t.Error("a pool's filter stays locked or does not apply")
	}

	for name, cookie := range map[string]string{
		"anonymous":              "",
		"signed, no NewsEnabled": signedAs(t, fields(""), time.Now().Add(time.Hour)),
	} {
		got := page("Counterspell v>1", cookie)
		if strings.Contains(got, results) {
			t.Errorf("%s: the filter finds cards", name)
		}
		negated := page("Counterspell -v>1", cookie)
		if strings.Contains(negated, results) || !strings.Contains(negated, VelocityLockedMessage) {
			t.Errorf("%s: the negated filter finds cards, or shows no notice", name)
		}
		if !strings.Contains(got, VelocityLockedMessage) {
			t.Errorf("%s: no notice", name)
		}
		if !strings.Contains(render("Counterspell v>1", cookie, true), VelocityLockedMessage) {
			t.Errorf("%s: no notice on a phone", name)
		}
		if strings.Contains(page("Counterspell", cookie), VelocityLockedMessage) {
			t.Errorf("%s: the notice shows on a search without the filter", name)
		}
	}
}

// TestSearchExportGatesVelocityFilter holds the export to the page's rule, and
// a key to none of it: the API does not read the filter, whatever the key carries.
func TestSearchExportGatesVelocityFilter(t *testing.T) {
	skipWithoutDatastore(t)
	name := searchStores(t)
	id, _ := plainCard(t)
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{id: {Copies: 69, Orders: 31, Days: 18}})
	signingEnabled(t, false)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")

	rows := func(query, news string) int {
		fields := url.Values{"SearchDownloadCSV": {"true"}}
		if news != "" {
			fields.Set("NewsEnabled", news)
		}
		req := httptest.NewRequest(http.MethodGet, "/search/export/retail/"+url.PathEscape(query)+".csv?id=mtgjson", nil)
		req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
		w := httptest.NewRecorder()
		testSite.SearchExport(w, req)
		return strings.Count(w.Body.String(), "\n") - 1
	}
	for _, tc := range []struct {
		query, news string
		found       bool
	}{
		{name, "", true},
		{name + " v>1", "1day", true},
		{name + " v>5", "1day", false},
		{name + " v>1", "", false},
	} {
		if (rows(tc.query, tc.news) > 0) != tc.found {
			t.Errorf("%q with NewsEnabled=%q: found %v, want %v", tc.query, tc.news, !tc.found, tc.found)
		}
	}

	handler := enforceAPISigning(http.HandlerFunc(testSite.SearchAPI))
	key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"APImode": {"all"}, "UserEmail": {"plan@example.com"}, "NewsEnabled": {"1day"}},
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	requests := 0
	api := func(query string) string {
		target := "/api/mtgban/search/retail/" + url.PathEscape(query) + ".json?sig=" + url.QueryEscape(key)
		req := httptest.NewRequest(http.MethodGet, target, nil)
		// The API limiter is shared and keyed on the address.
		requests++
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 80+requests)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Body.String()
	}
	if !strings.Contains(api(name), "Card Kingdom") {
		t.Fatal("the API lists no store for the card, so the rest proves nothing")
	}
	if body := api(name + " v>1"); strings.Contains(body, "Card Kingdom") {
		t.Errorf("the API reads the filter: %s", body)
	}
}

// velocitySortKeys sorts keys by velocity, reversed if asked, and returns them.
func velocitySortKeys(keys []string, reversed bool) []string {
	target := "/search"
	if reversed {
		target += "?reverse=true"
	}
	sorted := slices.Clone(keys)
	sortSearchKeys(httptest.NewRequest(http.MethodGet, target, nil), currentDatastore(), currentPrices(), sorted, nil, salesVelocityStore.Snapshot(), "velocity")
	return sorted
}

// TestSortSearchKeysByVelocity ranks the fastest first, reverses to slowest
// first, and leaves a card with no data last in both directions.
func TestSortSearchKeysByVelocity(t *testing.T) {
	skipWithoutDatastore(t)
	ids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(ids) < 4 {
		t.Skip("matcher data not loaded")
	}
	fast, slow, none, zero := ids[0], ids[1], ids[2], ids[3]
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{
		fast: {Copies: 90},
		slow: {Copies: 3},
		zero: {LastSale: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)},
	})
	keys := []string{none, zero, slow, fast}
	if got, want := velocitySortKeys(keys, false), []string{fast, slow, zero, none}; !slices.Equal(got, want) {
		t.Errorf("fastest first: got %v, want %v", got, want)
	}
	if got, want := velocitySortKeys(keys, true), []string{zero, slow, fast, none}; !slices.Equal(got, want) {
		t.Errorf("slowest first: got %v, want %v", got, want)
	}
}

// TestSearchKeepsItsSalesSnapshot filters, sorts and shows a search from the
// sales it started with, though a new load is published partway through.
func TestSearchKeepsItsSalesSnapshot(t *testing.T) {
	skipWithoutDatastore(t)
	ds := currentDatastore()
	p := currentPrices()
	ids, err := ds.backend.SearchEquals("Counterspell")
	if err != nil || len(ids) < 2 {
		t.Skip("matcher data not loaded")
	}
	fast, slow := ids[0], ids[1]
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{
		fast: {Copies: 90},
		slow: {Copies: 60},
	})
	started := salesVelocityStore.Snapshot()

	config := parseSearchPage(ds, p, "Counterspell v>1", false, false, nil, nil, nil)
	config.Sales = salesVelocityStore.Snapshot()
	unlockVelocity(config.CardFilters, config.Sales)
	config.VelocitySort = true

	// The next load has the two the other way round, and neither over the limit.
	salesVelocityStore.Publish(&salesvelocity.Snapshot{
		Cards:  map[string]*salesvelocity.Sales{fast: {Copies: 3}, slow: {Copies: 6}},
		Window: salesvelocity.Window,
	})
	if config.Sales != started || config.CardFilters[0].Sales != started {
		t.Fatal("the request holds a snapshot it did not start with")
	}

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	result := runSearch(r, ds, p, config)
	keys := orderSearchKeys(r, ds, p, result, config.Sales, "velocity").keys
	if !slices.Equal(keys, []string{fast, slow}) {
		t.Fatalf("filtered and sorted %v, want %v", keys, []string{fast, slow})
	}
	metadata, _ := searchMetadata(ds, p, config.Sales, keys, false)
	got := metadata[fast].Velocity
	if got != "3.0/day" {
		t.Errorf("shows %q, want the rate it started with", got)
	}
}

// TestReadSearchSortGatesVelocity drops velocity however it was asked for,
// unless a handler unlocked it, and leaves the other sorts alone.
func TestReadSearchSortGatesVelocity(t *testing.T) {
	cookie := &http.Cookie{Name: "SearchDefaultSort", Value: "velocity"}
	for _, tc := range []struct {
		desc   string
		target string
		cookie *http.Cookie
		config SearchConfig
		want   string
	}{
		{"syntax, locked", "/search", nil, SearchConfig{SortMode: "velocity"}, ""},
		{"parameter, locked", "/search?sort=velocity", nil, SearchConfig{}, ""},
		{"saved default, locked", "/search", cookie, SearchConfig{}, ""},
		{"syntax, unlocked", "/search", nil, SearchConfig{SortMode: "velocity", VelocitySort: true}, "velocity"},
		{"parameter, unlocked", "/search?sort=velocity", nil, SearchConfig{VelocitySort: true}, "velocity"},
		{"saved default, unlocked", "/search", cookie, SearchConfig{VelocitySort: true}, "velocity"},
		{"another sort, locked", "/search?sort=retail", nil, SearchConfig{}, "retail"},
		{"syntax beats the parameter", "/search?sort=velocity", nil, SearchConfig{SortMode: "alpha"}, "alpha"},
		{"refused syntax, parameter next", "/search?sort=number", nil, SearchConfig{SortMode: "velocity"}, "number"},
		{"refused parameter, saved default next", "/search?sort=velocity", &http.Cookie{Name: "SearchDefaultSort", Value: "alpha"}, SearchConfig{}, "alpha"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		if tc.cookie != nil {
			req.AddCookie(tc.cookie)
		}
		got := readSearchSort(req, tc.config)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.desc, got, tc.want)
		}
	}
}

// TestSearchGatesVelocitySortByTier orders the page for a newspaper tier, and
// for anyone else keeps the default order, however asked, with the pill greyed
// out and its tooltip.
func TestSearchGatesVelocitySortByTier(t *testing.T) {
	skipWithoutDatastore(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	ids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(ids) < 4 {
		t.Skip("matcher data not loaded")
	}
	// The default order's last card, the one a real sort has to move first.
	chrono := velocitySortChrono(ids)
	fastest := chrono[len(chrono)-1]
	co, err := backend().GetUUID(fastest)
	if err != nil {
		t.Fatal(err)
	}
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{fastest: {Copies: 90}})
	signingEnabled(t, true)
	fields := func(news string) url.Values {
		reader := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
		if news != "" {
			reader.Set("NewsEnabled", news)
		}
		return reader
	}
	tier := signedAs(t, fields("1day"), time.Now().Add(time.Hour))
	lower := signedAs(t, fields(""), time.Now().Add(time.Hour))
	page := func(target, cookie string) string {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		w := httptest.NewRecorder()
		testSite.Search(w, req)
		return w.Body.String()
	}
	// The rate row is the tier's only, so the first card's set line says who is first.
	firstCard := func(body string) string {
		_, rest, found := strings.Cut(body, `class="result-card-name"`)
		if !found {
			t.Fatal("the page shows no results")
		}
		first, _, _ := strings.Cut(rest, "</a>")
		return first
	}
	number := "cns%3A" + url.QueryEscape(co.Card.Number)
	for _, target := range []string{"/search?q=Counterspell+sort%3Avelocity", "/search?q=Counterspell&sort=velocity"} {
		got := page(target, tier)
		if !strings.Contains(firstCard(got), number) {
			t.Errorf("%s: a newspaper tier does not get the fastest card first: %s", target, firstCard(got))
		}
		if strings.Contains(got, velocitySortTip) {
			t.Errorf("%s: a newspaper tier sees the locked pill", target)
		}
		locked := page(target, lower)
		// Once, on the pill: there is no notice.
		if strings.Count(locked, velocitySortTip) != 1 {
			t.Errorf("%s: want the tooltip once for a reader without the tier", target)
		}
		if strings.Contains(firstCard(locked), number) {
			t.Errorf("%s: the order reveals the fastest card", target)
		}
	}
	const pill = `sort=velocity`
	if !strings.Contains(page("/search?q=Counterspell", tier), pill) {
		t.Error("a newspaper tier has no velocity pill")
	}
	plain := page("/search?q=Counterspell", lower)
	if strings.Contains(plain, pill) || !strings.Contains(plain, "sort-pill-locked") {
		t.Error("a reader without the tier should see the pill locked, with no link")
	}
	if strings.Count(plain, velocitySortTip) != 1 {
		t.Error("want the tooltip once, on the pill")
	}
	if strings.Contains(page("/search?q=Counterspell+sort%3Aalpha&sort=velocity", lower), `class="search-sort-pill`) {
		t.Error("the query's own sort should leave no pills up")
	}
	// The pills link back with the typed sort still in the query, and must work.
	_, active, found := strings.Cut(page("/search?q=Counterspell+sort%3Avelocity&sort=number", lower), `search-sort-pill active`)
	if !found {
		t.Fatal("no sort pill is active after picking one past a refused sort:velocity")
	}
	activeTag, _, _ := strings.Cut(active, ">")
	if !strings.Contains(activeTag, "sort=number") {
		t.Errorf("the pill picked past a refused sort:velocity is not the active one: %s", activeTag)
	}
	setSalesVelocityStore(t, &salesvelocity.Store{})
	if strings.Contains(page("/search?q=Counterspell&sort=velocity", lower), velocitySortTip) {
		t.Error("the pill shows with no sales loaded")
	}
}

// velocitySortChrono is keys in the default order.
func velocitySortChrono(keys []string) []string {
	sorted := slices.Clone(keys)
	sortSearchKeys(httptest.NewRequest(http.MethodGet, "/search", nil), currentDatastore(), currentPrices(), sorted, nil, nil, "")
	return sorted
}

// TestSearchExportGatesVelocitySort holds the export's order to the page's rule.
func TestSearchExportGatesVelocitySort(t *testing.T) {
	skipWithoutDatastore(t)
	ids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(ids) < 2 {
		t.Skip("matcher data not loaded")
	}
	signingEnabled(t, false)
	inventory := mtgban.InventoryRecord{}
	for _, id := range ids {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 1, Quantity: 1})
	}
	withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market"})}, nil)
	chrono := velocitySortChrono(ids)
	fastest := chrono[len(chrono)-1]
	co, err := backend().GetUUID(fastest)
	if err != nil {
		t.Fatal(err)
	}
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{fastest: {Copies: 90}})
	firstRow := func(news string) string {
		fields := url.Values{"SearchDownloadCSV": {"true"}}
		if news != "" {
			fields.Set("NewsEnabled", news)
		}
		req := httptest.NewRequest(http.MethodGet, "/search/export/retail/Counterspell.csv?id=mtgjson&sort=velocity", nil)
		req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
		w := httptest.NewRecorder()
		testSite.SearchExport(w, req)
		lines := strings.Split(w.Body.String(), "\n")
		if len(lines) < 2 {
			t.Fatalf("no rows: %s", w.Body.String())
		}
		return lines[1]
	}
	want := co.SetCode + "," + co.Edition + "," + co.Card.Number
	if !strings.Contains(firstRow("1day"), want) {
		t.Errorf("a newspaper tier's export does not start with the fastest card: %s, want %s", firstRow("1day"), want)
	}
	if strings.Contains(firstRow(""), want) {
		t.Error("the export's order reveals the fastest card")
	}
}

// TestVelocitySortPillShowsLocked greys the pill out, on both layouts, for a
// reader without the tier, the upsell setting aside, and only with sales loaded.
func TestVelocitySortPillShowsLocked(t *testing.T) {
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{"velocity-card": {Copies: 69}})
	const locked, linked = "sort-pill-locked", "sort=velocity"
	vars := func(canVelocity, loaded bool) PageVars {
		page := velocityPageVars(canVelocity, false)
		page.SearchRan = true
		page.TotalUnique = 1
		page.HasVelocity = loaded
		return page
	}
	for name, page := range velocityPages(t, vars(false, true)) {
		if !strings.Contains(page, locked) || strings.Contains(page, linked) {
			t.Errorf("%s: want the pill greyed out with no link", name)
		}
	}
	for name, page := range velocityPages(t, vars(true, true)) {
		if strings.Contains(page, locked) || !strings.Contains(page, linked) {
			t.Errorf("%s: want a working pill for a newspaper tier", name)
		}
	}
	for name, page := range velocityPages(t, vars(false, false)) {
		if strings.Contains(page, locked) {
			t.Errorf("%s: the pill shows with no sales loaded", name)
		}
	}
}

// newspaperSalesAnswers answers checkNewspaperSales's queries: the newest day,
// then each day in turn, as rows and those over five orders.
func newspaperSalesAnswers(newest driver.Value, days ...[2]int64) func(string) (*fakeRows, error) {
	return func(query string) (*fakeRows, error) {
		if query == salesvelocity.NewestSaleQuery {
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

// TestVelocityRateOnInfoPages shows the rate and its tooltip on arbitrage, Global
// and upload's optimizer, whatever the reader's tier, on the card selling fast
// enough alone, and none on upload's results.
func TestVelocityRateOnInfoPages(t *testing.T) {
	cards := closeVendors(t)
	for _, name := range []string{"Arbitrage", "Global"} {
		if LogPages[name] == nil {
			LogPages[name] = log.New(io.Discard, "", 0)
			t.Cleanup(func() { delete(LogPages, name) })
		}
	}
	withConfigCopy(t)
	Config().Stores.GlobalAllowList = []string{"ZZG"}
	Config().Stores.GlobalProbeList = []string{"ZZA"}
	stock := mtgban.InventoryRecord{}
	probe := mtgban.InventoryRecord{}
	ref := mtgban.InventoryRecord{}
	rows := ""
	for _, card := range cards {
		stock[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 1, Quantity: 2, URL: "u"}}
		probe[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 10, Quantity: 2, URL: "u"}}
		ref[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 100}}
		rows += card + "\t1\t\t0\t\n"
	}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(stock, sessionInfo("ZZS")),
		mtgban.NewSellerFromInventory(probe, sessionInfo("ZZG")),
		mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA")),
	}, currentPrices().vendors)
	co, err := backend().GetUUID(cards[0])
	if err != nil {
		t.Fatal(err)
	}
	slow, err := backend().GetUUID(cards[1])
	if err != nil {
		t.Fatal(err)
	}
	setTestSalesVelocity(t, map[string]*salesvelocity.Sales{
		co.UUID:   {Copies: 69, Orders: 31, Days: 18},
		slow.UUID: {Copies: 3, Orders: 3, Days: 3},
	})

	pages := map[string]func(cookie *http.Cookie) string{
		"arbitrage": func(cookie *http.Cookie) string {
			req := httptest.NewRequest(http.MethodGet, "/arbit?source=ZZS", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			testSite.Arbit(rec, req)
			return rec.Body.String()
		},
		"global": func(cookie *http.Cookie) string {
			req := httptest.NewRequest(http.MethodGet, "/global?source=ZZG&f=1&legit=0", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			testSite.Global(rec, req)
			return rec.Body.String()
		},
		"upload": func(cookie *http.Cookie) string {
			form := url.Values{"mode": {"true"}, "stores": {"ZZV", "ZZW"}, "rows": {rows}}
			req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			testSite.Upload(rec, req)
			return rec.Body.String()
		},
	}

	signingEnabled(t, true)
	reader := func(news string) *http.Cookie {
		fields := url.Values{
			"UserEmail": {"reader@example.com"}, "UserTier": {"Test"},
			"ArbitEnabled": {"ALL"}, "AnyEnabled": {"true"},
			"UploadBuylistEnabled": {"true"}, "UploadChangeStoresEnabled": {"true"},
		}
		if news != "" {
			fields.Set("NewsEnabled", news)
		}
		return &http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))}
	}
	const shown = `class="bl-velocity"`
	for name, page := range pages {
		got := page(reader("1day"))
		if strings.Count(got, shown) == 0 {
			t.Errorf("%s: a newspaper tier sees no rate in the %d byte page", name, len(got))
			continue
		}
		if !strings.Contains(got, `>2.3/day</span>`) || !strings.Contains(got, `data-tip="**Sold on TCGplayer, last 30 days**`) {
			t.Errorf("%s: the rate lacks its tooltip or text", name)
		}
		if strings.Contains(got, `>0.1/day</span>`) {
			t.Errorf("%s: a rate of 0.1/day shows", name)
		}
		if !strings.Contains(page(reader("")), shown) {
			t.Errorf("%s: the rate is hidden without the Newspaper", name)
		}
		if name == "upload" && regexp.MustCompile(`ures-card-set[^\n]*bl-velocity`).MatchString(got) {
			t.Error("upload: a rate on the results table")
		}
		if !strings.Contains(got, "INFO</th>") {
			t.Errorf("%s: no INFO column", name)
		}
	}
}

// TestVelocityRateSitsBesideCKSignal keeps INFO to one line for the signal and the
// rate, with the rate's own tooltip, and the signal's line alone for a slow card.
func TestVelocityRateSitsBesideCKSignal(t *testing.T) {
	render := func(notable bool) string {
		vars := reversePageVars()
		for id, card := range vars.Metadata {
			card.CKSignal = "sell"
			card.Velocity, card.VelocityDetail, card.VelocityNotable = "2.3/day", "**Sold**\n|copies|69", notable
			vars.Metadata[id] = card
		}
		return renderArbit(t, vars)
	}
	const signal = `<span class="bl-ck bl-ck-sell">Sell now</span>`
	got := render(true)
	if !strings.Contains(got, `<span class="bl-ck-line">`+signal+`<span class="bl-velocity" title="`) || !strings.Contains(got, `>2.3/day</span></span>`) {
		t.Error("the rate is not beside the signal")
	}
	if !strings.Contains(render(false), `<span class="bl-ck-line">`+signal+`</span>`) {
		t.Error("a slow card's signal shares its line")
	}
}
