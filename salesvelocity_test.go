package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// setTestSalesVelocity files cards as the loaded sales, restoring the last load when the test ends.
func setTestSalesVelocity(t *testing.T, cards map[string]*salesVelocity) {
	t.Helper()
	prev := salesVelocityPtr.Load()
	t.Cleanup(func() { salesVelocityPtr.Store(prev) })
	salesVelocityPtr.Store(&salesVelocitySnapshot{
		Day:    time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
		Cards:  cards,
		Window: salesVelocityWindow,
	})
}

// TestBuildSalesVelocity keys the pairs by card, adds up pairs on one card,
// keeps a year's sale with no sale in the window, and drops unmatched pairs.
func TestBuildSalesVelocity(t *testing.T) {
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }
	rows := []salesRow{
		{ProductID: 1, Variant: "Normal", Copies: 69, Orders: 31, Days: 18},
		{ProductID: 2, Variant: "Foil", Copies: 12, Orders: 9, Days: 4, Capped: true},
		// Two products filed under one card add up.
		{ProductID: 3, Variant: "Normal", Copies: 2, Orders: 2, Days: 2},
		{ProductID: 4, Variant: "Normal", Copies: 3, Orders: 1, Days: 1},
		// Their days add up too, but never past the window.
		{ProductID: 7, Variant: "Normal", Copies: 40, Orders: 40, Days: 20},
		{ProductID: 8, Variant: "Normal", Copies: 40, Orders: 40, Days: 20},
		// No card.
		{ProductID: 5, Variant: "Normal", Copies: 1, Orders: 1, Days: 1},
	}
	last := []lastRow{
		{ProductID: 1, Variant: "Normal", Last: day(10, 11)},
		{ProductID: 2, Variant: "Foil", Last: day(10, 12)},
		{ProductID: 3, Variant: "Normal", Last: day(10, 10)},
		{ProductID: 4, Variant: "Normal", Last: day(10, 12)},
		{ProductID: 7, Variant: "Normal", Last: day(10, 12)},
		{ProductID: 8, Variant: "Normal", Last: day(10, 11)},
		{ProductID: 5, Variant: "Normal", Last: day(10, 12)},
		// Sold in the year, not in the window.
		{ProductID: 6, Variant: "Normal", Last: day(8, 2)},
		// No card, and no sale in the window.
		{ProductID: 9, Variant: "Foil", Last: day(3, 1)},
	}
	ids := map[salesPair]string{
		{1, "Normal"}: "steady", {2, "Foil"}: "capped",
		{3, "Normal"}: "merged", {4, "Normal"}: "merged",
		{6, "Normal"}: "zero", {7, "Normal"}: "busy", {8, "Normal"}: "busy",
	}
	asked := map[salesPair]int{}
	match := func(productID int64, variant string) string {
		asked[salesPair{productID, variant}]++
		return ids[salesPair{productID, variant}]
	}

	cards, unmatched := buildSalesVelocity(rows, last, match)
	if unmatched != 2 {
		t.Errorf("unmatched: got %d, want 2", unmatched)
	}
	want := map[string]salesVelocity{
		"steady": {Copies: 69, Orders: 31, Days: 18, LastSale: day(10, 11)},
		"capped": {Copies: 12, Orders: 9, Days: 4, Capped: true, LastSale: day(10, 12)},
		"merged": {Copies: 5, Orders: 3, Days: 3, LastSale: day(10, 12)},
		"busy":   {Copies: 80, Orders: 80, Days: salesVelocityWindow, LastSale: day(10, 12)},
		"zero":   {LastSale: day(8, 2)},
	}
	if len(cards) != len(want) {
		t.Fatalf("got %d cards, want %d: %+v", len(cards), len(want), cards)
	}
	for id, w := range want {
		got := cards[id]
		if got == nil || *got != w {
			t.Errorf("%s: got %+v, want %+v", id, got, w)
		}
	}
	for pair, n := range asked {
		if n != 1 {
			t.Errorf("%v: matched %d times, want once", pair, n)
		}
	}
}

// TestSalesVelocityDue loads a sale day once, and retries a day whose load
// failed only after salesVelocityRetryAfter.
func TestSalesVelocityDue(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	prev := day.AddDate(0, 0, -1)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	loaded := func(d time.Time) *salesVelocitySnapshot { return &salesVelocitySnapshot{Day: d} }
	failed := func(d time.Time, ago time.Duration) *salesVelocityFailure {
		return &salesVelocityFailure{Day: d, At: now.Add(-ago)}
	}
	for _, tc := range []struct {
		desc    string
		current *salesVelocitySnapshot
		failed  *salesVelocityFailure
		want    bool
	}{
		{"nothing loaded yet", nil, nil, true},
		{"the day is loaded", loaded(day), nil, false},
		{"a newer sale day landed", loaded(prev), nil, true},
		{"the day failed an hour ago", loaded(prev), failed(day, time.Hour), false},
		{"the day failed long enough ago", loaded(prev), failed(day, salesVelocityRetryAfter), true},
		{"an older day failed", loaded(prev), failed(prev, time.Hour), true},
		{"the first load failed an hour ago", nil, failed(day, time.Hour), false},
	} {
		got := salesVelocityDue(tc.current, tc.failed, day, now)
		if got != tc.want {
			t.Errorf("%s: due = %v, want %v", tc.desc, got, tc.want)
		}
	}
}

// TestSalesVelocityFor answers a loaded card's sales, and nothing for a card
// not loaded or before any load.
func TestSalesVelocityFor(t *testing.T) {
	setTestSalesVelocity(t, map[string]*salesVelocity{"card": {Copies: 69, Orders: 31, Days: 18}})
	got, found := salesVelocityFor("card")
	if !found || got != (salesVelocity{Copies: 69, Orders: 31, Days: 18}) {
		t.Errorf("card: got %+v, %v", got, found)
	}
	_, found = salesVelocityFor("missing")
	if found {
		t.Error("missing: found")
	}
	salesVelocityPtr.Store(nil)
	_, found = salesVelocityFor("card")
	if found {
		t.Error("nothing loaded: found")
	}
}

// TestSalesVelocityReport is the line the admin dashboard shows for a load.
func TestSalesVelocityReport(t *testing.T) {
	snap := &salesVelocitySnapshot{
		Day:    time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
		Cards:  map[string]*salesVelocity{"a": {Copies: 3}, "b": {Copies: 9, Capped: true}, "c": {}},
		Window: salesVelocityWindow,
	}
	got := salesVelocityReport(snap, 7)
	want := "3 cards over the 30 days to 2026-10-12, 1 capped, 7 not matched"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
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

	s.ds.Store(&datastore{backend: &mtgmatcher.Backend{AllUUIDs: []string{"a-card"}}})
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

// TestReadSalesVelocity reads the 30-day window and the 365-day lookback, both
// ending on the sale day, for one game in one read-only snapshot, and ends
// that transaction before returning.
func TestReadSalesVelocity(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	lastSale := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		if query == salesVelocityQuery {
			return &fakeRows{cols: []string{"p", "v", "c", "o", "d", "x"}, vals: [][]driver.Value{
				{int64(1), "Normal", int64(69), int64(31), int64(18), true},
			}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}, vals: [][]driver.Value{{int64(6), "Foil", lastSale}}}, nil
	}}
	db := sql.OpenDB(f)
	t.Cleanup(func() { db.Close() })

	rows, last, err := readSales(context.Background(), db, "Magic: The Gathering", day)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rows, []salesRow{{ProductID: 1, Variant: "Normal", Copies: 69, Orders: 31, Days: 18, Capped: true}}) {
		t.Errorf("rows: got %+v", rows)
	}
	if len(last) != 1 || last[0].ProductID != 6 || last[0].Variant != "Foil" || !last[0].Last.Equal(lastSale) {
		t.Errorf("last: got %+v", last)
	}

	queries := f.seen()
	want := []salesQuery{
		{sql: salesVelocityQuery, args: []driver.Value{"2026-09-13", "2026-10-12", "Magic: The Gathering"}, inTx: true},
		{sql: salesVelocityLastQuery, args: []driver.Value{"2025-10-13", "2026-10-12", "Magic: The Gathering"}, inTx: true},
	}
	if len(queries) != len(want) {
		t.Fatalf("got %d queries, want %d", len(queries), len(want))
	}
	for i, w := range want {
		q := queries[i]
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

// TestSalesVelocitySQL keeps both queries bounded on both ends by the
// arguments and to one game's products, and the window's cap at five orders.
func TestSalesVelocitySQL(t *testing.T) {
	for name, query := range map[string]string{"window": salesVelocityQuery, "lookback": salesVelocityLastQuery} {
		for _, part := range []string{
			"sale_date BETWEEN $1::date AND $2::date",
			"product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)",
		} {
			if !strings.Contains(query, part) {
				t.Errorf("%s: missing %q", name, part)
			}
		}
	}
	if !strings.Contains(salesVelocityQuery, "bool_or(num_orders >= 5)") {
		t.Error("window: missing the five-order cap")
	}
}

// withFakeNewspaper makes f the newspaper of a magic site with a datastore, restoring the globals when the test ends.
func withFakeNewspaper(t *testing.T, f *fakeNewspaper) *site {
	t.Helper()
	withConfigCopy(t)
	prevDB, prevSkip := NewNewspaperDB, SkipNewspaper
	prevSnap, prevFailed := salesVelocityPtr.Load(), salesVelocityFailed.Load()
	db := sql.OpenDB(f)
	t.Cleanup(func() {
		db.Close()
		NewNewspaperDB, SkipNewspaper = prevDB, prevSkip
		salesVelocityPtr.Store(prevSnap)
		salesVelocityFailed.Store(prevFailed)
	})
	NewNewspaperDB, SkipNewspaper = db, false
	Config().Game = DefaultGame
	salesVelocityPtr.Store(nil)
	salesVelocityFailed.Store(nil)

	s := newSite()
	s.ds.Store(&datastore{backend: &mtgmatcher.Backend{AllUUIDs: []string{"a-card"}}})
	return s
}

// TestLoadSalesVelocityReadsOneGame reads the newest sale day, then that
// day's sales for the site's own game only.
func TestLoadSalesVelocityReadsOneGame(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	f := &fakeNewspaper{answer: func(query string) (*fakeRows, error) {
		if query == salesVelocityDayQuery {
			return &fakeRows{cols: []string{"max"}, vals: [][]driver.Value{{day}}}, nil
		}
		return &fakeRows{cols: []string{"p", "v", "l"}}, nil
	}}
	s := withFakeNewspaper(t, f)
	Config().Game = mtgmatcher.GameLorcana

	s.loadSalesVelocity()
	queries := f.seen()
	if len(queries) != 3 {
		t.Fatalf("got %d queries, want 3", len(queries))
	}
	if queries[0].sql != salesVelocityDayQuery || len(queries[0].args) != 0 {
		t.Errorf("first query: got %q %v, want the day query", queries[0].sql, queries[0].args)
	}
	for _, q := range queries[1:] {
		if len(q.args) != 3 || q.args[1] != "2026-10-12" || q.args[2] != gameMap[mtgmatcher.GameLorcana] {
			t.Errorf("got args %v, want the day and %q", q.args, gameMap[mtgmatcher.GameLorcana])
		}
	}
	failed := salesVelocityFailed.Load()
	if failed == nil || !failed.Day.Equal(day) {
		t.Errorf("a load matching no card: failure got %+v, want one for %s", failed, day.Format(time.DateOnly))
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loadSalesVelocity()
	}()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first load never queried the newspaper")
	}

	second := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loadSalesVelocity()
		close(second)
	}()
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
