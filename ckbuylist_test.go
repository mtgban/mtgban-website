package main

import (
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestCKSignalFor pins the rules of ADR-0004 and their order.
func TestCKSignalFor(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	quote := ckQuote{ID: "1", Buy: 10, Buying: true, Stock: 5, StockKnown: true}
	hist := ckHistory{
		StockYesterday: 5, HasStockYesterday: true,
		StockWeekAgo: 8, HasStockWeekAgo: true,
		BuyWeekAgo: 10, HasBuyWeekAgo: true,
		LastInStock: today.AddDate(0, 0, -1),
	}
	good := 9.0

	cases := []struct {
		name       string
		quote      func(q *ckQuote)
		hist       func(h *ckHistory)
		noHistory  bool
		good       float64
		wantState  string
		wantTip    string
		wantNoFact bool
	}{
		{name: "above P90 in stock", wantState: "sell", wantTip: ckTipSell},
		{name: "not buying", quote: func(q *ckQuote) { q.Buying = false }, wantNoFact: true},
		{name: "under a dollar", quote: func(q *ckQuote) { q.Buy = 0.9 }, good: 0.5},
		{name: "no P90", good: -1},
		{name: "ties P90", quote: func(q *ckQuote) { q.Buy = 9 }},
		{name: "stock halved since yesterday", quote: func(q *ckQuote) { q.Stock = 2 },
			wantState: "wait", wantTip: ckTipBuyout},
		{name: "halved from under three is no buyout",
			quote: func(q *ckQuote) { q.Stock = 1 }, hist: func(h *ckHistory) { h.StockYesterday = 2 },
			wantState: "sell", wantTip: ckTipSell},
		{name: "sold out since yesterday is a buyout", quote: func(q *ckQuote) { q.Stock = 0 },
			wantState: "wait", wantTip: ckTipBuyout},
		{name: "out of stock at P90",
			quote: func(q *ckQuote) { q.Stock, q.Buy = 0, 9 }, hist: func(h *ckHistory) { h.StockYesterday = 0 },
			wantState: "wait", wantTip: ckTipOutOfStock},
		{name: "out of stock above P90",
			quote: func(q *ckQuote) { q.Stock = 0 }, hist: func(h *ckHistory) { h.StockYesterday = 0 }},
		{name: "cut 20% wins over sell", hist: func(h *ckHistory) { h.BuyWeekAgo = 13 },
			wantState: "wait", wantTip: ckTipCut},
		{name: "cut under 20%", hist: func(h *ckHistory) { h.BuyWeekAgo = 12 },
			wantState: "sell", wantTip: ckTipSell},
		{name: "stock unknown", quote: func(q *ckQuote) { q.StockKnown, q.Stock = false, 0 }, wantNoFact: true},
		{name: "no history still sells", noHistory: true, wantState: "sell", wantTip: ckTipSell},
		{name: "no history, out of stock at P90", noHistory: true,
			quote:     func(q *ckQuote) { q.Stock, q.Buy = 0, 9 },
			wantState: "wait", wantTip: ckTipOutOfStock},
		{name: "no history sees no buyout", noHistory: true, quote: func(q *ckQuote) { q.Stock = 2 },
			wantState: "sell", wantTip: ckTipSell},
	}
	for _, tc := range cases {
		q, h, g := quote, hist, good
		if tc.quote != nil {
			tc.quote(&q)
		}
		if tc.hist != nil {
			tc.hist(&h)
		}
		if tc.good != 0 {
			g = max(tc.good, 0)
		}
		got := ckSignalFor(q, h, !tc.noHistory, g, today)
		if got.State != tc.wantState || got.Tip != tc.wantTip {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.name, got.State, got.Tip, tc.wantState, tc.wantTip)
		}
		if (got.Facts == "") != tc.wantNoFact {
			t.Errorf("%s: facts %q", tc.name, got.Facts)
		}
	}
}

// TestCKFacts pins the facts line.
func TestCKFacts(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		quote     ckQuote
		hist      ckHistory
		noHistory bool
		want      string
	}{
		{"out for days", ckQuote{Stock: 0, StockKnown: true, Buy: 5},
			ckHistory{LastInStock: today.AddDate(0, 0, -9)}, false, "CK stock 0 · out 9 days"},
		{"out since yesterday", ckQuote{Stock: 0, StockKnown: true, Buy: 5},
			ckHistory{LastInStock: today.AddDate(0, 0, -1)}, false, "CK stock 0 · out 1 day"},
		{"out all month", ckQuote{Stock: 0, StockKnown: true, Buy: 5},
			ckHistory{}, false, "CK stock 0 · out 30+ days"},
		{"in stock, a week ago", ckQuote{Stock: 3, StockKnown: true, Buy: 5},
			ckHistory{StockWeekAgo: 12, HasStockWeekAgo: true}, false, "CK stock 3 · 12 a week ago"},
		{"price cut", ckQuote{Stock: 3, StockKnown: true, Buy: 7.5},
			ckHistory{BuyWeekAgo: 10, HasBuyWeekAgo: true}, false, "CK stock 3 · buy −25% this week"},
		{"price raise", ckQuote{Stock: 3, StockKnown: true, Buy: 12},
			ckHistory{BuyWeekAgo: 10, HasBuyWeekAgo: true}, false, "CK stock 3 · buy +20% this week"},
		{"small change", ckQuote{Stock: 3, StockKnown: true, Buy: 10.5},
			ckHistory{BuyWeekAgo: 10, HasBuyWeekAgo: true}, false, "CK stock 3"},
		{"no history", ckQuote{Stock: 0, StockKnown: true, Buy: 5},
			ckHistory{}, true, "CK stock 0"},
		{"nothing known", ckQuote{Buy: 5}, ckHistory{}, true, ""},
	}
	for _, tc := range cases {
		got := ckFacts(tc.quote, tc.hist, !tc.noHistory, today)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCKHistoryFor checks a stale load is not used, and that a load from the
// day before does not pass its yesterday off as today's.
func TestCKHistoryFor(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	products := map[string]ckHistory{"1": {
		StockYesterday: 4, HasStockYesterday: true, BuyWeekAgo: 10, HasBuyWeekAgo: true,
	}}
	for _, tc := range []struct {
		name      string
		yesterday time.Time
		id        string
		want      bool
	}{
		{"fresh", today.AddDate(0, 0, -1), "1", true},
		{"two missed days", today.AddDate(0, 0, -3), "1", true},
		{"stale", today.AddDate(0, 0, -4), "1", false},
		{"unknown product", today.AddDate(0, 0, -1), "2", false},
		{"no id", today.AddDate(0, 0, -1), "", false},
	} {
		snap := &ckHistorySnapshot{Today: today, Yesterday: tc.yesterday, Products: products}
		h, found := snap.historyFor(tc.id, today)
		if found != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, found, tc.want)
		}
		if found && !h.HasStockYesterday {
			t.Errorf("%s: lost yesterday's stock", tc.name)
		}
	}

	var none *ckHistorySnapshot
	_, found := none.historyFor("1", today)
	if found {
		t.Error("no load: got a history")
	}

	// Loaded the day before, until the next load: its yesterday is two days
	// back, so only the week and the days out of stock still count.
	snap := &ckHistorySnapshot{Today: today.AddDate(0, 0, -1), Yesterday: today.AddDate(0, 0, -2), Products: products}
	h, found := snap.historyFor("1", today)
	if !found || h.HasStockYesterday || h.StockYesterday != 0 || !h.HasBuyWeekAgo {
		t.Errorf("loaded the day before: got %+v, %v; want the week kept and yesterday dropped", h, found)
	}
}

// TestLoadCKHistoryKeepsTheLastLoad checks an unreachable newspaper leaves the
// loaded history in place.
func TestLoadCKHistoryKeepsTheLastLoad(t *testing.T) {
	db, err := timeseries.SQLConfig{Host: "127.0.0.1", Port: 1, User: "none", Password: "none", DBName: "none"}.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	prevDB, prevGame, prevSkip, prevHistory := NewNewspaperDB, Config.Game, SkipNewspaper, ckHistoryPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB, Config.Game, SkipNewspaper = prevDB, prevGame, prevSkip
		ckHistoryPtr.Store(prevHistory)
	})
	NewNewspaperDB, Config.Game, SkipNewspaper = db, DefaultGame, false

	last := &ckHistorySnapshot{Products: map[string]ckHistory{"1": {}}}
	ckHistoryPtr.Store(last)
	testSite.loadCKHistory()
	if ckHistoryPtr.Load() != last {
		t.Error("a failed load replaced the history")
	}
}
