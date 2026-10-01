package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// ckTestCard is a card as the signal tests read it.
func ckTestCard(id string) *mtgmatcher.CardObject {
	return &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: id}}
}

// setTestCKOdds loads odds for the test, nil for none.
func setTestCKOdds(t *testing.T, odds *ckOdds) {
	t.Helper()
	prev := ckOddsPtr.Load()
	t.Cleanup(func() { ckOddsPtr.Store(prev) })
	ckOddsPtr.Store(odds)
}

// TestCKRuleFor pins the rules of ADR-0004 and their order: wait wins over
// sell.
func TestCKRuleFor(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	quote := ckQuote{ID: "1", Buy: 10, Buying: true, Stock: 5, StockKnown: true, Retail: 15}
	hist := ckHistory{StockYesterday: 5, HasStockYesterday: true}
	daysAgo := func(n int) time.Time { return today.AddDate(0, 0, -n) }

	for _, tc := range []struct {
		name       string
		quote      func(q *ckQuote)
		hist       func(h *ckHistory)
		noHistory  bool
		product    ckProduct
		verdict    string
		wantReason string
	}{
		{name: "nothing"},
		{name: "not buying", quote: func(q *ckQuote) { q.Buying = false }, product: ckProduct{SetReleased: daysAgo(30)}},
		{name: "under $3", quote: func(q *ckQuote) { q.Buy = 2.99 }, product: ckProduct{SetReleased: daysAgo(30)}},

		{name: "stock halved", quote: func(q *ckQuote) { q.Stock = 2 }, verdict: "wait", wantReason: "halved"},
		{name: "stock 4 to 2", quote: func(q *ckQuote) { q.Stock = 2 }, hist: func(h *ckHistory) { h.StockYesterday = 4 },
			verdict: "wait", wantReason: "halved"},
		{name: "stock 5 to 3", quote: func(q *ckQuote) { q.Stock = 3 }},
		{name: "halved from under 3", quote: func(q *ckQuote) { q.Stock = 1 }, hist: func(h *ckHistory) { h.StockYesterday = 2 }},
		{name: "sold out", quote: func(q *ckQuote) { q.Stock = 0 }, verdict: "wait", wantReason: "soldout"},
		{name: "sold out from 1", quote: func(q *ckQuote) { q.Stock = 0 }, hist: func(h *ckHistory) { h.StockYesterday = 1 },
			verdict: "wait", wantReason: "soldout"},
		{name: "out of stock since before yesterday", quote: func(q *ckQuote) { q.Stock = 0 }, hist: func(h *ckHistory) { h.StockYesterday = 0 }},
		{name: "stock unknown", quote: func(q *ckQuote) { q.Stock, q.StockKnown = 0, false }},
		{name: "yesterday's stock unknown", quote: func(q *ckQuote) { q.Stock = 0 }, hist: func(h *ckHistory) { h.HasStockYesterday = false }},
		{name: "no history", quote: func(q *ckQuote) { q.Stock = 0 }, noHistory: true},

		{name: "TCG Market up 10%", product: ckProduct{Market: 11, MarketWeekAgo: 10}, verdict: "wait", wantReason: "marketrose"},
		{name: "TCG Market up 9%", product: ckProduct{Market: 10.9, MarketWeekAgo: 10}},
		{name: "no TCG Market a week ago", product: ckProduct{Market: 11}},

		{name: "set 4 weeks out", product: ckProduct{SetReleased: daysAgo(28)}, verdict: "sell", wantReason: "newset"},
		{name: "set 55 days out", product: ckProduct{SetReleased: daysAgo(55)}, verdict: "sell", wantReason: "newset"},
		{name: "set 27 days out", product: ckProduct{SetReleased: daysAgo(27)}},
		{name: "set 56 days out", product: ckProduct{SetReleased: daysAgo(56)}},
		{name: "reprinted 60 days ago", product: ckProduct{Reprinted: daysAgo(60)}, verdict: "sell", wantReason: "reprinted"},
		{name: "reprinted today", product: ckProduct{Reprinted: today}, verdict: "sell", wantReason: "reprinted"},
		{name: "reprinted 61 days ago", product: ckProduct{Reprinted: daysAgo(61)}},
		{name: "reprint not out yet", product: ckProduct{Reprinted: today.AddDate(0, 0, 1)}},
		{name: "retail twice TCG Market", product: ckProduct{Market: 7.5}, verdict: "sell", wantReason: "premium"},
		{name: "retail under twice TCG Market", product: ckProduct{Market: 7.51}},

		{name: "wait wins over sell", quote: func(q *ckQuote) { q.Stock = 0 },
			product: ckProduct{SetReleased: daysAgo(30)}, verdict: "wait", wantReason: "soldout"},
	} {
		q, h := quote, hist
		if tc.quote != nil {
			tc.quote(&q)
		}
		if tc.hist != nil {
			tc.hist(&h)
		}
		verdict, reason := ckRuleFor(q, h, !tc.noHistory, tc.product, q.Retail, today)
		if verdict != tc.verdict || reason != tc.wantReason {
			t.Errorf("%s: got %q %q, want %q %q", tc.name, verdict, reason, tc.verdict, tc.wantReason)
		}
		if reason != "" && ckReasons[reason] == "" {
			t.Errorf("%s: %q has no tooltip", tc.name, reason)
		}
	}
}

// testCKTables are odds as ckodds writes them: products 1 (nonfoil), 2
// (foil), 3 (Reserved List nonfoil) and 4 (Reserved List foil); cells for
// the nonfoil $10-20 band, one of them too thin to quote, every band's, and
// the exceptions', whose foils are too thin; and the pauses.
const testCKTables = `{
  "generated": "2026-09-29T08:00:00Z", "from": "2025-12-28", "to": "2026-09-28",
  "cells": [
    {"group": "cohort", "finish": "nonfoil", "bucket": "10-20", "verdict": "typical", "week_more": 36, "week_less": 38, "month_more": 45, "month_less": 46, "printings": 4000},
    {"group": "cohort", "finish": "nonfoil", "bucket": "10-20", "verdict": "wait", "week_more": 60, "week_less": 20, "month_more": 61, "month_less": 30, "printings": 120},
    {"group": "cohort", "finish": "nonfoil", "bucket": "10-20", "verdict": "sell", "week_more": 24, "week_less": 45, "month_more": 34, "month_less": 58, "printings": 900},
    {"group": "cohort", "finish": "nonfoil", "bucket": "all", "verdict": "typical", "week_more": 35, "week_less": 37, "month_more": 44, "month_less": 45, "printings": 12000},
    {"group": "cohort", "finish": "nonfoil", "bucket": "all", "verdict": "wait", "week_more": 52, "week_less": 28, "month_more": 53, "month_less": 41, "printings": 6000},
    {"group": "cohort", "finish": "nonfoil", "bucket": "all", "verdict": "sell", "week_more": 25, "week_less": 44, "month_more": 33, "month_less": 57, "printings": 7000},
    {"group": "cohort", "finish": "nonfoil", "bucket": "all", "verdict": "newhigh", "week_more": 22, "week_less": 44, "month_more": 30, "month_less": 60, "printings": 5000},
    {"group": "cohort", "finish": "foil", "bucket": "all", "verdict": "typical", "week_more": 20, "week_less": 24, "month_more": 39, "month_less": 40, "printings": 18000},
    {"group": "cohort", "finish": "foil", "bucket": "all", "verdict": "wait", "week_more": 34, "week_less": 19, "month_more": 49, "month_less": 36, "printings": 11000},
    {"group": "exceptions", "finish": "nonfoil", "bucket": "all", "verdict": "typical", "week_more": 19, "week_less": 24, "month_more": 30, "month_less": 33, "printings": 500},
    {"group": "exceptions", "finish": "nonfoil", "bucket": "all", "verdict": "wait", "week_more": 36, "week_less": 19, "month_more": 41, "month_less": 29, "printings": 310},
    {"group": "exceptions", "finish": "foil", "bucket": "all", "verdict": "typical", "week_more": 15, "week_less": 20, "month_more": 25, "month_less": 30, "printings": 80},
    {"group": "exceptions", "finish": "foil", "bucket": "all", "verdict": "wait", "week_more": 50, "week_less": 10, "month_more": 55, "month_less": 20, "printings": 20}
  ],
  "pauses": [
    {"finish": "nonfoil", "min_days": 30, "back_month": 50, "back_over_listed": [0.8, 0.9, 0.95, 1, 1, 1, 1, 1.05, 1.1], "days": 1271, "pauses": 1271},
    {"finish": "nonfoil", "min_days": 0, "back_month": 93, "back_over_listed": [0.9, 0.95, 1, 1, 1, 1, 1.05, 1.1, 1.2], "days": 24832, "pauses": 24832},
    {"finish": "nonfoil", "min_days": 3, "back_month": 88, "back_over_listed": [0.9, 0.95, 1, 1, 1, 1, 1.05, 1.1, 1.2], "days": 11089, "pauses": 11089},
    {"finish": "foil", "min_days": 0, "back_month": 92, "back_over_listed": [1, 1, 1, 1, 1, 1, 1, 1, 1], "days": 48157, "pauses": 48157}
  ],
  "products": {
    "1": {},
    "2": {"foil": true},
    "3": {"exception": true},
    "4": {"foil": true, "exception": true, "set_released": "1994-01-01", "reprinted": "2026-09-01", "market": 11, "market_week_ago": 10}
  }
}`

func testCKOdds(t *testing.T) *ckOdds {
	t.Helper()
	var tables ckOddsTables
	err := json.Unmarshal([]byte(testCKTables), &tables)
	if err != nil {
		t.Fatal(err)
	}
	return newCKOdds(tables)
}

// TestCKChancesFor reads a verdict's chances from the card's band where it
// has enough printings, else from its finish over every band; the exceptions
// from their own group, else the finish's.
func TestCKChancesFor(t *testing.T) {
	odds := testCKOdds(t)
	for _, tc := range []struct {
		name                           string
		group, finish, bucket, verdict string
		cell                           ckCellKey
		weekLess, typicalWeekLess      int
	}{
		{"its band", "cohort", "nonfoil", "10-20", "sell", ckCellKey{"cohort", "nonfoil", "10-20", "sell"}, 45, 38},
		{"its band too thin", "cohort", "nonfoil", "10-20", "wait", ckCellKey{"cohort", "nonfoil", "all", "wait"}, 28, 37},
		{"its band not measured", "cohort", "nonfoil", "50-100", "sell", ckCellKey{"cohort", "nonfoil", "all", "sell"}, 44, 37},
		{"unknown retail", "cohort", "nonfoil", "all", "newhigh", ckCellKey{"cohort", "nonfoil", "all", "newhigh"}, 44, 37},
		{"foil", "cohort", "foil", "5-10", "wait", ckCellKey{"cohort", "foil", "all", "wait"}, 19, 24},
		{"foil sell not measured", "cohort", "foil", "5-10", "sell", ckCellKey{}, 0, 0},
		{"exceptions", "exceptions", "nonfoil", "10-20", "wait", ckCellKey{"exceptions", "nonfoil", "all", "wait"}, 19, 24},
		{"exceptions' foils too thin", "exceptions", "foil", "10-20", "wait", ckCellKey{"cohort", "foil", "all", "wait"}, 19, 24},
		{"exceptions sell falls to the finish's", "exceptions", "nonfoil", "10-20", "sell", ckCellKey{"cohort", "nonfoil", "all", "sell"}, 44, 37},
	} {
		cell, chances, typical, found := odds.chancesFor(tc.group, tc.finish, tc.bucket, tc.verdict)
		if cell != tc.cell || found != (tc.cell != ckCellKey{}) || chances.WeekLess != tc.weekLess || typical.WeekLess != tc.typicalWeekLess {
			t.Errorf("%s: got %v %+v against %+v, %v; want %v, week less %d against %d",
				tc.name, cell, chances, typical, found, tc.cell, tc.weekLess, tc.typicalWeekLess)
		}
	}
	var none *ckOdds
	_, _, _, found := none.chancesFor("cohort", "nonfoil", "all", "sell")
	if found {
		t.Error("no odds loaded: found chances")
	}
}

// TestCKChanceLines words a wait's chances as CK paying more and every
// other verdict's as CK paying less or nothing, and names the printings they
// were measured on.
func TestCKChanceLines(t *testing.T) {
	odds := ckChances{WeekMore: 52, WeekLess: 28, MonthMore: 53, MonthLess: 41, Printings: 900}
	typical := ckChances{WeekMore: 36, WeekLess: 38, MonthMore: 45, MonthLess: 46, Printings: 4000}
	for _, tc := range []struct {
		cell ckCellKey
		want string
	}{
		{ckCellKey{"cohort", "nonfoil", "10-20", "wait"},
			"Chances CK pays more\n• in a week: **52%** instead of 36%\n• in a month: **53%** instead of 45%\nMeasured on 900 nonfoils at $10-20"},
		{ckCellKey{"cohort", "foil", "all", "sell"},
			"Chances CK pays less or nothing\n• in a week: **28%** instead of 38%\n• in a month: **41%** instead of 46%\nMeasured on 900 foils"},
		{ckCellKey{"exceptions", "nonfoil", "all", "newhigh"},
			"Chances CK pays less or nothing\n• in a week: **28%** instead of 38%\n• in a month: **41%** instead of 46%\nMeasured on 900 nonfoils, RL or pre-1995"},
	} {
		if got := ckChanceLines(tc.cell, odds, typical); got != tc.want {
			t.Errorf("%v:\n%s\nwant:\n%s", tc.cell, got, tc.want)
		}
	}
}

// TestCKBucketOf bands CK's retail as ckodds does.
func TestCKBucketOf(t *testing.T) {
	for retail, want := range map[float64]string{
		5.99: "5-10", 9.99: "5-10", 10: "10-20", 19.99: "10-20", 20: "20-50", 49.99: "20-50",
		50: "50-100", 99.99: "50-100", 100: "100-200", 199.99: "100-200", 200: "200+", 1999.99: "200+",
	} {
		if got := ckBucketOf(retail); got != want {
			t.Errorf("ckBucketOf(%v) = %q, want %q", retail, got, want)
		}
	}
}

// TestLoadCKOdds reads the odds from a file, as from the bucket.
func TestLoadCKOdds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ck-odds.json")
	err := os.WriteFile(path, []byte(testCKTables), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	odds, err := loadCKOdds(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if odds.From != "2025-12-28" || odds.To != "2026-09-28" || !odds.Generated.Equal(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("loaded %s to %s, generated %v", odds.From, odds.To, odds.Generated)
	}
	want := ckProduct{
		Foil: true, Exception: true, Market: 11, MarketWeekAgo: 10,
		SetReleased: time.Date(1994, 1, 1, 0, 0, 0, 0, time.UTC),
		Reprinted:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	got, found := odds.product("4")
	if !found || got != want {
		t.Errorf("product 4: got %+v, %v, want %+v", got, found, want)
	}
	if got, found := odds.product("1"); !found || got != (ckProduct{}) {
		t.Errorf("product 1: got %+v, %v, want a nonfoil with nothing known", got, found)
	}
	if _, found := odds.product("999"); found {
		t.Error("product 999: found")
	}
	if _, chances, _, found := odds.chancesFor("cohort", "nonfoil", "10-20", "sell"); !found || chances != (ckChances{24, 45, 34, 58, 900}) {
		t.Errorf("nonfoil $10-20 sell: got %+v, %v", chances, found)
	}
}

// TestCKReopenFor reads the pause cell of the finish for the pause's age,
// the longest pauses past the last age measured.
func TestCKReopenFor(t *testing.T) {
	odds := testCKOdds(t)
	for _, tc := range []struct {
		finish      string
		days, cell  int
		wantNothing bool
	}{
		{"nonfoil", 0, 0, false},
		{"nonfoil", 2, 0, false},
		{"nonfoil", 3, 3, false},
		{"nonfoil", 29, 3, false},
		{"nonfoil", 45, 30, false},
		{"foil", 45, 0, false},
		{"etched", 0, 0, true},
	} {
		got := odds.reopenFor(tc.finish, tc.days)
		if (got == nil) != tc.wantNothing || (got != nil && got.MinDays != tc.cell) {
			t.Errorf("%s paused %d days: got %+v, want the %d-day cell", tc.finish, tc.days, got, tc.cell)
		}
	}
	var none *ckOdds
	if none.reopenFor("nonfoil", 3) != nil {
		t.Error("no odds loaded: got a pause cell")
	}
}

// TestCKViewFor puts a buying card's rule, the chances of its cell and its
// facts together.
func TestCKViewFor(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	odds := testCKOdds(t)
	odds.products["5"] = ckProduct{Market: 7}
	odds.products["6"] = ckProduct{SetReleased: today.AddDate(0, 0, -30)}
	odds.products["8"] = ckProduct{Foil: true, SetReleased: today.AddDate(0, 0, -30)}
	quote := ckQuote{ID: "1", Buy: 7, Buying: true, Stock: 2, StockKnown: true, Retail: 14}
	hist := ckHistory{StockYesterday: 5, HasStockYesterday: true, RetailYesterday: 15}

	got := ckViewFor(quote, hist, true, odds, false, today)
	want := ckView{
		State: "wait",
		Tip: ckReasons["halved"] + "\n" +
			ckChanceLines(ckCellKey{"cohort", "nonfoil", "all", "wait"}, ckChances{52, 28, 53, 41, 6000}, ckChances{35, 37, 44, 45, 12000}),
		Facts: "**CK stock**: 2",
	}
	if got != want {
		t.Errorf("stock halved, band too thin:\ngot  %+v\nwant %+v", got, want)
	}

	// Out of stock, CK's retail is yesterday's: twice TCG Market, in the
	// $10-20 band.
	q := quote
	q.ID, q.Stock, q.Retail = "5", 0, 0
	h := hist
	h.StockYesterday = 0
	got = ckViewFor(q, h, true, odds, false, today)
	if got.State != "sell" ||
		got.Tip != ckReasons["premium"]+"\n"+ckChanceLines(ckCellKey{"cohort", "nonfoil", "10-20", "sell"}, ckChances{24, 45, 34, 58, 900}, ckChances{36, 38, 45, 46, 4000}) ||
		got.Facts != "**CK stock**: 0 - out 30+ days\n**CK retail**: 2.1x TCG Market" {
		t.Errorf("out of stock at twice TCG Market: got %+v", got)
	}

	// A new high on a card of a new set: sell for the set, with New high's
	// own chances on its pill.
	q = quote
	q.ID, q.Stock = "6", 5
	got = ckViewFor(q, hist, true, odds, true, today)
	if got.State != "sell" || !strings.HasPrefix(got.Tip, ckReasons["newset"]+"\n") ||
		got.NewHighTip != ckNewHighVerdict+"\n"+ckChanceLines(ckCellKey{"cohort", "nonfoil", "all", "newhigh"}, ckChances{22, 44, 30, 60, 5000}, ckChances{35, 37, 44, 45, 12000}) {
		t.Errorf("new high on a new set: got %+v", got)
	}

	// A new high alone is no sell; its pill carries its own chances.
	q = quote
	q.Stock = 5
	got = ckViewFor(q, hist, true, odds, true, today)
	if got.State != "" || got.Tip != "" || got.NewHighTip != ckNewHighVerdict+"\n"+ckChanceLines(ckCellKey{"cohort", "nonfoil", "all", "newhigh"}, ckChances{22, 44, 30, 60, 5000}, ckChances{35, 37, 44, 45, 12000}) {
		t.Errorf("a new high alone: got %+v, want no state and the pill's chances", got)
	}

	// A verdict whose cell the odds do not list, and a product they do not
	// know, show their facts only.
	q = quote
	q.ID = "2"
	got = ckViewFor(q, hist, true, odds, true, today)
	if got.State != "wait" {
		t.Errorf("a foil halved: got %+v, want a wait", got)
	}
	q.ID, q.Stock = "8", 5
	got = ckViewFor(q, hist, true, odds, true, today)
	if got.State != "" || got.Tip != "" || got.NewHighTip != ckNewHighVerdict {
		t.Errorf("a foil of a new set, sell not measured: got %+v, want no state and New high without chances", got)
	}
	q.ID, q.Stock = "999", 2
	got = ckViewFor(q, hist, true, odds, true, today)
	if got != (ckView{Facts: "**CK stock**: 2", NewHighTip: ckNewHighVerdict}) {
		t.Errorf("a product the odds do not know: got %+v", got)
	}
	got = ckViewFor(quote, hist, true, nil, false, today)
	if got != (ckView{Facts: "**CK stock**: 2"}) {
		t.Errorf("no odds loaded: got %+v", got)
	}
}

// TestCKFacts pins the facts line.
func TestCKFacts(t *testing.T) {
	today := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	out := ckQuote{Stock: 0, StockKnown: true, Buy: 5}
	in := ckQuote{Stock: 3, StockKnown: true, Buy: 5}
	for _, tc := range []struct {
		name      string
		quote     ckQuote
		hist      ckHistory
		noHistory bool
		product   ckProduct
		retail    float64
		want      string
	}{
		{"out for days", out, ckHistory{LastInStock: today.AddDate(0, 0, -9)}, false, ckProduct{}, 0, "**CK stock**: 0 - out 9 days"},
		{"out since yesterday", out, ckHistory{LastInStock: today.AddDate(0, 0, -1)}, false, ckProduct{}, 0, "**CK stock**: 0 - out 1 day"},
		{"out all month", out, ckHistory{}, false, ckProduct{}, 0, "**CK stock**: 0 - out 30+ days"},
		{"in stock, a week ago", in, ckHistory{StockWeekAgo: 12, HasStockWeekAgo: true}, false, ckProduct{}, 0,
			"**CK stock**: 3 - it was 12 a week ago"},
		{"no history", out, ckHistory{}, true, ckProduct{}, 0, "**CK stock**: 0"},
		{"TCG Market up", in, ckHistory{}, true, ckProduct{Market: 11.2, MarketWeekAgo: 10}, 0,
			"**CK stock**: 3\n**TCG Market**: +12% this week"},
		{"TCG Market down", in, ckHistory{}, true, ckProduct{Market: 9, MarketWeekAgo: 10}, 0,
			"**CK stock**: 3\n**TCG Market**: -10% this week"},
		{"TCG Market flat", in, ckHistory{}, true, ckProduct{Market: 10.04, MarketWeekAgo: 10}, 0,
			"**CK stock**: 3\n**TCG Market**: flat this week"},
		{"retail against TCG Market", in, ckHistory{}, true, ckProduct{Market: 10}, 14, "**CK stock**: 3\n**CK retail**: 1.4x TCG Market"},
		{"stock unknown", ckQuote{Buy: 5}, ckHistory{}, true, ckProduct{Market: 10, MarketWeekAgo: 10}, 20,
			"**TCG Market**: flat this week\n**CK retail**: 2.0x TCG Market"},
		{"nothing known", ckQuote{Buy: 5}, ckHistory{}, true, ckProduct{}, 20, ""},
	} {
		got := ckFacts(tc.quote, tc.hist, !tc.noHistory, tc.product, tc.retail, today)
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
		StockYesterday: 4, HasStockYesterday: true, StockWeekAgo: 6, HasStockWeekAgo: true, RetailYesterday: 15,
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
	if !found || h.HasStockYesterday || h.StockYesterday != 0 || !h.HasStockWeekAgo {
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

	prevDB, prevGame, prevSkip, prevHistory := NewNewspaperDB, Config().Game, SkipNewspaper, ckHistoryPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB, Config().Game, SkipNewspaper = prevDB, prevGame, prevSkip
		ckHistoryPtr.Store(prevHistory)
	})
	NewNewspaperDB, Config().Game, SkipNewspaper = db, DefaultGame, false

	last := &ckHistorySnapshot{Products: map[string]ckHistory{"1": {}}}
	ckHistoryPtr.Store(last)
	testSite.loadCKHistory()
	if ckHistoryPtr.Load() != last {
		t.Error("a failed load replaced the history")
	}
}

// setTestCK files CK's buylist and, when inv is not nil, its inventory, in
// place of whatever is loaded, restoring it when the test ends.
func setTestCK(t *testing.T, bl mtgban.BuylistRecord, inv mtgban.InventoryRecord) {
	t.Helper()
	prevSellers, prevVendors, prevSignals := sellersPtr.Load(), vendorsPtr.Load(), ckSignalsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		ckSignalsPtr.Store(prevSignals)
	})
	now := time.Now()
	info := mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK", BuylistTimestamp: &now, InventoryTimestamp: &now}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(bl, info)}
	vendorsPtr.Store(&vendors)
	sellers := []mtgban.Seller{}
	if inv != nil {
		sellers = append(sellers, mtgban.NewSellerFromInventory(inv, info))
	}
	sellersPtr.Store(&sellers)
}

// TestCKQuoteFrom reads CK's offer the way its scraper files it: an entry per
// grade, and for a card CK is not buying an entry with no quantity.
func TestCKQuoteFrom(t *testing.T) {
	offers := []mtgban.BuylistEntry{
		{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "111"},
		{Conditions: "SP", BuyPrice: 8, Quantity: 4, OriginalID: "111"},
	}
	stock := []mtgban.InventoryEntry{{Conditions: "NM", Quantity: 3, Price: 20}, {Conditions: "SP", Quantity: 2, Price: 16}}
	// A card CK has none of: a link and no price, which the record files as
	// one NM copy.
	placeholder := []mtgban.InventoryEntry{{Conditions: "NM", Quantity: 1, URL: "https://www.cardkingdom.com/mtg/x"}}
	for _, tc := range []struct {
		name       string
		offers     []mtgban.BuylistEntry
		stock      []mtgban.InventoryEntry
		stockKnown bool
		want       ckQuote
	}{
		{"buying, stock across grades", offers, stock, true, ckQuote{ID: "111", Buy: 10, Buying: true, Stock: 5, StockKnown: true, Retail: 20}},
		{"only SP in stock", offers, stock[1:], true, ckQuote{ID: "111", Buy: 10, Buying: true, Stock: 2, StockKnown: true}},
		{"not buying", []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: 6.4}}, nil, true, ckQuote{Buy: 6.4, StockKnown: true}},
		{"out of stock", offers, nil, true, ckQuote{ID: "111", Buy: 10, Buying: true, StockKnown: true}},
		{"out of stock, as CK's dump has it", offers, placeholder, true, ckQuote{ID: "111", Buy: 10, Buying: true, StockKnown: true}},
		// No CK inventory loaded: stock is unknown, not zero.
		{"no inventory", offers, nil, false, ckQuote{ID: "111", Buy: 10, Buying: true}},
	} {
		got := ckQuoteFrom(tc.offers, tc.stock, tc.stockKnown)
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// setTestCKInputs files the new highs and the history the signals read,
// restoring them when the test ends.
func setTestCKInputs(t *testing.T, newHighs mtgban.InventoryRecord, history *ckHistorySnapshot) {
	t.Helper()
	prevInfos, prevHistory := infosPtr.Load(), ckHistoryPtr.Load()
	t.Cleanup(func() {
		infosPtr.Store(prevInfos)
		ckHistoryPtr.Store(prevHistory)
	})
	infos := map[string]mtgban.InventoryRecord{"newhigh": newHighs}
	infosPtr.Store(&infos)
	ckHistoryPtr.Store(history)
}

// TestRebuildCKSignals puts the live offer, the history, the odds and the new
// highs together for every card CK is buying at $3 or more, and pages read
// the result until the next rebuild.
func TestRebuildCKSignals(t *testing.T) {
	today := ckToday(time.Now())
	odds := testCKOdds(t)
	odds.products["6"] = ckProduct{SetReleased: today.AddDate(0, 0, -30)}
	odds.products["7"] = ckProduct{}
	setTestCKOdds(t, odds)
	setTestCK(t,
		mtgban.BuylistRecord{
			"a":     {{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "1"}},
			"new":   {{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "6"}},
			"cheap": {{Conditions: "NM", BuyPrice: 2.5, Quantity: 4, OriginalID: "6"}},
			"off":   {{Conditions: "NM", BuyPrice: 10, OriginalID: "6"}},
			"plain": {{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "7"}},
		},
		mtgban.InventoryRecord{
			"a":   {{Conditions: "NM", Quantity: 1, Price: 15}},
			"new": {{Conditions: "NM", Quantity: 1, Price: 15}},
		})
	products := map[string]ckHistory{"1": {StockYesterday: 6, HasStockYesterday: true}}
	setTestCKInputs(t, mtgban.InventoryRecord{"plain": {{Price: 9}}},
		&ckHistorySnapshot{Today: today, Yesterday: today.AddDate(0, 0, -1), Products: products})

	rebuildCKSignals()
	// plain is at a new high only, which is no sell.
	for cardID, want := range map[string]string{"a": "wait", "new": "sell", "plain": "", "cheap": "", "off": ""} {
		got := ckSignalForCard(ckTestCard(cardID))
		if got.State != want {
			t.Errorf("%s: got %+v, want %q", cardID, got, want)
		}
	}
	if got := ckSignalForCard(ckTestCard("a")); !strings.HasPrefix(got.Tip, ckReasons["halved"]+"\n") {
		t.Errorf("stock 6 to 1: got %+v, want the halving's tip", got)
	}
	if got := ckNewHighTipFor(ckTestCard("plain")); got == ckNewHighVerdict {
		t.Errorf("New high: got %q, want its chances", got)
	}
	for _, cardID := range []string{"cheap", "off"} {
		if _, stored := (*ckSignalsPtr.Load())[cardID]; stored {
			t.Errorf("%s: got a view", cardID)
		}
	}

	// Inputs change nothing until the next rebuild.
	ckHistoryPtr.Store(nil)
	if got := ckSignalForCard(ckTestCard("a")); got.State != "wait" {
		t.Errorf("before the rebuild: got %+v, want the wait still", got)
	}
	rebuildCKSignals()
	if got := ckSignalForCard(ckTestCard("a")); got.State != "" {
		t.Errorf("no history: got %+v, want no state", got)
	}

	// Loaded the day before, the history cannot see a halving.
	ckHistoryPtr.Store(&ckHistorySnapshot{Today: today.AddDate(0, 0, -1), Yesterday: today.AddDate(0, 0, -2), Products: products})
	rebuildCKSignals()
	if got := ckSignalForCard(ckTestCard("a")); got.State != "" {
		t.Errorf("history from the day before: got %+v, want no state", got)
	}

	// Without odds nothing is colored; the facts still show.
	ckOddsPtr.Store(nil)
	rebuildCKSignals()
	if got := ckSignalForCard(ckTestCard("new")); got.State != "" || got.Facts != "**CK stock**: 1" {
		t.Errorf("no odds: got %+v, want the facts only", got)
	}
}

// TestCKPauseFor pins how long a pause has lasted, the chances it quotes, and
// when waiting for CK beats the other cash offers.
func TestCKPauseFor(t *testing.T) {
	today := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		lastBuying time.Time
		days       int
		paused     bool
	}{
		{today.AddDate(0, 0, -1), 0, true},
		{today.AddDate(0, 0, -2), 1, true},
		{today.AddDate(0, 0, -45), 44, true},
		{time.Time{}, 0, false},
	} {
		days, paused := ckPauseDays(ckHistory{LastBuying: tc.lastBuying}, today)
		if days != tc.days || paused != tc.paused {
			t.Errorf("last bought %v: got %d, %v, want %d, %v", tc.lastBuying, days, paused, tc.days, tc.paused)
		}
	}

	reopen := &ckReopen{MinDays: 7, BackMonth: 80, Deciles: []float64{0.9, 0.95, 1, 1, 1, 1, 1.05, 1.1, 1.2}}
	for _, tc := range []struct {
		name   string
		others []float64
		reopen *ckReopen
		want   ckPause
	}{
		// 7 of 9 deciles come back above 9.5: 80% × 70%.
		{"others 5% below", []float64{8, 9.5}, reopen, ckPause{Paused: true, Days: 9, Back: 80, Beat: 56, Wait: true}},
		{"an offer just under", []float64{9.99}, reopen, ckPause{Paused: true, Days: 9, Back: 80, Beat: 56, Wait: true}},
		{"an offer at CK's price", []float64{10}, reopen, ckPause{Paused: true, Days: 9, Back: 80, Beat: 24}},
		{"no other offer", nil, reopen, ckPause{Paused: true, Days: 9, Back: 80, Beat: -1}},
		{"no chances", []float64{8}, nil, ckPause{Paused: true, Days: 9, Back: -1, Beat: -1}},
		{"half is not more than half", []float64{5},
			&ckReopen{BackMonth: 55, Deciles: slices.Repeat([]float64{1}, 9)}, ckPause{Paused: true, Days: 9, Back: 55, Beat: 50}},
	} {
		got := ckPauseFor(10, 9, tc.others, tc.reopen)
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}

	for days, want := range map[int]string{0: "Paused today", 1: "Paused 1d", 29: "Paused 29d", 30: "Paused 30d+", 45: "Paused 30d+"} {
		if got := ckPauseLabel(days); got != want {
			t.Errorf("paused %d days: got %q, want %q", days, got, want)
		}
	}

	for _, tc := range []struct {
		pause ckPause
		want  string
	}{
		{ckPause{Paused: true, Days: 9, Back: 80, Beat: 56, Wait: true},
			"**Wait**: CK stopped buying this card 9 days ago.\nChances CK buys it again in a month: **80%**\nand pays more than any other offer: **56%**"},
		{ckPause{Paused: true, Days: 1, Back: 93, Beat: -1},
			"**Paused**: CK stopped buying this card yesterday.\nChances CK buys it again in a month: **93%**"},
		{ckPause{Paused: true, Days: 0, Back: -1, Beat: -1}, "**Paused**: CK stopped buying this card today."},
		{ckPause{Paused: true, Days: 44, Back: 50, Beat: 0},
			"**Paused**: CK stopped buying this card 30+ days ago.\nChances CK buys it again in a month: **50%**\nand pays more than any other offer: **0%**"},
	} {
		if got := ckPauseTip(tc.pause); got != tc.want {
			t.Errorf("%+v:\n%s\nwant:\n%s", tc.pause, got, tc.want)
		}
	}
}

// TestRebuildCKPauses gives the cards on CK's last known buylist at $3 or
// more their pause, against the other stores' cash offers only.
func TestRebuildCKPauses(t *testing.T) {
	odds := testCKOdds(t)
	for _, id := range []string{"333", "334", "444", "555", "666"} {
		odds.products[id] = ckProduct{}
	}
	setTestCKOdds(t, odds)
	prevVendors, prevSignals := vendorsPtr.Load(), ckSignalsPtr.Load()
	t.Cleanup(func() {
		vendorsPtr.Store(prevVendors)
		ckSignalsPtr.Store(prevSignals)
	})
	vendor := func(shorthand string, bl mtgban.BuylistRecord) mtgban.Vendor {
		return mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Name: shorthand, Shorthand: shorthand})
	}
	vendors := []mtgban.Vendor{
		vendor("CK", mtgban.BuylistRecord{"both": {{Conditions: "NM", BuyPrice: 10, Quantity: 2, OriginalID: "111"}}}),
		vendor("CKBLLast", mtgban.BuylistRecord{
			"p":       {{Conditions: "NM", BuyPrice: 10, OriginalID: "333"}},
			"both":    {{Conditions: "NM", BuyPrice: 10, OriginalID: "334"}},
			"nohist":  {{Conditions: "NM", BuyPrice: 10, OriginalID: "444"}},
			"noid":    {{Conditions: "NM", BuyPrice: 10}},
			"blocked": {{Conditions: "NM", BuyPrice: 10, OriginalID: "555"}},
			"cheap":   {{Conditions: "NM", BuyPrice: 2.9, OriginalID: "666"}},
			"unknown": {{Conditions: "NM", BuyPrice: 10, OriginalID: "777"}},
		}),
		vendor("SCG", mtgban.BuylistRecord{
			"p":       {{Conditions: "NM", BuyPrice: 8}},
			"blocked": {{Conditions: "NM", BuyPrice: 10}},
		}),
		// A credit list pays more, but not in cash.
		vendor("ABUCredit", mtgban.BuylistRecord{"p": {{Conditions: "NM", BuyPrice: 12}}}),
	}
	vendorsPtr.Store(&vendors)
	today := ckToday(time.Now())
	paused := ckHistory{LastBuying: today.AddDate(0, 0, -5)}
	setTestCKInputs(t, mtgban.InventoryRecord{}, &ckHistorySnapshot{
		Today: today, Yesterday: today.AddDate(0, 0, -1),
		Products: map[string]ckHistory{"333": paused, "334": paused, "555": paused, "666": paused, "777": paused},
	})

	rebuildCKSignals()
	// Paused 4 days: back within a month 88%, and every decile above SCG's 8.
	got := ckSignalForCard(ckTestCard("p"))
	if got.PauseLabel != "Paused 4d" || !got.PauseWait || got.State != "" ||
		got.PauseTip != ckPauseTip(ckPause{Paused: true, Days: 4, Back: 88, Beat: 79, Wait: true}) {
		t.Errorf("paused 4 days, SCG 20%% below: got %+v, want a wait", got)
	}
	got = ckSignalForCard(ckTestCard("blocked"))
	if got.PauseLabel != "Paused 4d" || got.PauseWait {
		t.Errorf("SCG at CK's price: got %+v, want paused with no wait", got)
	}
	got = ckSignalForCard(ckTestCard("unknown"))
	if got.PauseLabel != "Paused 4d" || got.PauseWait || got.PauseTip != "**Paused**: CK stopped buying this card 4 days ago." {
		t.Errorf("a product the odds do not know: got %+v, want paused with no chances", got)
	}
	for _, cardID := range []string{"both", "nohist", "noid", "cheap"} {
		got = ckSignalForCard(ckTestCard(cardID))
		if got.PauseLabel != "" {
			t.Errorf("%s: got %+v, want no pause", cardID, got)
		}
	}
}

// TestLoadScraperRebuildsCKSignals installs CK the way startup and the reload
// endpoint do, and checks each install refreshes the signals.
func TestLoadScraperRebuildsCKSignals(t *testing.T) {
	withLocalDumpsBucket(t, "magic")
	prevSignals := ckSignalsPtr.Load()
	t.Cleanup(func() { ckSignalsPtr.Store(prevSignals) })
	today := ckToday(time.Now())
	odds := testCKOdds(t)
	odds.products["111"] = ckProduct{SetReleased: today.AddDate(0, 0, -30)}
	setTestCKOdds(t, odds)
	setTestCKInputs(t, nil, &ckHistorySnapshot{
		Today: today, Yesterday: today.AddDate(0, 0, -1),
		Products: map[string]ckHistory{"111": {StockYesterday: 2, HasStockYesterday: true, LastInStock: today.AddDate(0, 0, -1)}},
	})

	dump := func(stock int, ts time.Time) {
		info := mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK", BuylistTimestamp: &ts, InventoryTimestamp: &ts}
		writeVendorDump(t, filepath.Join("magic", "cardkingdom", "buylist", "CK.json.xz"), mtgban.NewVendorFromBuylist(
			mtgban.BuylistRecord{"a": {{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "111"}}}, info))
		writeSellerDump(t, filepath.Join("magic", "cardkingdom", "retail", "CK.json.xz"), mtgban.NewSellerFromInventory(
			mtgban.InventoryRecord{"a": {{Conditions: "NM", Quantity: stock, Price: 20}}}, info))
	}
	load := func(kind string) {
		err := loadScraper(DataBucket, "magic", "cardkingdom", kind, "CK")
		if err != nil {
			t.Fatalf("load %s: %v", kind, err)
		}
	}

	now := time.Now()
	dump(2, now)
	load("retail")
	load("buylist")
	got := ckSignalForCard(ckTestCard("a"))
	if got.State != "sell" || got.Facts != "**CK stock**: 2" {
		t.Errorf("after the buylist load: got %+v, want sell for the new set", got)
	}

	dump(0, now.Add(time.Minute))
	load("retail")
	got = ckSignalForCard(ckTestCard("a"))
	if got.State != "wait" || got.Facts != "**CK stock**: 0 - out 1 day" {
		t.Errorf("after the retail reload: got %+v, want a wait on the sellout", got)
	}
}

// TestCardFilterOnCK checks on:cksell keeps the sell-now cards and on:ckwait
// the wait ones.
func TestCardFilterOnCK(t *testing.T) {
	setTestCK(t,
		mtgban.BuylistRecord{
			"sell":    {{Conditions: "NM", BuyPrice: 10, Quantity: 4, OriginalID: "9"}},
			"wait":    {{Conditions: "NM", BuyPrice: 9, Quantity: 4, OriginalID: "2"}},
			"neutral": {{Conditions: "NM", BuyPrice: 9, Quantity: 4, OriginalID: "3"}},
		},
		mtgban.InventoryRecord{
			"sell":    {{Conditions: "NM", Quantity: 5, Price: 20}},
			"neutral": {{Conditions: "NM", Quantity: 5, Price: 20}},
		})
	today := ckToday(time.Now())
	odds := testCKOdds(t)
	odds.products["9"] = ckProduct{SetReleased: today.AddDate(0, 0, -30)}
	setTestCKOdds(t, odds)
	// neutral is at a new high, which is no sell.
	setTestCKInputs(t, mtgban.InventoryRecord{"neutral": {{Price: 9}}}, &ckHistorySnapshot{
		Today: today, Yesterday: today.AddDate(0, 0, -1),
		Products: map[string]ckHistory{"2": {StockYesterday: 3, HasStockYesterday: true}},
	})
	rebuildCKSignals()

	for _, tc := range []struct {
		card         string
		cksell, wait bool
	}{
		{"sell", true, false},
		{"wait", false, true},
		{"neutral", false, false},
	} {
		co := ckTestCard(tc.card)
		// cardFilterOn reports whether to skip the card.
		if cardFilterOn([]string{"cksell"}, co) == tc.cksell {
			t.Errorf("on:cksell %s: kept %v, want %v", tc.card, !tc.cksell, tc.cksell)
		}
		if cardFilterOn([]string{"ckwait"}, co) == tc.wait {
			t.Errorf("on:ckwait %s: kept %v, want %v", tc.card, !tc.wait, tc.wait)
		}
	}
}

// TestCKWorkNeedsCKBuylist builds no CK signals on a site that does not
// serve CK's buylist, whatever its game.
func TestCKWorkNeedsCKBuylist(t *testing.T) {
	prevVendors, prevSignals := vendorsPtr.Load(), ckSignalsPtr.Load()
	t.Cleanup(func() {
		vendorsPtr.Store(prevVendors)
		ckSignalsPtr.Store(prevSignals)
	})
	vendors := []mtgban.Vendor{buylistOf("SCG", 1, time.Now())}
	vendorsPtr.Store(&vendors)
	ckSignalsPtr.Store(nil)

	(&site{}).refreshCKSignals()
	rebuildCKSignals()
	if ckSignalsPtr.Load() != nil {
		t.Error("built CK signals without a CK buylist")
	}
}
