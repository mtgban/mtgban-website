package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestCKHistoryLive runs the history loader against the newspaper's real
// cardkingdomproductmodel and checks a sample of products against their raw
// rows, which is the only way to see the aggregate and the table agree.
// Read-only, and skipped unless pointed at a config with a
// new_newspaper_sql_config:
//
//	CKLIVE_CONFIG=config.json go test -run TestCKHistoryLive -v
func TestCKHistoryLive(t *testing.T) {
	path := os.Getenv("CKLIVE_CONFIG")
	if path == "" {
		t.Skip("CKLIVE_CONFIG not set; skipping the live CK history test")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg struct {
		SQLConfig *timeseries.SQLConfig `json:"new_newspaper_sql_config"`
	}
	err = json.Unmarshal(blob, &cfg)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg.SQLConfig == nil {
		t.Fatalf("%s has no new_newspaper_sql_config", path)
	}
	db, err := cfg.SQLConfig.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// One connection, so the read-only setting covers every query below.
	db.SetMaxOpenConns(1)
	_, err = db.Exec("SET default_transaction_read_only = on")
	if err != nil {
		t.Fatal(err)
	}

	prevDB, prevGame, prevSkip, prevHistory := NewNewspaperDB, Config.Game, SkipNewspaper, ckHistoryPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB, Config.Game, SkipNewspaper = prevDB, prevGame, prevSkip
		ckHistoryPtr.Store(prevHistory)
	})
	NewNewspaperDB, Config.Game, SkipNewspaper = db, DefaultGame, false
	ckHistoryPtr.Store(nil)

	start := time.Now()
	testSite.loadCKHistory()
	snap := ckHistoryPtr.Load()
	if snap == nil {
		t.Fatal("no history loaded")
	}
	t.Logf("loaded in %v, against the loader's 5-minute timeout", time.Since(start).Round(time.Second))
	today := ckToday(time.Now())
	if !snap.Today.Equal(today) || !snap.Yesterday.Before(today) || today.Sub(snap.Yesterday) > ckHistoryMaxAge*24*time.Hour {
		t.Fatalf("loaded for %v with yesterday %v", snap.Today, snap.Yesterday)
	}
	t.Logf("%d products, yesterday %s", len(snap.Products), snap.Yesterday.Format(time.DateOnly))

	ctx := context.Background()
	weekAgo, err := ckSnapshotOnOrBefore(ctx, today.AddDate(0, 0, -7))
	if err != nil {
		t.Fatal(err)
	}
	weekAgoUsed := !weekAgo.IsZero() && today.Sub(weekAgo) <= (7+ckHistoryMaxAge-1)*24*time.Hour

	// Every thousandth product, plus the ones with each field set.
	ids := make([]string, 0, len(snap.Products))
	for id := range snap.Products {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var sample []string
	for i := 0; i < len(ids); i += 1000 {
		sample = append(sample, ids[i])
	}
	for _, id := range ids {
		h := snap.Products[id]
		if h.StockYesterday > 0 && h.StockWeekAgo > 0 && h.BuyWeekAgo > 0 && !h.LastInStock.IsZero() {
			sample = append(sample, id)
			break
		}
	}
	// And one CK stopped buying within the window.
	for _, id := range ids {
		h := snap.Products[id]
		if !h.LastBuying.IsZero() && h.LastBuying.Before(snap.Yesterday) {
			sample = append(sample, id)
			break
		}
	}

	// The sample's raw rows over the window, reduced here rather than in SQL.
	sampleIDs := make([]int64, len(sample))
	for i, id := range sample {
		sampleIDs[i], err = strconv.ParseInt(id, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.QueryContext(ctx, `
		SELECT ck_id, date, quantity_selling, price_buy, quantity_buying
		  FROM cardkingdomproductmodel
		 WHERE ck_id = ANY($1) AND date >= $2 AND date <= $3`,
		pq.Array(sampleIDs), today.AddDate(0, 0, -ckHistoryWindow), snap.Yesterday)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]ckHistory{}
	for rows.Next() {
		var id int64
		var date time.Time
		var stock, buying sql.NullInt64
		var buy sql.NullFloat64
		err := rows.Scan(&id, &date, &stock, &buy, &buying)
		if err != nil {
			t.Fatal(err)
		}
		key := strconv.FormatInt(id, 10)
		h := want[key]
		if date.Equal(snap.Yesterday) && stock.Valid {
			h.StockYesterday, h.HasStockYesterday = max(h.StockYesterday, int(stock.Int64)), true
		}
		if weekAgoUsed && date.Equal(weekAgo) && stock.Valid {
			h.StockWeekAgo, h.HasStockWeekAgo = max(h.StockWeekAgo, int(stock.Int64)), true
		}
		if weekAgoUsed && date.Equal(weekAgo) && buy.Valid {
			h.BuyWeekAgo, h.HasBuyWeekAgo = max(h.BuyWeekAgo, buy.Float64), true
		}
		if stock.Int64 > 0 && date.After(h.LastInStock) {
			h.LastInStock = date
		}
		if buying.Int64 > 0 && date.After(h.LastBuying) {
			h.LastBuying = date
		}
		want[key] = h
	}
	err = rows.Err()
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range sample {
		got, expected := snap.Products[id], want[id]
		if !got.LastInStock.Equal(expected.LastInStock) {
			t.Errorf("ck_id %s: last in stock %v, raw rows say %v", id, got.LastInStock, expected.LastInStock)
		}
		if !got.LastBuying.Equal(expected.LastBuying) {
			t.Errorf("ck_id %s: last bought %v, raw rows say %v", id, got.LastBuying, expected.LastBuying)
		}
		got.LastInStock, expected.LastInStock = time.Time{}, time.Time{}
		got.LastBuying, expected.LastBuying = time.Time{}, time.Time{}
		if got != expected {
			t.Errorf("ck_id %s: loaded %+v, raw rows say %+v", id, got, expected)
		}
	}
	t.Logf("checked %d products against their rows", len(sample))
}

// TestCKOddsFileLive loads a file go-mtgban's ckodds wrote and checks every
// category it names gets every rule's tooltip with chances in it. Skipped
// unless pointed at one:
//
//	CKODDS_FILE=ck-odds.json.xz go test -run TestCKOddsFileLive -v
func TestCKOddsFileLive(t *testing.T) {
	path := os.Getenv("CKODDS_FILE")
	if path == "" {
		t.Skip("CKODDS_FILE not set; skipping the live CK odds test")
	}
	odds, err := loadCKOdds(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("measured %s to %s, %d products", odds.From, odds.To, len(odds.categories))
	for id, category := range odds.categories {
		for rule := range ckVerdicts {
			for _, finish := range []string{"foil", "nonfoil"} {
				tip := odds.tip(id, finish, rule)
				if !strings.Contains(tip, "Chances CK pays") {
					t.Fatalf("%s (%s) %s %s: no chances in %q", id, category, finish, rule, tip)
				}
			}
		}
		if !strings.Contains(odds.pauseTip(id, 10, false), "Chances CK buys it again") {
			t.Fatalf("%s (%s): no pause chances", id, category)
		}
	}
	t.Logf("a Masters sell now: %q", odds.tipFor("masters", "nonfoil", "sell"))
	var off []string
	for key, isOff := range odds.off {
		if isOff {
			off = append(off, fmt.Sprintf("%s/%s/%s", key.Category, key.Finish, key.Rule))
		}
	}
	slices.Sort(off)
	t.Logf("rules off: %v", off)
}
