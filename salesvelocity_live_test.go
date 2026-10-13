package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestSalesVelocityLive times the sales velocity load on the newspaper and
// prints the tables docs/search-sales-velocity.md quotes. Read-only, and
// skipped unless asked for:
//
//	NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=config.json go test -run TestSalesVelocityLive -v
func TestSalesVelocityLive(t *testing.T) {
	if os.Getenv("NEWSPAPER_LIVE") != "1" {
		t.Skip("NEWSPAPER_LIVE not set; skipping the live sales velocity test")
	}
	skipWithoutDatastore(t)
	path := cmp.Or(os.Getenv("NEWSPAPER_LIVE_CONFIG"), "config.json")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	game := gameMap[Config().Game]

	start := time.Now()
	var day time.Time
	err = db.QueryRowContext(ctx, salesVelocityDayQuery).Scan(&day)
	if err != nil {
		t.Fatal(err)
	}
	dayTook := time.Since(start)
	t.Logf("the window ends on %s", day.Format(time.DateOnly))

	// Timed apart, not through readSales (which wraps both in one
	// transaction), so the window and last-sale queries get their own row.
	start = time.Now()
	rows, err := readSalesRows(ctx, db, game, day)
	if err != nil {
		t.Fatal(err)
	}
	rowsTook := time.Since(start)

	start = time.Now()
	last, err := readLastRows(ctx, db, game, day)
	if err != nil {
		t.Fatal(err)
	}
	lastTook := time.Since(start)

	match := salesVelocityMatcher(testSite.backend())
	start = time.Now()
	cards, unmatched := buildSalesVelocity(rows, last, match)
	buildTook := time.Since(start)
	if len(cards) == 0 {
		t.Fatal("no cards matched")
	}

	// readLastRows already scopes to this game; re-derive the same set from
	// tcgplayerproductinfomodel as an independent check that it did.
	products, err := db.QueryContext(ctx, `SELECT DISTINCT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1`, game)
	if err != nil {
		t.Fatal(err)
	}
	inGame := map[int64]bool{}
	for products.Next() {
		var id int64
		err := products.Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		inGame[id] = true
	}
	err = products.Err()
	products.Close()
	if err != nil {
		t.Fatal(err)
	}
	gamePairs, gameUnmatched := 0, 0
	for _, row := range last {
		if !inGame[row.ProductID] {
			continue
		}
		gamePairs++
		if match(row.ProductID, row.Variant) == "" {
			gameUnmatched++
		}
	}

	capped, zero := 0, 0
	for _, v := range cards {
		if v.Capped {
			capped++
		}
		if v.Copies == 0 {
			zero++
		}
	}

	fmt.Print("| query | ms | rows |\n|---|---:|---:|\n")
	fmt.Printf("| newest sale day | %d | 1 |\n", dayTook.Milliseconds())
	fmt.Printf("| %d-day window | %d | %d |\n", salesVelocityWindow, rowsTook.Milliseconds(), len(rows))
	fmt.Printf("| last sale over %d days | %d | %d |\n", salesVelocityLookback, lastTook.Milliseconds(), len(last))
	fmt.Printf("| match and build (cards) | %d | %d |\n\n", buildTook.Milliseconds(), len(cards))
	fmt.Print("| entries | capped | capped share | zero | unmatched pairs | this game's pairs unmatched |\n|---:|---:|---:|---:|---:|---:|\n")
	fmt.Printf("| %d | %d | %.1f%% | %d | %d | %d of %d |\n",
		len(cards), capped, 100*float64(capped)/float64(len(cards)), zero, unmatched, gameUnmatched, gamePairs)
}
