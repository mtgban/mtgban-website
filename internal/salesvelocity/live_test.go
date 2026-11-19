package salesvelocity

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	_ "github.com/mtgban/go-mtgban/matcher/games"
	"github.com/mtgban/mtgban-website/timeseries"
)

// TestSalesVelocityLive times the sales velocity load on the newspaper and
// prints the tables docs/search-sales-velocity.md quotes. Read-only, and
// skipped unless asked for. The test runs in this directory, so the config is an
// absolute path, or the repo's config.json by default:
//
//	NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<absolute path> go test ./internal/salesvelocity -run TestSalesVelocityLive -v
func TestSalesVelocityLive(t *testing.T) {
	if os.Getenv("NEWSPAPER_LIVE") != "1" {
		t.Skip("NEWSPAPER_LIVE not set; skipping the live sales velocity test")
	}
	datastore, err := os.Open("../../allprintings5.json")
	if err != nil {
		t.Skip("no local datastore: ", err)
	}
	defer datastore.Close()
	b, err := matcher.Open(matcher.GameMagic, datastore)
	if err != nil {
		t.Fatal(err)
	}

	path := cmp.Or(os.Getenv("NEWSPAPER_LIVE_CONFIG"), "../../config.json")
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

	const game = "Magic: The Gathering"

	start := time.Now()
	var newest time.Time
	err = db.QueryRowContext(ctx, DayQuery, game, Window).Scan(&newest)
	if err != nil {
		t.Fatal(err)
	}
	dayTook := time.Since(start)
	err = db.QueryRowContext(ctx, GlobalDayQuery, Window).Scan(&newest)
	if err != nil {
		t.Fatal(err)
	}
	day := lastCompleteSaleDay(newest)
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

	start = time.Now()
	orders, err := readOrderRows(ctx, db, game)
	orderCount := fmt.Sprint(len(orders))
	if ordersUnavailable(err) != "" {
		orderCount = "n/a"
	} else if err != nil {
		t.Fatal(err)
	}
	ordersTook := time.Since(start)

	match := cardMatcher(b)
	start = time.Now()
	cards, unmatched := build(rows, last, orders, match)
	bands := grade(cards)
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

	zero := 0
	for _, v := range cards {
		if v.Copies == 0 {
			zero++
		}
	}

	fmt.Print("| query | ms | rows |\n|---|---:|---:|\n")
	fmt.Printf("| newest sale day | %d | 1 |\n", dayTook.Milliseconds())
	fmt.Printf("| %d-day window | %d | %d |\n", Window, rowsTook.Milliseconds(), len(rows))
	fmt.Printf("| last sale over %d days | %d | %d |\n", lookback, lastTook.Milliseconds(), len(last))
	fmt.Printf("| last orders | %d | %s |\n", ordersTook.Milliseconds(), orderCount)
	fmt.Printf("| match and build (cards) | %d | %d |\n\n", buildTook.Milliseconds(), len(cards))
	fmt.Print("| entries | with a price | zero | unmatched pairs | this game's pairs unmatched |\n|---:|---:|---:|---:|---:|\n")
	fmt.Printf("| %d | %d | %d | %d | %d of %d |\n\n", len(cards), pricedCount(cards), zero, unmatched, gameUnmatched, gamePairs)

	// Each band's cards with a sale in the window, and the slowest rate of each pace.
	counts := make([]int, len(bands))
	from := make([][PaceFastest + 1]float64, len(bands))
	for _, v := range cards {
		if v.Copies == 0 {
			continue
		}
		counts[v.Band]++
		rate := v.PerDay(Window)
		low := &from[v.Band][v.Pace]
		if *low == 0 || rate < *low {
			*low = rate
		}
	}
	fmt.Print("| band | cards | fastest from | fast from | steady from |\n|---|---:|---:|---:|---:|\n")
	for i, band := range bands {
		fmt.Printf("| %s | %d | %.2f | %.2f | %.2f |\n", cmp.Or(band.String(), "all"), counts[i],
			from[i][PaceFastest], from[i][PaceFast], from[i][PaceSteady])
	}

	// The cards rising, against those chance alone would flag were each card's
	// orders spread evenly over the window. Cards first sold in the window
	// have no pace before it, so are left out.
	windowStart := day.AddDate(0, 0, 1-Window)
	eligible, rising, chance := 0, 0, 0.0
	for _, v := range cards {
		if v.Orders < trendMinOrders || !v.FirstSale.Before(windowStart) {
			continue
		}
		eligible++
		if v.Rising(Window, windowStart) > 0 {
			rising++
		}
		chance += risingByChance(v.Orders, windowStart)
	}
	fmt.Print("\n| cards with enough orders | rising | by chance |\n|---:|---:|---:|\n")
	fmt.Printf("| %d | %d (%.1f%%) | %.0f (%.1f%%) |\n", eligible, rising, 100*float64(rising)/float64(eligible),
		chance, 100*chance/float64(eligible))
}

// risingByChance is the odds a card with orders spread evenly over the window
// has enough of them in its last TrendDays to read as rising.
func risingByChance(orders int32, start time.Time) float64 {
	n := float64(orders)
	p := float64(TrendDays) / float64(Window)
	odds := 0.0
	for k := range orders + 1 {
		if (Sales{Orders: orders, RecentOrders: k, FirstSale: start.AddDate(0, 0, -1)}).Rising(Window, start) == 0 {
			continue
		}
		lnN, _ := math.Lgamma(n + 1)
		lnK, _ := math.Lgamma(float64(k) + 1)
		lnNK, _ := math.Lgamma(n - float64(k) + 1)
		odds += math.Exp(lnN - lnK - lnNK + float64(k)*math.Log(p) + (n-float64(k))*math.Log(1-p))
	}
	return odds
}
