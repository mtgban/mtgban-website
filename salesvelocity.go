package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

// TCGplayer's copies sold a day per card, from the newspaper's sales table.

const (
	// Days the rate is taken over, ending on the newest sale day.
	salesVelocityWindow = 30
	// Days back the last sale is looked for.
	salesVelocityLookback = 365
	// How long a sale day whose load failed waits before a retry.
	salesVelocityRetryAfter = 6 * time.Hour
)

// salesVelocity is one card's sales over the window and its last sale.
type salesVelocity struct {
	Copies, Orders, Days int32
	LastSale             time.Time
}

// perDay is the copies sold a day over window days.
func (v salesVelocity) perDay(window int) float64 {
	return float64(v.Copies) / float64(window)
}

// salesVelocitySnapshot is one load of the sales, keyed by card uuid.
type salesVelocitySnapshot struct {
	// The newest sale_date, which the window ends on.
	Day    time.Time
	Cards  map[string]*salesVelocity
	Window int
}

var salesVelocityPtr atomic.Pointer[salesVelocitySnapshot]

// salesVelocityLoading gates concurrent loads (datastore loads and cron).
var salesVelocityLoading atomic.Bool

// salesVelocityFailure is the sale day whose load last failed, and when.
type salesVelocityFailure struct {
	Day, At time.Time
}

var salesVelocityFailed atomic.Pointer[salesVelocityFailure]

// The newest day this game has a sale; the scrape lags today by a day.
const salesVelocityDayQuery = `SELECT max(sale_date) FROM tcgplayersalesdata WHERE product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1)`

// Copies, orders and sale days per product and printing of one game.
const salesVelocityQuery = `
	SELECT product_id, variant,
	       coalesce(sum(sales_count), 0), coalesce(sum(num_orders), 0), count(*)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// The last sale per product and printing of one game over the lookback.
const salesVelocityLastQuery = `
	SELECT product_id, variant, max(sale_date)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// salesRow is one row of salesVelocityQuery.
type salesRow struct {
	ProductID            int64
	Variant              string
	Copies, Orders, Days int32
}

// lastRow is one row of salesVelocityLastQuery.
type lastRow struct {
	ProductID int64
	Variant   string
	Last      time.Time
}

// salesPair is a product in one printing, as the sales table keys it.
type salesPair struct {
	productID int64
	variant   string
}

// loadSalesVelocity loads the newspaper's newest sale day once it is new.
func (s *site) loadSalesVelocity() {
	game, found := gameMap[Config().Game]
	if !found || SkipNewspaper || NewNewspaperDB == nil {
		return
	}
	b := s.backend()
	if len(b.GetUUIDs()) == 0 {
		// No datastore yet: its load runs this once it is in.
		return
	}
	if !salesVelocityLoading.CompareAndSwap(false, true) {
		return
	}
	defer salesVelocityLoading.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var day sql.NullTime
	err := NewNewspaperDB.QueryRowContext(ctx, salesVelocityDayQuery, game).Scan(&day)
	if err != nil {
		log.Println("sales velocity:", err)
		backgroundJobs.Report(jobSalesVelocity, "", "cannot read the newspaper: "+err.Error())
		return
	}
	if !day.Valid {
		log.Println("sales velocity: the newspaper has no sales")
		return
	}
	if !salesVelocityDue(salesVelocityPtr.Load(), salesVelocityFailed.Load(), day.Time, time.Now()) {
		return
	}

	cards, unmatched, err := querySalesVelocity(ctx, b, game, day.Time)
	if err != nil {
		log.Println("sales velocity:", err)
		salesVelocityFailed.Store(&salesVelocityFailure{Day: day.Time, At: time.Now()})
		backgroundJobs.Report(jobSalesVelocity, "", "failed to load "+day.Time.Format(time.DateOnly)+": "+err.Error())
		return
	}
	snap := &salesVelocitySnapshot{Day: day.Time, Cards: cards, Window: salesVelocityWindow}
	salesVelocityPtr.Store(snap)
	result := salesVelocityReport(snap, unmatched)
	log.Println("sales velocity:", result)
	backgroundJobs.Report(jobSalesVelocity, result, "")
}

// salesVelocityDue reports whether day should load, given the loaded and the last failed one.
func salesVelocityDue(current *salesVelocitySnapshot, failed *salesVelocityFailure, day, now time.Time) bool {
	if current != nil && current.Day.Equal(day) {
		return false
	}
	return failed == nil || !failed.Day.Equal(day) || now.Sub(failed.At) >= salesVelocityRetryAfter
}

// salesQuerier is a database or one of its transactions.
type salesQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readSalesRows reads game's window ending on day, per product and printing.
func readSalesRows(ctx context.Context, q salesQuerier, game string, day time.Time) ([]salesRow, error) {
	from := day.AddDate(0, 0, 1-salesVelocityWindow)
	rows, err := q.QueryContext(ctx, salesVelocityQuery, from.Format(time.DateOnly), day.Format(time.DateOnly), game)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []salesRow
	for rows.Next() {
		var row salesRow
		err := rows.Scan(&row.ProductID, &row.Variant, &row.Copies, &row.Orders, &row.Days)
		if err != nil {
			return nil, err
		}
		all = append(all, row)
	}
	return all, rows.Err()
}

// readLastRows reads game's last sale over the lookback ending on day, per product and printing.
func readLastRows(ctx context.Context, q salesQuerier, game string, day time.Time) ([]lastRow, error) {
	from := day.AddDate(0, 0, 1-salesVelocityLookback)
	rows, err := q.QueryContext(ctx, salesVelocityLastQuery, from.Format(time.DateOnly), day.Format(time.DateOnly), game)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []lastRow
	for rows.Next() {
		var row lastRow
		err := rows.Scan(&row.ProductID, &row.Variant, &row.Last)
		if err != nil {
			return nil, err
		}
		all = append(all, row)
	}
	return all, rows.Err()
}

// salesVelocityMatcher resolves a product and printing to b's card id, "" for none.
func salesVelocityMatcher(b *matcher.Backend) func(productID int64, variant string) string {
	return func(productID int64, variant string) string {
		cardID, err := b.Match(&matcher.InputCard{
			ID:     strconv.FormatInt(productID, 10),
			Finish: variant,
			Foil:   variant != "Normal",
		})
		if err != nil {
			return ""
		}
		return cardID
	}
}

// readSales reads game's window and lookback ending on day in one read-only snapshot.
func readSales(ctx context.Context, db *sql.DB, game string, day time.Time) ([]salesRow, []lastRow, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := readSalesRows(ctx, tx, game, day)
	if err != nil {
		return nil, nil, err
	}
	last, err := readLastRows(ctx, tx, game, day)
	if err != nil {
		return nil, nil, err
	}
	return rows, last, nil
}

// querySalesVelocity reads game's sales to day, ends the transaction, then keys them by b's cards.
func querySalesVelocity(ctx context.Context, b *matcher.Backend, game string, day time.Time) (map[string]*salesVelocity, int, error) {
	rows, last, err := readSales(ctx, NewNewspaperDB, game, day)
	if err != nil {
		return nil, 0, err
	}
	cards, unmatched := buildSalesVelocity(rows, last, salesVelocityMatcher(b))
	if len(cards) == 0 {
		return nil, unmatched, fmt.Errorf("no cards matched in %d pairs to %s, keeping the previous load", len(last), day.Format(time.DateOnly))
	}
	return cards, unmatched, nil
}

// buildSalesVelocity keys the pairs by card uuid and counts the pairs no card matches.
func buildSalesVelocity(rows []salesRow, last []lastRow, match func(productID int64, variant string) string) (map[string]*salesVelocity, int) {
	cards := map[string]*salesVelocity{}
	resolved := map[salesPair]string{}
	unmatched := 0
	entry := func(productID int64, variant string) *salesVelocity {
		key := salesPair{productID, variant}
		cardID, seen := resolved[key]
		if !seen {
			cardID = match(productID, variant)
			resolved[key] = cardID
			if cardID == "" {
				unmatched++
			}
		}
		if cardID == "" {
			return nil
		}
		v := cards[cardID]
		if v == nil {
			v = &salesVelocity{}
			cards[cardID] = v
		}
		return v
	}
	for _, row := range last {
		v := entry(row.ProductID, row.Variant)
		if v != nil && row.Last.After(v.LastSale) {
			v.LastSale = row.Last
		}
	}
	for _, row := range rows {
		v := entry(row.ProductID, row.Variant)
		if v == nil {
			continue
		}
		v.Copies += row.Copies
		v.Orders += row.Orders
		// The larger count, not the sum: the rows can't say which days overlap.
		v.Days = max(v.Days, row.Days)
	}
	return cards, unmatched
}

// salesVelocityFor is a copy of a card's loaded sales, false when it has none.
func salesVelocityFor(cardID string) (salesVelocity, bool) {
	snap := salesVelocityPtr.Load()
	if snap == nil {
		return salesVelocity{}, false
	}
	v, found := snap.Cards[cardID]
	if !found {
		return salesVelocity{}, false
	}
	return *v, true
}

// salesVelocityReport is a load's line on the admin dashboard.
func salesVelocityReport(snap *salesVelocitySnapshot, unmatched int) string {
	return fmt.Sprintf("%d cards over the %d days to %s, %d not matched",
		len(snap.Cards), snap.Window, snap.Day.Format(time.DateOnly), unmatched)
}

// velocityText is a card's rate and its details (tip_html format) over window days.
func velocityText(v salesVelocity, window int) (rate, detail string) {
	head := fmt.Sprintf("**Sold on TCGplayer, last %d days**", window)
	if v.Copies == 0 {
		zero := "no sale in the window"
		if !v.LastSale.IsZero() {
			zero += "; last sold " + v.LastSale.Format(time.DateOnly)
		}
		return "0/day", head + "\n" + zero
	}

	perDay := v.perDay(window)
	rate = strconv.FormatFloat(perDay, 'f', 1, 64) + "/day"
	if perDay < 0.1 {
		rate = "<0.1/day"
	}

	lines := []string{
		head,
		"|copies|" + strconv.Itoa(int(v.Copies)),
		"|orders|" + strconv.Itoa(int(v.Orders)),
		"|days with a sale|" + strconv.Itoa(int(v.Days)),
	}
	if !v.LastSale.IsZero() {
		lines = append(lines, "|last sale|"+v.LastSale.Format(time.DateOnly))
	}
	return rate, strings.Join(lines, "\n")
}

// salesVelocityView is a card's rate and details, both empty without data.
func salesVelocityView(cardID string) (rate, detail string) {
	v, found := salesVelocityFor(cardID)
	if !found {
		return "", ""
	}
	return velocityText(v, salesVelocityWindow)
}

// cardFilterVelocityGreaterThan skips a card selling at most the rate asked,
// and one with no data, which is not the same as selling none.
func cardFilterVelocityGreaterThan(filters []string, co *matcher.CardObject) bool {
	v, found := salesVelocityFor(co.UUID)
	if !found {
		return true
	}
	limit, _ := strconv.ParseFloat(filters[0], 64)
	return v.perDay(salesVelocityWindow) <= limit
}

// cardFilterVelocityLessThan skips a card selling at least the rate asked, and
// one with no data.
func cardFilterVelocityLessThan(filters []string, co *matcher.CardObject) bool {
	v, found := salesVelocityFor(co.UUID)
	if !found {
		return true
	}
	limit, _ := strconv.ParseFloat(filters[0], 64)
	return v.perDay(salesVelocityWindow) >= limit
}

// A velocity filter parses locked and a locked one matches nothing, so no way
// into the parser reveals which cards sell without having read the reader's tier.
const lockedFilterPrefix = "locked_"

// unlockVelocity opens a query's velocity filters, those in its pools too, for
// a handler that checked the reader's signature.
func unlockVelocity(filters []FilterElem) {
	for i := range filters {
		if filters[i].Pool != nil {
			unlockVelocity(filters[i].Pool.CardFilters)
		}
		filters[i].Name = strings.TrimPrefix(filters[i].Name, lockedFilterPrefix)
	}
}

// lockedVelocity reports whether a query holds a velocity filter still locked.
func lockedVelocity(filters []FilterElem) bool {
	for i := range filters {
		if strings.HasPrefix(filters[i].Name, lockedFilterPrefix) {
			return true
		}
		if filters[i].Pool != nil && lockedVelocity(filters[i].Pool.CardFilters) {
			return true
		}
	}
	return false
}
