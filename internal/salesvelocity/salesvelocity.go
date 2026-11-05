// Package salesvelocity reads TCGplayer's copies sold a day per card from the
// newspaper's sales table, holds the last load, and watches the pull behind it.
package salesvelocity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

const (
	// Window is the days the rate is taken over, ending on the last complete sale day.
	Window = 30
	// Days back the last sale is looked for.
	lookback = 365
	// How long a sale day whose load failed waits before a retry.
	retryAfter = 6 * time.Hour
)

// Sales is one card's sales over the window and its last sale.
type Sales struct {
	Copies, Orders, Days int32
	LastSale             time.Time
}

// PerDay is the copies sold a day over window days.
func (v Sales) PerDay(window int) float64 {
	return float64(v.Copies) / float64(window)
}

// Snapshot is one load of the sales, keyed by card uuid.
type Snapshot struct {
	// The last complete sale day, which the window ends on.
	Day    time.Time
	Cards  map[string]*Sales
	Window int
}

// failure is the sale day whose load last failed, and when.
type failure struct {
	Day, At time.Time
}

// Store is the last load and what decides the next one. The zero value is
// empty and ready to use.
type Store struct {
	current atomic.Pointer[Snapshot]
	failed  atomic.Pointer[failure]
	// loading gates concurrent loads (datastore loads and cron).
	loading atomic.Bool
}

// Snapshot is the last load, nil before the first.
func (s *Store) Snapshot() *Snapshot {
	return s.current.Load()
}

// Publish makes snap the last load.
func (s *Store) Publish(snap *Snapshot) {
	s.current.Store(snap)
}

// DayQuery is the newest day this game has a sale, none over the window; the
// scrape lags today by a day. It walks the date index down to the first sale: a
// max() has to read every row a game has, which for Magic is a scan of the whole table.
const DayQuery = `
	SELECT sale_date
	  FROM tcgplayersalesdata
	 WHERE sale_date > current_date - $2::int
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1)
	 ORDER BY sale_date DESC
	 LIMIT 1`

// WindowQuery is the copies, orders and sale days per product and printing of one game.
const WindowQuery = `
	SELECT product_id, variant,
	       coalesce(sum(sales_count), 0), coalesce(sum(num_orders), 0), count(*)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// LastQuery is the last sale per product and printing of one game over the lookback.
const LastQuery = `
	SELECT product_id, variant, max(sale_date)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// salesRow is one row of WindowQuery.
type salesRow struct {
	ProductID            int64
	Variant              string
	Copies, Orders, Days int32
}

// lastRow is one row of LastQuery.
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

// Load reads game's last complete sale day into the store once it is new. What it
// did goes in result or problem for the job's dashboard row, both empty when
// there was nothing to do.
func (s *Store) Load(ctx context.Context, db *sql.DB, b *matcher.Backend, game string) (result, problem string) {
	if !s.loading.CompareAndSwap(false, true) {
		return "", ""
	}
	defer s.loading.Store(false)

	var newest time.Time
	err := db.QueryRowContext(ctx, DayQuery, game, Window).Scan(&newest)
	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("sales velocity: no sales in the last %d days", Window)
		return "", ""
	}
	if err != nil {
		log.Println("sales velocity:", err)
		return "", "cannot read the newspaper: " + err.Error()
	}
	day := lastCompleteSaleDay(newest)
	if !due(s.current.Load(), s.failed.Load(), day, time.Now()) {
		return "", ""
	}

	cards, unmatched, err := query(ctx, db, b, game, day)
	if err != nil {
		log.Println("sales velocity:", err)
		s.failed.Store(&failure{Day: day, At: time.Now()})
		return "", "failed to load " + day.Format(time.DateOnly) + ": " + err.Error()
	}
	snap := &Snapshot{Day: day, Cards: cards, Window: Window}
	s.current.Store(snap)
	result = report(snap, unmatched)
	log.Println("sales velocity:", result)
	return result, ""
}

// lastCompleteSaleDay is the day before the newest: the newspaper writes a day
// as it pulls each product, so for hours the newest holds only part of its sales.
func lastCompleteSaleDay(newest time.Time) time.Time {
	return newest.AddDate(0, 0, -1)
}

// due reports whether day should load, given the loaded and the last failed one.
func due(current *Snapshot, failed *failure, day, now time.Time) bool {
	if current != nil && current.Day.Equal(day) {
		return false
	}
	return failed == nil || !failed.Day.Equal(day) || now.Sub(failed.At) >= retryAfter
}

// salesQuerier is a database or one of its transactions.
type salesQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readSalesRows reads game's window ending on day, per product and printing.
func readSalesRows(ctx context.Context, q salesQuerier, game string, day time.Time) ([]salesRow, error) {
	from := day.AddDate(0, 0, 1-Window)
	rows, err := q.QueryContext(ctx, WindowQuery, from.Format(time.DateOnly), day.Format(time.DateOnly), game)
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
	from := day.AddDate(0, 0, 1-lookback)
	rows, err := q.QueryContext(ctx, LastQuery, from.Format(time.DateOnly), day.Format(time.DateOnly), game)
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

// cardMatcher resolves a product and printing to b's card id, "" for none.
func cardMatcher(b *matcher.Backend) func(productID int64, variant string) string {
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

// query reads game's sales to day, ends the transaction, then keys them by b's cards.
func query(ctx context.Context, db *sql.DB, b *matcher.Backend, game string, day time.Time) (map[string]*Sales, int, error) {
	rows, last, err := readSales(ctx, db, game, day)
	if err != nil {
		return nil, 0, err
	}
	cards, unmatched := build(rows, last, cardMatcher(b))
	if len(cards) == 0 {
		return nil, unmatched, fmt.Errorf("no cards matched in %d pairs to %s, keeping the previous load", len(last), day.Format(time.DateOnly))
	}
	return cards, unmatched, nil
}

// build keys the pairs by card uuid and counts the pairs no card matches.
func build(rows []salesRow, last []lastRow, match func(productID int64, variant string) string) (map[string]*Sales, int) {
	cards := map[string]*Sales{}
	resolved := map[salesPair]string{}
	unmatched := 0
	entry := func(productID int64, variant string) *Sales {
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
			v = &Sales{}
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

// For is a copy of a card's loaded sales, false when it has none.
func (s *Store) For(cardID string) (Sales, bool) {
	snap := s.current.Load()
	if snap == nil {
		return Sales{}, false
	}
	v, found := snap.Cards[cardID]
	if !found {
		return Sales{}, false
	}
	return *v, true
}

// report is a load's line on the admin dashboard.
func report(snap *Snapshot, unmatched int) string {
	return fmt.Sprintf("%d cards over the %d days to %s, %d not matched",
		len(snap.Cards), snap.Window, snap.Day.Format(time.DateOnly), unmatched)
}

// text is a card's rate and its details (tip_html format) over window days.
func text(v Sales, window int) (rate, detail string) {
	head := fmt.Sprintf("**Sold on TCGplayer, last %d days**", window)
	if v.Copies == 0 {
		zero := "no sale in the window"
		if !v.LastSale.IsZero() {
			zero += "; last sold " + v.LastSale.Format(time.DateOnly)
		}
		return "0/day", head + "\n" + zero
	}

	perDay := v.PerDay(window)
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

// notableFloor is the rate worth showing on a table of cards: anything lower
// prints as 0.1/day or less, which is noise there.
const notableFloor = 0.15

// View is a card's rate and details, both empty without data, and whether it
// sells fast enough to show the rate on a table of cards.
func (s *Store) View(cardID string) (rate, detail string, notable bool) {
	v, found := s.For(cardID)
	if !found {
		return "", "", false
	}
	rate, detail = text(v, Window)
	return rate, detail, v.PerDay(Window) >= notableFloor
}

// Rates is the copies sold a day of each card with data.
func (s *Store) Rates(cardIDs []string) map[string]float64 {
	rates := make(map[string]float64, len(cardIDs))
	for _, cardID := range cardIDs {
		v, found := s.For(cardID)
		if found {
			rates[cardID] = v.PerDay(Window)
		}
	}
	return rates
}
