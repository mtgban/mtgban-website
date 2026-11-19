// Package salesvelocity reads TCGplayer's copies sold a day per card from the
// newspaper's sales table, holds the last load, and watches the pull behind it.
package salesvelocity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"weak"

	"github.com/lib/pq"
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
	// The orders in the window's last TrendDays.
	RecentOrders int32
	// The first and last sale over the lookback.
	FirstSale, LastSale time.Time
	// The newest order's price per copy and its condition abbreviated, 0 and empty with none.
	LastPrice     float64
	LastCondition string
	// The median sale price over the window, weighted by orders.
	Price float64

	// How fast it sells against its price band, Bands[Band], and the percent
	// of that band's cards it outsells, rounded down.
	Pace     Pace
	Band     int8
	Outsells int8
}

// Pace is how fast a card sells against cards of a like price.
type Pace int8

const (
	// PaceNone is a card with no sales loaded.
	PaceNone Pace = iota
	// PaceSlow is the slowest quarter of a price band, and a card with no
	// sale in the window.
	PaceSlow
	// PaceSteady is down to the slowest quarter.
	PaceSteady
	// PaceFast is the next three tenths after the fastest.
	PaceFast
	// PaceFastest is the fastest tenth of a price band.
	PaceFastest
)

// String names the pace, as the stylesheets' velocity-<name> classes do.
func (p Pace) String() string {
	switch p {
	case PaceSlow:
		return "slow"
	case PaceSteady:
		return "steady"
	case PaceFast:
		return "fast"
	case PaceFastest:
		return "fastest"
	}
	return ""
}

// PerDay is the copies sold a day over window days.
func (v Sales) PerDay(window int) float64 {
	return float64(v.Copies) / float64(window)
}

const (
	// TrendDays is the end of the window a trend compares with the days before it.
	TrendDays = 7
	// The fewest orders in the window a trend is read from, and how many times
	// the days before it the last TrendDays sell at to count as rising.
	trendMinOrders = 30
	trendFactor    = 2
	// The most times faster the details print: past it the days before hold
	// an order or two, and the ratio says more about them than the trend.
	trendCap = 5
)

// Rising is how many times faster the last TrendDays sold than the days before
// them in the window starting on start, in orders, or 0 when that is under
// trendFactor or there are too few orders to tell from noise. A card first
// sold in the window is new rather than rising, having no pace before it.
func (v Sales) Rising(window int, start time.Time) float64 {
	before := v.Orders - v.RecentOrders
	if v.Orders < trendMinOrders || before <= 0 || window <= TrendDays || !v.FirstSale.Before(start) {
		return 0
	}
	ratio := float64(v.RecentOrders) / TrendDays / (float64(before) / float64(window-TrendDays))
	if ratio < trendFactor {
		return 0
	}
	return ratio
}

// Snapshot is one load of the sales, keyed by card uuid.
type Snapshot struct {
	// The last complete sale day, which the window ends on.
	Day    time.Time
	Cards  map[string]*Sales
	Window int
	// The price bands each card's pace is judged within.
	Bands []Band
	// The cards with a last sale price, and why there are none when the
	// order table could not be read.
	Priced int
	Note   string

	// The backend whose card ids key Cards, held weakly so a snapshot
	// outliving a datastore reload does not keep the old backend alive
	Backend weak.Pointer[matcher.Backend]
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

// GlobalDayQuery is the newest day any game has a sale, none over the window.
// It walks the same date index as DayQuery, with no game to keep to, so it
// stops at the first row rather than reading the whole table as a max() does.
const GlobalDayQuery = `
	SELECT sale_date
	  FROM tcgplayersalesdata
	 WHERE sale_date > current_date - $1::int
	 ORDER BY sale_date DESC
	 LIMIT 1`

// WindowQuery is the copies, orders, sale days and median sale price per
// product and printing of one game, and the orders in its last $4 days.
const WindowQuery = `
	SELECT product_id, variant,
	       coalesce(sum(sales_count), 0), coalesce(sum(num_orders), 0), count(*),
	       coalesce(sum(median_price * num_orders) / nullif(sum(num_orders), 0), 0)::float8,
	       coalesce(sum(num_orders) FILTER (WHERE sale_date > $2::date - $4::int), 0)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// LastQuery is the last and first sale per product and printing of one game over the lookback.
const LastQuery = `
	SELECT product_id, variant, max(sale_date), min(sale_date)
	  FROM tcgplayersalesdata
	 WHERE sale_date BETWEEN $1::date AND $2::date
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)
	 GROUP BY 1, 2`

// LastOrderQuery is the newest order per product and printing of one game, whatever its date.
const LastOrderQuery = `
	SELECT product_id, variant, order_date, condition, purchase_price::float8
	  FROM tcgplayerlastsalemodel
	 WHERE product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1)
	 ORDER BY product_id, variant`

// salesRow is one row of WindowQuery.
type salesRow struct {
	ProductID            int64
	Variant              string
	Copies, Orders, Days int32
	Price                float64
	RecentOrders         int32
}

// lastRow is one row of LastQuery.
type lastRow struct {
	ProductID int64
	Variant   string
	Last      time.Time
	First     time.Time
}

// orderRow is a product and printing's newest order.
type orderRow struct {
	ProductID int64
	Variant   string
	At        time.Time
	Condition string
	Price     float64
}

// salesPair is a product in one printing, as the sales table keys it.
type salesPair struct {
	productID int64
	variant   string
}

// Load reads game's last complete sale day into the store once it is new. What it
// found goes in result or problem for the job's dashboard row, both empty while
// another load runs or a failed day waits out its retry, so that failure stands.
func (s *Store) Load(ctx context.Context, db *sql.DB, b *matcher.Backend, game string) (result, problem string) {
	if !s.loading.CompareAndSwap(false, true) {
		return "", ""
	}
	defer s.loading.Store(false)

	// This game's newest sale only says it sold in the window: the newspaper
	// writes a sale day for every game at once, so the partial one is the
	// newest across them all.
	var newest time.Time
	err := db.QueryRowContext(ctx, DayQuery, game, Window).Scan(&newest)
	if errors.Is(err, sql.ErrNoRows) {
		result = fmt.Sprintf("no sales in the last %d days", Window)
		log.Println("sales velocity:", result)
		return result, ""
	}
	if err == nil {
		err = db.QueryRowContext(ctx, GlobalDayQuery, Window).Scan(&newest)
	}
	if err != nil {
		log.Println("sales velocity:", err)
		return "", "cannot read the newspaper: " + err.Error()
	}
	day := lastCompleteSaleDay(newest)
	current := s.current.Load()
	// A datastore reload brings new card ids, so the day is read again for them
	if current != nil && current.Backend != weak.Make(b) {
		current = nil
	}
	if current != nil && current.Day.Equal(day) {
		return alreadyLoadedLine(current), ""
	}
	if !due(current, s.failed.Load(), day, time.Now()) {
		return "", ""
	}

	cards, bands, unmatched, priced, note, err := query(ctx, db, b, game, day)
	if err != nil {
		log.Println("sales velocity:", err)
		s.failed.Store(&failure{Day: day, At: time.Now()})
		return "", "failed to load " + day.Format(time.DateOnly) + ": " + err.Error()
	}
	snap := &Snapshot{Day: day, Cards: cards, Window: Window, Bands: bands, Priced: priced, Note: note, Backend: weak.Make(b)}
	s.current.Store(snap)
	result = report(snap, unmatched)
	log.Println("sales velocity:", result)
	return result, ""
}

// lastCompleteSaleDay is the day before the newest of any game: the newspaper
// writes a day as it pulls each product, so for hours the newest holds only part
// of its sales.
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
	rows, err := q.QueryContext(ctx, WindowQuery, from.Format(time.DateOnly), day.Format(time.DateOnly), game, TrendDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []salesRow
	for rows.Next() {
		var row salesRow
		err := rows.Scan(&row.ProductID, &row.Variant, &row.Copies, &row.Orders, &row.Days, &row.Price, &row.RecentOrders)
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
		err := rows.Scan(&row.ProductID, &row.Variant, &row.Last, &row.First)
		if err != nil {
			return nil, err
		}
		all = append(all, row)
	}
	return all, rows.Err()
}

// readOrderRows reads game's newest orders, per product and printing.
func readOrderRows(ctx context.Context, q salesQuerier, game string) ([]orderRow, error) {
	rows, err := q.QueryContext(ctx, LastOrderQuery, game)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []orderRow
	for rows.Next() {
		var row orderRow
		var condition sql.NullString
		err := rows.Scan(&row.ProductID, &row.Variant, &row.At, &condition, &row.Price)
		if err != nil {
			return nil, err
		}
		row.Condition = condition.String
		// A timestamp without zone holds UTC, whatever location the driver gives it.
		y, m, d := row.At.Date()
		hh, mm, ss := row.At.Clock()
		row.At = time.Date(y, m, d, hh, mm, ss, row.At.Nanosecond(), time.UTC)
		all = append(all, row)
	}
	return all, rows.Err()
}

// ordersUnavailable is whether err is the order table missing or unreadable.
func ordersUnavailable(err error) bool {
	var pgErr *pq.Error
	return errors.As(err, &pgErr) && (pgErr.Code == "42P01" || pgErr.Code == "42501")
}

// loadOrders runs read, turning an absent or unreadable table into no orders and a note.
func loadOrders(ctx context.Context, read func() ([]orderRow, error)) ([]orderRow, string, error) {
	orders, err := read()
	if err == nil {
		return orders, "", nil
	}
	var pgErr *pq.Error
	if ctx.Err() == nil && ordersUnavailable(err) && errors.As(err, &pgErr) {
		return nil, "last sale prices unavailable: " + pgErr.Message, nil
	}
	return nil, "", err
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

// readSales reads game's window and lookback in one snapshot, then its newest
// orders; the note says why there are none.
func readSales(ctx context.Context, db *sql.DB, game string, day time.Time) ([]salesRow, []lastRow, []orderRow, string, error) {
	rows, last, err := readSnapshot(ctx, db, game, day)
	if err != nil {
		return nil, nil, nil, "", err
	}
	orders, note, err := loadOrders(ctx, func() ([]orderRow, error) { return readOrderRows(ctx, db, game) })
	if err != nil {
		return nil, nil, nil, "", err
	}
	return rows, last, orders, note, nil
}

// readSnapshot reads the window and the lookback in one read-only repeatable read.
func readSnapshot(ctx context.Context, db *sql.DB, game string, day time.Time) ([]salesRow, []lastRow, error) {
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

// query reads game's sales to day, ends the transaction, then keys them by b's
// cards and grades their pace. It also returns the cards with a last sale
// price, and the note on why there are none.
func query(ctx context.Context, db *sql.DB, b *matcher.Backend, game string, day time.Time) (map[string]*Sales, []Band, int, int, string, error) {
	rows, last, orders, note, err := readSales(ctx, db, game, day)
	if err != nil {
		return nil, nil, 0, 0, "", err
	}
	cards, unmatched := build(rows, last, orders, cardMatcher(b))
	if len(cards) == 0 {
		return nil, nil, unmatched, 0, "", fmt.Errorf("no cards matched in %d pairs to %s, keeping the previous load", len(last), day.Format(time.DateOnly))
	}
	return cards, grade(cards), unmatched, pricedCount(cards), note, nil
}

// pricedCount is the cards with a last sale price.
func pricedCount(cards map[string]*Sales) int {
	n := 0
	for _, v := range cards {
		if v.LastPrice > 0 {
			n++
		}
	}
	return n
}

// build keys the pairs by card uuid and counts the pairs no card matches.
func build(rows []salesRow, last []lastRow, orders []orderRow, match func(productID int64, variant string) string) (map[string]*Sales, int) {
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
		if v == nil {
			continue
		}
		if row.Last.After(v.LastSale) {
			v.LastSale = row.Last
		}
		if v.FirstSale.IsZero() || row.First.Before(v.FirstSale) {
			v.FirstSale = row.First
		}
	}
	// The newest order per card, picked before any date moves; a pair with no
	// card entry is not a sales pair, so it neither makes one nor counts.
	newest := map[*Sales]orderRow{}
	for _, o := range orders {
		key := salesPair{o.ProductID, o.Variant}
		cardID, seen := resolved[key]
		if !seen {
			cardID = match(o.ProductID, o.Variant)
			// A miss stays unrecorded, so a sales pair of it is still counted unmatched.
			if cardID != "" {
				resolved[key] = cardID
			}
		}
		v := cards[cardID]
		if cardID == "" || v == nil || o.Price <= 0 || startOfDay(o.At).Before(v.LastSale) {
			continue
		}
		if best, ok := newest[v]; !ok || o.At.After(best.At) {
			newest[v] = o
		}
	}
	for v, o := range newest {
		v.LastSale = startOfDay(o.At)
		v.LastPrice = o.Price
		v.LastCondition = shortCondition(o.Condition)
	}
	for _, row := range rows {
		v := entry(row.ProductID, row.Variant)
		if v == nil {
			continue
		}
		if row.Orders > 0 {
			v.Price = (v.Price*float64(v.Orders) + row.Price*float64(row.Orders)) / float64(v.Orders+row.Orders)
		}
		v.Copies += row.Copies
		v.Orders += row.Orders
		v.RecentOrders += row.RecentOrders
		// The larger count, not the sum: the rows can't say which days overlap.
		v.Days = max(v.Days, row.Days)
	}
	return cards, unmatched
}

// startOfDay is t's UTC date at midnight, as the lookback's dates scan.
func startOfDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// The conditions' short forms, shared so every card holds one string of each.
const (
	condNM  = "NM"
	condLP  = "LP"
	condMP  = "MP"
	condHP  = "HP"
	condDMG = "DMG"
)

// shortCondition is TCGplayer's grade abbreviated, anything else as sent.
func shortCondition(condition string) string {
	switch condition {
	case "Near Mint":
		return condNM
	case "Lightly Played":
		return condLP
	case "Moderately Played":
		return condMP
	case "Heavily Played":
		return condHP
	case "Damaged":
		return condDMG
	}
	return condition
}

// priceText is the last sale's price and condition, "$12.34 LP", empty with no price.
func priceText(v Sales) string {
	if v.LastPrice <= 0 {
		return ""
	}
	price := fmt.Sprintf("$%.2f", v.LastPrice)
	if c := v.LastCondition; c != "" {
		price += " " + c
	}
	return price
}

// lastSaleText is the last sale's price, condition and date, as the details print it.
func lastSaleText(v Sales) string {
	date := v.LastSale.Format(time.DateOnly)
	if price := priceText(v); price != "" {
		return price + " · " + date
	}
	return date
}

// bandEdges split the cards, by price in dollars, into the bands a pace is
// judged within: copies sold a day hold level to about $30 and fall above it.
var bandEdges = []float64{1, 3, 10, 30, 100, 300}

// minBand is the fewest cards a band is graded on; a smaller one joins the
// band below it, or the lowest the one above.
const minBand = 200

// Band is the prices from Low up to High, with no bound where one is 0.
type Band struct {
	Low, High float64
}

// String is the band's prices: "under $1", "at $10–30", "at $300+", or empty
// for a band holding every price.
func (b Band) String() string {
	dollars := func(x float64) string { return strconv.FormatFloat(x, 'f', -1, 64) }
	switch {
	case b.Low == 0 && b.High == 0:
		return ""
	case b.Low == 0:
		return "under $" + dollars(b.High)
	case b.High == 0:
		return "at $" + dollars(b.Low) + "+"
	}
	return "at $" + dollars(b.Low) + "–" + dollars(b.High)
}

// grade sets each card's pace against the cards of its price band that sold
// in the window, and returns the bands. A card with no sale in it is slow.
func grade(cards map[string]*Sales) []Band {
	type group struct {
		band  Band
		cards []*Sales
	}
	groups := make([]group, len(bandEdges)+1)
	for i := range groups {
		if i > 0 {
			groups[i].band.Low = bandEdges[i-1]
		}
		if i < len(bandEdges) {
			groups[i].band.High = bandEdges[i]
		}
	}
	for _, v := range cards {
		if v.Copies == 0 {
			v.Pace = PaceSlow
			continue
		}
		i := sort.Search(len(bandEdges), func(i int) bool { return bandEdges[i] > v.Price })
		groups[i].cards = append(groups[i].cards, v)
	}
	for i := len(groups) - 1; i > 0; i-- {
		if len(groups[i].cards) < minBand {
			groups[i-1].cards = append(groups[i-1].cards, groups[i].cards...)
			groups[i-1].band.High = groups[i].band.High
			groups = slices.Delete(groups, i, i+1)
		}
	}
	if len(groups) > 1 && len(groups[0].cards) < minBand {
		groups[1].cards = append(groups[1].cards, groups[0].cards...)
		groups[1].band.Low = 0
		groups = groups[1:]
	}

	bands := make([]Band, len(groups))
	for i, g := range groups {
		bands[i] = g.band
		copies := make([]int, len(g.cards))
		for j, v := range g.cards {
			copies[j] = int(v.Copies)
		}
		sort.Ints(copies)
		n := len(copies)
		for _, v := range g.cards {
			slower := sort.SearchInts(copies, int(v.Copies))
			v.Band, v.Outsells = int8(i), int8(100*slower/n)
			// In whole counts, so a share on a cut-off is never a hair under it.
			switch {
			case 10*slower >= 9*n:
				v.Pace = PaceFastest
			case 10*slower >= 6*n:
				v.Pace = PaceFast
			case 4*slower >= n:
				v.Pace = PaceSteady
			default:
				v.Pace = PaceSlow
			}
		}
	}
	return bands
}

// For is a copy of a card's sales, false when it has none or s is nil.
func (s *Snapshot) For(cardID string) (Sales, bool) {
	if s == nil {
		return Sales{}, false
	}
	v, found := s.Cards[cardID]
	if !found {
		return Sales{}, false
	}
	return *v, true
}

// report is a load's line on the admin dashboard.
func report(snap *Snapshot, unmatched int) string {
	return fmt.Sprintf("%d cards over the %d days to %s, %d not matched%s",
		len(snap.Cards), snap.Window, snap.Day.Format(time.DateOnly), unmatched, pricedSuffix(snap.Priced, snap.Note))
}

// alreadyLoadedLine is the dashboard line for a load that finds snap's day loaded.
func alreadyLoadedLine(snap *Snapshot) string {
	return fmt.Sprintf("%d cards over the %d days to %s, already loaded%s",
		len(snap.Cards), snap.Window, snap.Day.Format(time.DateOnly), pricedSuffix(snap.Priced, snap.Note))
}

// pricedSuffix is the dashboard line's count of priced cards and its note, if any.
func pricedSuffix(priced int, note string) string {
	line := fmt.Sprintf(", %d with a last sale price", priced)
	if note != "" {
		line += "; " + note
	}
	return line
}

// paceLine is the details' line on how a card sells against its price band,
// empty for a card not graded or with no sale in the window.
func paceLine(v Sales, bands []Band) string {
	if v.Pace == PaceNone || v.Copies == 0 || int(v.Band) >= len(bands) {
		return ""
	}
	peers := "all cards"
	label := bands[v.Band].String()
	if label != "" {
		peers = "cards " + label
	}
	faster := "among the slowest"
	if v.Outsells > 0 {
		faster = "faster than " + strconv.Itoa(int(v.Outsells)) + "%"
	}
	return "|vs. " + peers + "|" + faster
}

// trendLine is the details' line on a card rising the times given, empty for
// one not rising.
func trendLine(rising float64) string {
	if rising == 0 {
		return ""
	}
	if rising > trendCap {
		return fmt.Sprintf("|last %d days|over %d× the pace before", TrendDays, trendCap)
	}
	return fmt.Sprintf("|last %d days|%.1f× the pace before", TrendDays, rising)
}

// text is a card's rate and its details (tip_html format) over window days,
// with notes, its paceLine and trendLine, before the last sale.
func text(v Sales, window int, notes ...string) (rate, detail string) {
	head := fmt.Sprintf("**Sold on TCGplayer, last %d days**", window)
	if v.Copies == 0 {
		zero := "no sale in the window"
		if !v.LastSale.IsZero() {
			zero += "; last sold " + v.LastSale.Format(time.DateOnly)
			if price := priceText(v); price != "" {
				zero += " for " + price
			}
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
	for _, note := range notes {
		if note != "" {
			lines = append(lines, note)
		}
	}
	if !v.LastSale.IsZero() {
		lines = append(lines, "|last sale|"+lastSaleText(v))
	}
	return rate, strings.Join(lines, "\n")
}

// notableFloor is the rate worth showing on a table of cards: anything lower
// prints as 0.1/day or less, which is noise there.
const notableFloor = 0.15

// View is a card's rate and details, both empty without data, and whether it
// sells fast enough to show the rate on a table of cards.
func (s *Snapshot) View(cardID string) (rate, detail string, notable bool) {
	v, found := s.For(cardID)
	if !found {
		return "", "", false
	}
	rate, detail = text(v, Window, paceLine(v, s.Bands), trendLine(s.rising(v)))
	return rate, detail, v.PerDay(Window) >= notableFloor
}

// rising is v.Rising over the snapshot's window.
func (s *Snapshot) rising(v Sales) float64 {
	return v.Rising(Window, s.Day.AddDate(0, 0, 1-Window))
}

// Rising reports whether a card sells markedly faster in the last TrendDays.
func (s *Snapshot) Rising(cardID string) bool {
	v, found := s.For(cardID)
	return found && s.rising(v) > 0
}

// Pace is how fast a card sells for its price, PaceNone without data.
func (s *Snapshot) Pace(cardID string) Pace {
	v, _ := s.For(cardID)
	return v.Pace
}

// Rates is the copies sold a day of each card with data.
func (s *Snapshot) Rates(cardIDs []string) map[string]float64 {
	rates := make(map[string]float64, len(cardIDs))
	for _, cardID := range cardIDs {
		v, found := s.For(cardID)
		if found {
			rates[cardID] = v.PerDay(Window)
		}
	}
	return rates
}
