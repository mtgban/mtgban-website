package salesvelocity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"maps"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"weak"

	"github.com/lib/pq"
	"github.com/mtgban/go-mtgban/matcher"
)

// Grades are the conditions an order is kept under: TCGplayer's Near Mint
// through Damaged as the Buyers column heads its buylist, then the one a
// sealed product sells in.
var Grades = [...]string{"NM", "SP", "MP", "HP", "PO", unopened}

// unopened is the condition of every sealed order, and the grade it is kept under.
const unopened = "Unopened"

const (
	// RecentShown is the orders a grade shows before the rest fold away.
	RecentShown = 5
	// The orders kept per card and grade, as the newspaper keeps them.
	recentDepth = 20
	// How far before the newest stamp read an incremental load reads again. The
	// newspaper writes each product in one short transaction stamped at its
	// start, so rows commit out of stamp order by seconds; repeats are dropped.
	recentOverlap = 10 * time.Minute
)

// Order is one TCGplayer order: when, the price of one copy, the copies.
type Order struct {
	// Seconds since the epoch, UTC.
	At    uint32
	Cents uint32
	// The rest of the newspaper's key, hashed: product, printing, listing
	// and the date's fraction of a second, so two sales stay two.
	ID  uint32
	Qty uint16
}

// Recent is a card's newest orders per grade, Grades[i] in Grades[i], newest first.
type Recent struct {
	Grades [len(Grades)][]Order
}

// RecentSnapshot is the loaded orders, keyed by card uuid.
type RecentSnapshot struct {
	Cards map[string]*Recent
	// The newest stamp read, by the newspaper's clock: the next load reads
	// what was written after it.
	Pulled time.Time
	// When the last full load ran.
	Full time.Time

	// The backend whose card ids key Cards, held weakly like Snapshot's.
	Backend weak.Pointer[matcher.Backend]
}

// For is the card's orders, if any were loaded.
func (s *RecentSnapshot) For(cardID string) (*Recent, bool) {
	if s == nil {
		return nil, false
	}
	r, found := s.Cards[cardID]
	return r, found
}

// RecentStore is the last load of the orders. The zero value is empty and
// ready to use.
type RecentStore struct {
	current atomic.Pointer[RecentSnapshot]
	loading atomic.Bool
}

// Snapshot is the last load, nil before the first.
func (s *RecentStore) Snapshot() *RecentSnapshot {
	return s.current.Load()
}

// Publish makes snap the last load.
func (s *RecentStore) Publish(snap *RecentSnapshot) {
	s.current.Store(snap)
}

// RecentQuery is the orders of one game stamped after a time, naive UTC as
// the newspaper writes it.
const RecentQuery = `
	SELECT product_id, variant, condition, order_date,
	       round(purchase_price * 100)::bigint, quantity, custom_listing_id, pulled_at
	  FROM tcgplayerrecentsalemodel
	 WHERE pulled_at > $1
	   AND product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $2)`

// recentRow is one row of RecentQuery.
type recentRow struct {
	ProductID int64
	Variant   string
	Condition string
	At        time.Time
	Cents     int64
	Qty       int64
	ListingID string
	Pulled    time.Time
}

// Load reads game's orders into a new snapshot: all of them when there is
// none, the backend changed, or the last full load was another UTC day,
// otherwise only those written since the last load. A failure keeps the last
// snapshot for the next run to retry.
func (s *RecentStore) Load(ctx context.Context, db *sql.DB, b *matcher.Backend, game string, now time.Time) (result, problem string) {
	if !s.loading.CompareAndSwap(false, true) {
		return "", ""
	}
	defer s.loading.Store(false)

	current := s.current.Load()
	full := fullLoad(current, b, now)
	since := time.Time{}
	if !full {
		since = current.Pulled.Add(-recentOverlap)
	}

	var base *RecentSnapshot
	if !full {
		base = current
	}
	rb := newRecentBuilder(base, recentMatcher(b))
	err := scanRecent(ctx, db, game, since, rb)
	if err != nil {
		note := recentUnavailable(err)
		if note != "" {
			return note, ""
		}
		log.Println("recent sales:", err)
		return "", "cannot read recent sales: " + err.Error()
	}

	snap := rb.snapshot(base)
	stats := rb.st
	if full && len(snap.Cards) == 0 && stats.rows > 0 {
		return "", fmt.Sprintf("no cards matched in %d orders, keeping the previous load", stats.rows)
	}
	snap.Backend = weak.Make(b)
	snap.Full = now
	if !full {
		snap.Full = current.Full
	}
	s.current.Store(snap)

	result = stats.report(full, len(snap.Cards))
	log.Println("recent sales:", result)
	return result, ""
}

// fullLoad reports whether a load reads every order rather than those
// written since current: with none loaded, for a new backend, and once a day
// so orders deleted from the table leave the snapshot.
func fullLoad(current *RecentSnapshot, b *matcher.Backend, now time.Time) bool {
	return current == nil || current.Backend != weak.Make(b) || !startOfDay(current.Full).Equal(startOfDay(now))
}

// scanRecent reads game's orders stamped after since into rb one row at a
// time, so a full load never holds them all.
func scanRecent(ctx context.Context, q salesQuerier, game string, since time.Time, rb *recentBuilder) error {
	rows, err := q.QueryContext(ctx, RecentQuery, naive(since), game)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var row recentRow
		err := rows.Scan(&row.ProductID, &row.Variant, &row.Condition, &row.At, &row.Cents, &row.Qty, &row.ListingID, &row.Pulled)
		if err != nil {
			return err
		}
		row.At = asUTC(row.At)
		row.Pulled = asUTC(row.Pulled)
		rb.add(row)
	}
	return rows.Err()
}

// naive is t's UTC wall clock, for comparing with a timestamp without zone.
func naive(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.999999")
}

// asUTC reads a timestamp without zone as the UTC it holds, whatever
// location the driver gave it.
func asUTC(t time.Time) time.Time {
	y, m, d := t.Date()
	hh, mm, ss := t.Clock()
	return time.Date(y, m, d, hh, mm, ss, t.Nanosecond(), time.UTC)
}

// recentUnavailable is the note for err being the order table missing or
// unreadable, empty for any other error.
func recentUnavailable(err error) string {
	var pgErr *pq.Error
	if errors.As(err, &pgErr) && (pgErr.Code == "42P01" || pgErr.Code == "42501") {
		return "recent sales unavailable: " + pgErr.Message
	}
	return ""
}

// gradeIndex is condition's index in Grades, -1 for one that is not kept.
func gradeIndex(condition string) int {
	switch condition {
	case "Near Mint":
		return 0
	case "Lightly Played":
		return 1
	case "Moderately Played":
		return 2
	case "Heavily Played":
		return 3
	case "Damaged":
		return 4
	case unopened:
		return 5
	}
	return -1
}

// recentStats counts what a load read and could not keep.
type recentStats struct {
	rows, unmatched, undated int
	// Orders per condition with no grade.
	dropped map[string]int
}

// report is the job's line for a load.
func (st recentStats) report(full bool, cards int) string {
	kind := "new"
	if full {
		kind = "full"
	}
	line := fmt.Sprintf("%d cards, %d orders read (%s)", cards, st.rows, kind)
	if st.unmatched > 0 {
		line += fmt.Sprintf(", %d unmatched", st.unmatched)
	}
	if len(st.dropped) > 0 {
		names := make([]string, 0, len(st.dropped))
		for condition, n := range st.dropped {
			names = append(names, fmt.Sprintf("%q %d", condition, n))
		}
		sort.Strings(names)
		line += ", no grade for " + strings.Join(names, ", ")
	}
	return line
}

// recentBuilder keys rows by card and grade, on top of a base snapshot for
// an incremental load.
type recentBuilder struct {
	match  func(row recentRow) string
	added  map[string]*Recent
	pulled time.Time
	st     recentStats
}

// recentMatcher resolves an order to b's id for what it sold, "" for none: a
// sealed order's product through the sealed products, since only Magic's
// datastore matches a sealed id, and any other as the velocity does.
func recentMatcher(b *matcher.Backend) func(row recentRow) string {
	card := cardMatcher(b)
	sealed := b.BuildSealedProductMap("tcgplayerProductId")
	return func(row recentRow) string {
		if row.Condition != unopened {
			return card(row.ProductID, row.Variant)
		}
		// Two products under one id cannot be told apart: every sealed
		// order's variant is Normal, a foil drop's included.
		uuids := sealed[int(row.ProductID)]
		if len(uuids) != 1 {
			return ""
		}
		return uuids[0]
	}
}

// newRecentBuilder starts a load on top of base, nil for a full one.
func newRecentBuilder(base *RecentSnapshot, match func(row recentRow) string) *recentBuilder {
	rb := &recentBuilder{match: match, added: map[string]*Recent{}}
	if base != nil {
		rb.pulled = base.Pulled
	}
	return rb
}

// add files row under its card and grade, cutting a busy grade back to its
// newest as it grows.
func (rb *recentBuilder) add(row recentRow) {
	rb.st.rows++
	if row.Pulled.After(rb.pulled) {
		rb.pulled = row.Pulled
	}
	grade := gradeIndex(row.Condition)
	if grade < 0 {
		if rb.st.dropped == nil {
			rb.st.dropped = map[string]int{}
		}
		rb.st.dropped[row.Condition]++
		return
	}
	order, ok := newOrder(row)
	if !ok {
		rb.st.undated++
		return
	}
	cardID := rb.match(row)
	if cardID == "" {
		rb.st.unmatched++
		return
	}
	r := rb.added[cardID]
	if r == nil {
		r = &Recent{}
		rb.added[cardID] = r
	}
	r.Grades[grade] = append(r.Grades[grade], order)
	if len(r.Grades[grade]) >= 2*recentDepth {
		r.Grades[grade] = newestOrders(nil, r.Grades[grade])
	}
}

// snapshot is base with the cards the rows touched rebuilt; base is never changed.
func (rb *recentBuilder) snapshot(base *RecentSnapshot) *RecentSnapshot {
	cards := map[string]*Recent{}
	if base != nil {
		cards = maps.Clone(base.Cards)
	}
	for cardID, r := range rb.added {
		merged := &Recent{}
		old := cards[cardID]
		for i := range r.Grades {
			var kept []Order
			if old != nil {
				kept = old.Grades[i]
			}
			merged.Grades[i] = newestOrders(kept, r.Grades[i])
		}
		cards[cardID] = merged
	}
	return &RecentSnapshot{Cards: cards, Pulled: rb.pulled}
}

// newOrder is row as an Order, false when its date does not fit.
func newOrder(row recentRow) (Order, bool) {
	at := row.At.Unix()
	if at < 0 || at > math.MaxUint32 {
		return Order{}, false
	}
	cents := min(max(row.Cents, 0), math.MaxUint32)
	qty := min(max(row.Qty, 1), math.MaxUint16)
	h := fnv.New32a()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%d", row.ProductID, row.Variant, row.ListingID, row.At.Nanosecond())
	return Order{At: uint32(at), Cents: uint32(cents), ID: h.Sum32(), Qty: uint16(qty)}, true
}

// byNewest sorts orders newest first, then by price and copies, as the
// newspaper ranks them, then by identity so equal orders sit together.
type byNewest []Order

func (o byNewest) Len() int      { return len(o) }
func (o byNewest) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o byNewest) Less(i, j int) bool {
	if o[i].At != o[j].At {
		return o[i].At > o[j].At
	}
	if o[i].Cents != o[j].Cents {
		return o[i].Cents > o[j].Cents
	}
	if o[i].Qty != o[j].Qty {
		return o[i].Qty > o[j].Qty
	}
	return o[i].ID > o[j].ID
}

// newestOrders is kept and added together, each order once by its whole
// identity, newest first and at most recentDepth, in a new slice.
func newestOrders(kept, added []Order) []Order {
	if len(added) == 0 && len(kept) == 0 {
		return nil
	}
	all := make([]Order, 0, len(kept)+len(added))
	all = append(all, kept...)
	all = append(all, added...)
	sort.Sort(byNewest(all))
	out := all[:0]
	for i, o := range all {
		if i > 0 && o == all[i-1] {
			continue
		}
		out = append(out, o)
		if len(out) == recentDepth {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out[:len(out):len(out)]
}

// Line is one order as the Sales pane prints it: the date, and to the minute
// for its tooltip.
type Line struct {
	Date, Time string
	Source     string
	Price, Qty string
}

// recentSource is where every order here was sold.
const recentSource = "TCGplayer"

// Group is one grade's orders: the average price per copy over all of
// them, the newest RecentShown, then the rest. Link is where the store sells
// the card in this grade, filled by the caller, "" for a name with no link.
type Group struct {
	Grade       string
	Avg         string
	Shown, More []Line
	Link        string
}

// Groups is r's orders per grade in Grades' order; none for a grade with no
// order.
func (r *Recent) Groups() []Group {
	if r == nil {
		return nil
	}
	var groups []Group
	for i, orders := range r.Grades {
		if len(orders) == 0 {
			continue
		}
		g := Group{Grade: Grades[i], Avg: averageText(orders)}
		for j, o := range orders {
			line := orderLine(o)
			if j < RecentShown {
				g.Shown = append(g.Shown, line)
			} else {
				g.More = append(g.More, line)
			}
		}
		groups = append(groups, g)
	}
	return groups
}

// orderLine is o's date, where it sold, its price per copy and, above one
// copy, the copies.
func orderLine(o Order) Line {
	at := time.Unix(int64(o.At), 0).UTC()
	line := Line{
		Date:   at.Format(time.DateOnly),
		Time:   at.Format("2006-01-02 15:04 UTC"),
		Source: recentSource,
		Price:  centsText(uint64(o.Cents)),
	}
	if o.Qty > 1 {
		line.Qty = fmt.Sprintf("×%d", o.Qty)
	}
	return line
}

// averageText is the average price of one copy over orders, weighted by
// their copies.
func averageText(orders []Order) string {
	var cents, copies uint64
	for _, o := range orders {
		cents += uint64(o.Cents) * uint64(o.Qty)
		copies += uint64(o.Qty)
	}
	if copies == 0 {
		return ""
	}
	return centsText((cents + copies/2) / copies)
}

// centsText is cents as dollars, "12.34"; the page prints the sign.
func centsText(cents uint64) string {
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}
