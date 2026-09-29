package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Card Kingdom's buylist moves with its retail stock: CK pays more for cards
// it has sold out of and trims the ones it is restocking. These signals
// combine CK's live buylist and stock with a month of the newspaper's daily
// snapshots of CK's price list; docs/adr/0004-ck-buylist-signals.md has the
// measurements behind every threshold and tooltip below.

const (
	// The rules fire only where they were measured: CK buying the card at $1
	// or more, and the card having a P90.
	ckMinBuyPrice = 1.0
	// A buyout is stock at half or less of yesterday's, from at least this.
	ckBuyoutMinStock = 3
	// A cut is a buy price at this share or less of the one a week before.
	ckCutRatio = 0.8
	// Days back the loader looks for the last day CK had stock.
	ckHistoryWindow = 31
	// Yesterday's snapshot may be this many days old: a missed day or two
	// carries over, as in the backtest; more means the newspaper stopped.
	ckHistoryMaxAge = 3
	// The facts mention a buy price change this large (display only, not
	// measured).
	ckFactsPriceChange = 0.10
)

// The odds each state carries, measured over March to August 2026.
const (
	ckTipSell       = "Above CK's P90 with CK in stock. Two weeks later CK paid 5% more only 27% of the time, and 5% less or stopped buying 42% of the time (typical: 33% and 35%)."
	ckTipBuyout     = "CK's stock halved since yesterday. Two weeks later CK paid 5% more 51% of the time (typical: 33%); the effect fades in two to three days."
	ckTipOutOfStock = "CK is out of stock and paying its P90 or less. Two weeks later CK paid 5% more 48% of the time, and 5% less only 21% of the time (typical: 33% and 35%)."
	ckTipCut        = "CK cut its buy price 20% or more this week. Two weeks later it paid 5% more 48% of the time (typical: 33%), though 20% of these cards stop being bought."
)

// ckHistory is what the newspaper's snapshots say about one CK product.
type ckHistory struct {
	StockYesterday    int
	HasStockYesterday bool
	StockWeekAgo      int
	HasStockWeekAgo   bool
	BuyWeekAgo        float64
	HasBuyWeekAgo     bool
	// Zero when CK had no stock anywhere in the window.
	LastInStock time.Time
}

// ckHistorySnapshot is one load of the history, keyed by CK's product id.
type ckHistorySnapshot struct {
	Today     time.Time // the UTC day it was loaded for
	Latest    time.Time // the newest snapshot in the table then
	Yesterday time.Time // the snapshot read as yesterday
	Products  map[string]ckHistory
}

var ckHistoryPtr atomic.Pointer[ckHistorySnapshot]

// ckHistoryLoading gates concurrent loads (startup and cron).
var ckHistoryLoading atomic.Bool

// ckToday is the UTC day the newspaper dates its snapshots by.
func ckToday(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// loadCKHistory reads, for every CK product, its stock yesterday and a week
// ago, its buy price a week ago, and the last day it had stock in the past
// month. It reruns only when the day or the newspaper's newest snapshot
// changed, and keeps the last good load on any error.
func (s *site) loadCKHistory() {
	if Config.Game != DefaultGame || SkipNewspaper || NewNewspaperDB == nil {
		return
	}
	if !ckHistoryLoading.CompareAndSwap(false, true) {
		return
	}
	defer ckHistoryLoading.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	today := ckToday(time.Now())
	latest, err := ckSnapshotOnOrBefore(ctx, today)
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	current := ckHistoryPtr.Load()
	if current != nil && current.Today.Equal(today) && current.Latest.Equal(latest) {
		return
	}

	yesterday, err := ckSnapshotOnOrBefore(ctx, today.AddDate(0, 0, -1))
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	if yesterday.IsZero() || today.Sub(yesterday) > ckHistoryMaxAge*24*time.Hour {
		log.Println("ck history: no snapshot recent enough, newest before today is", yesterday.Format(time.DateOnly))
		return
	}
	weekAgo, err := ckSnapshotOnOrBefore(ctx, today.AddDate(0, 0, -7))
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	var weekAgoDate sql.NullTime
	if !weekAgo.IsZero() && today.Sub(weekAgo) <= (7+ckHistoryMaxAge-1)*24*time.Hour {
		weekAgoDate = sql.NullTime{Time: weekAgo, Valid: true}
	}

	// One row per product: the newspaper writes CK's whole list each day, so
	// a date present in the table is present for every product CK lists.
	rows, err := NewNewspaperDB.QueryContext(ctx, `
		SELECT ck_id,
		       MAX(quantity_selling) FILTER (WHERE date = $2),
		       MAX(quantity_selling) FILTER (WHERE date = $3),
		       MAX(price_buy) FILTER (WHERE date = $3),
		       MAX(date) FILTER (WHERE quantity_selling > 0)
		  FROM cardkingdomproductmodel
		 WHERE date >= $1 AND date <= $2
		 GROUP BY ck_id`, today.AddDate(0, 0, -ckHistoryWindow), yesterday, weekAgoDate)
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	defer rows.Close()

	products := map[string]ckHistory{}
	for rows.Next() {
		var id int64
		var stockYesterday, stockWeekAgo sql.NullInt64
		var buyWeekAgo sql.NullFloat64
		var lastInStock sql.NullTime
		err := rows.Scan(&id, &stockYesterday, &stockWeekAgo, &buyWeekAgo, &lastInStock)
		if err != nil {
			log.Println("ck history:", err)
			return
		}
		products[strconv.FormatInt(id, 10)] = ckHistory{
			StockYesterday:    int(stockYesterday.Int64),
			HasStockYesterday: stockYesterday.Valid,
			StockWeekAgo:      int(stockWeekAgo.Int64),
			HasStockWeekAgo:   stockWeekAgo.Valid,
			BuyWeekAgo:        buyWeekAgo.Float64,
			HasBuyWeekAgo:     buyWeekAgo.Valid,
			LastInStock:       lastInStock.Time,
		}
	}
	err = rows.Err()
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	if len(products) == 0 {
		log.Println("ck history: no products, keeping the previous load")
		return
	}

	ckHistoryPtr.Store(&ckHistorySnapshot{
		Today:     today,
		Latest:    latest,
		Yesterday: yesterday,
		Products:  products,
	})
	log.Println("ck history: loaded", len(products), "products, yesterday is", yesterday.Format(time.DateOnly))
}

// ckSnapshotOnOrBefore returns the newest snapshot date on or before day, or
// the zero time when there is none.
func ckSnapshotOnOrBefore(ctx context.Context, day time.Time) (time.Time, error) {
	var date sql.NullTime
	err := NewNewspaperDB.QueryRowContext(ctx,
		`SELECT MAX(date) FROM cardkingdomproductmodel WHERE date <= $1`, day).Scan(&date)
	return date.Time, err
}

// historyFor returns a CK product's history, when the snapshot is recent
// enough to trust. Yesterday's stock counts only in a snapshot loaded today:
// in one loaded the day before, "yesterday" is two days back.
func (snap *ckHistorySnapshot) historyFor(id string, today time.Time) (ckHistory, bool) {
	if snap == nil || id == "" || today.Sub(snap.Yesterday) > ckHistoryMaxAge*24*time.Hour {
		return ckHistory{}, false
	}
	h, found := snap.Products[id]
	if found && !snap.Today.Equal(today) {
		h.StockYesterday, h.HasStockYesterday = 0, false
	}
	return h, found
}

// ckQuote is CK's live offer and stock for one card.
type ckQuote struct {
	ID         string // CK's product id
	Buy        float64
	Buying     bool
	Stock      int // across conditions
	StockKnown bool
}

// ckSignal is a card's state on CK's buylist: "sell" when CK's offer is worth
// taking now, "wait" when CK is likely to pay more soon, "" otherwise, with
// the odds behind it and a line of facts about CK's stock and price.
type ckSignal struct {
	State string
	Tip   string
	Facts string
}

// ckSignalFor applies the rules of ADR-0004. Wait wins over sell, and the
// wait reasons are checked in the order they were measured. Without history
// only out of stock can mean wait, and sell skips its buyout check.
func ckSignalFor(q ckQuote, h ckHistory, hasHistory bool, good float64, today time.Time) ckSignal {
	if !q.Buying {
		return ckSignal{}
	}
	sig := ckSignal{Facts: ckFacts(q, h, hasHistory, today)}
	if q.Buy < ckMinBuyPrice || good <= 0 {
		return sig
	}

	buyout := hasHistory && h.HasStockYesterday && h.StockYesterday >= ckBuyoutMinStock &&
		q.StockKnown && q.Stock*2 <= h.StockYesterday
	outOfStock := q.StockKnown && q.Stock == 0 && q.Buy <= good
	cut := hasHistory && h.HasBuyWeekAgo && h.BuyWeekAgo > 0 && q.Buy <= h.BuyWeekAgo*ckCutRatio

	switch {
	case buyout:
		sig.State, sig.Tip = "wait", ckTipBuyout
	case outOfStock:
		sig.State, sig.Tip = "wait", ckTipOutOfStock
	case cut:
		sig.State, sig.Tip = "wait", ckTipCut
	case q.StockKnown && q.Stock > 0 && q.Buy > good:
		sig.State, sig.Tip = "sell", ckTipSell
	}
	return sig
}

// ckFacts describes CK's stock and recent buy price, e.g. "CK stock 0 · out 9
// days · buylist −25% this week". Unlike the rules it shows whatever is known.
func ckFacts(q ckQuote, h ckHistory, hasHistory bool, today time.Time) string {
	var parts []string
	if q.StockKnown {
		stock := "CK stock " + strconv.Itoa(q.Stock)
		switch {
		case q.Stock == 0 && hasHistory && h.LastInStock.IsZero():
			stock += fmt.Sprintf(" · out %d+ days", ckHistoryWindow-1)
		case q.Stock == 0 && hasHistory:
			days := int(today.Sub(h.LastInStock).Hours() / 24)
			stock += " · out " + strconv.Itoa(days) + " day"
			if days != 1 {
				stock += "s"
			}
		case q.Stock > 0 && hasHistory && h.HasStockWeekAgo:
			stock += fmt.Sprintf(" · %d a week ago", h.StockWeekAgo)
		}
		parts = append(parts, stock)
	}
	if hasHistory && h.HasBuyWeekAgo && h.BuyWeekAgo > 0 {
		change := q.Buy/h.BuyWeekAgo - 1
		if math.Abs(change) >= ckFactsPriceChange {
			sign := "+"
			if change < 0 {
				sign = "−"
			}
			parts = append(parts, fmt.Sprintf("buylist %s%.0f%% this week", sign, math.Abs(change)*100))
		}
	}
	return strings.Join(parts, " · ")
}

// ckQuoteFrom reads CK's offer for a card from its buylist entries and its
// stock from its inventory entries. CK's buylist keeps entries for cards it
// is not buying, with no quantity, so buying needs a quantity as well as a
// price.
func ckQuoteFrom(offers []mtgban.BuylistEntry, stock []mtgban.InventoryEntry, stockKnown bool) ckQuote {
	var q ckQuote
	for _, entry := range offers {
		if entry.Conditions != "NM" {
			continue
		}
		q.ID = entry.OriginalID
		q.Buy = entry.BuyPrice
		q.Buying = entry.Quantity > 0 && entry.BuyPrice > 0
		break
	}
	q.StockKnown = stockKnown
	if stockKnown {
		for _, entry := range stock {
			q.Stock += entry.Quantity
		}
	}
	return q
}

// ckSignalsPtr holds the signal of every card CK is buying.
var ckSignalsPtr atomic.Pointer[map[string]ckSignal]

// ckSignalsMu runs one rebuild at a time, so the last one to start, which
// read the newest inputs, is the last one to publish.
var ckSignalsMu sync.Mutex

// rebuildCKSignals computes every card's signal from CK's live buylist and
// stock, the loaded history and the P90s. It runs when any of them changes,
// and hourly because the rules and facts count days.
func rebuildCKSignals() {
	ckSignalsMu.Lock()
	defer ckSignalsMu.Unlock()

	offers, _ := findVendorBuylist("CK")
	// A missing inventory leaves stock unknown rather than zero.
	stock, err := findSellerInventory("CK")
	stockKnown := err == nil && len(stock) > 0
	good := GetInfos()["goodP90"]
	history := ckHistoryPtr.Load()
	today := ckToday(time.Now())

	signals := map[string]ckSignal{}
	for cardID, entries := range offers {
		q := ckQuoteFrom(entries, stock[cardID], stockKnown)
		if !q.Buying {
			continue
		}
		var p90 float64
		if len(good[cardID]) > 0 {
			p90 = good[cardID][0].Price
		}
		h, found := history.historyFor(q.ID, today)
		sig := ckSignalFor(q, h, found, p90, today)
		if sig != (ckSignal{}) {
			signals[cardID] = sig
		}
	}
	ckSignalsPtr.Store(&signals)
}

// refreshCKSignals reloads the history when the newspaper has a new day, and
// rebuilds the signals either way.
func (s *site) refreshCKSignals() {
	s.loadCKHistory()
	rebuildCKSignals()
}

// ckSignalForCard is a card's CK signal as of the last rebuild.
func ckSignalForCard(cardID string) ckSignal {
	signals := ckSignalsPtr.Load()
	if signals == nil {
		return ckSignal{}
	}
	return (*signals)[cardID]
}
