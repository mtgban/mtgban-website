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
	// Days back the loader looks for the last day CK had stock, and the last
	// day it bought the card.
	ckHistoryWindow = 31
	// Yesterday's snapshot may be this many days old: a missed day or two
	// carries over, as in the backtest; more means the newspaper stopped.
	ckHistoryMaxAge = 3
	// The facts mention a buy price change this large (display only, not
	// measured).
	ckFactsPriceChange = 0.10
)

// Each state's verdict on a line of its own, then its chances two weeks on
// next to the usual ones, measured over March to August 2026. The tooltip
// sets what sits between ** marks in bold (js/tooltips.js).
const (
	ckTipSell = "**Sell now**: CK pays above its P90 and has stock.\n" +
		"Chances CK pays (two weeks from now):\n" +
		"• 5% more: **27%** instead of 33%\n" +
		"• 5% less or stops buying: **42%** instead of 35%"
	ckTipBuyout = "**Wait**: CK's stock halved since yesterday.\n" +
		"Chances CK pays (two weeks from now):\n" +
		"• 5% more: **51%** instead of 33%\n" +
		"• 5% less or stops buying: **27%** instead of 35%"
	ckTipOutOfStock = "**Wait**: CK is out of stock, at or below its P90.\n" +
		"Chances CK pays (two weeks from now):\n" +
		"• 5% more: **48%** instead of 33%\n" +
		"• 5% less or stops buying: **21%** instead of 35%"
	ckTipCut = "**Wait**: CK cut its buylist price 20% or more this week.\n" +
		"Chances CK pays (two weeks from now):\n" +
		"• 5% more: **48%** instead of 33%\n" +
		"• 5% less or stops buying: **42%** instead of 35%"
)

// A card CK is not buying sits on its last known buylist (CKBLLast) at the
// price CK lists for it. How long CK has had it paused predicts CK buying it
// again: the chances within 7 and 30 days, from the longest pause down,
// measured over January to August 2026 on cards CK last paid $1 or more for.
var ckPauseChances = []struct {
	MinDays     int
	Week, Month int
}{
	{30, 20, 58},
	{14, 32, 74},
	{7, 45, 83},
	{3, 52, 88},
	{0, 62, 92},
}

const (
	// Waiting for CK beats the other buylists while the pause is younger
	// than this, and only if every other cash offer is below this share of
	// the price CK lists.
	ckPauseWaitDays  = 14
	ckPauseWaitRatio = 0.95
	// The chances CK then comes back within 30 days paying 5% more than the
	// best of them, in the pause's first week and in its second.
	ckPauseWaitFirstWeek  = 76
	ckPauseWaitSecondWeek = 66
	// The wait arrow's own tooltip; the pill and the price carry the chances.
	ckPauseWaitTip = "**Wait**: don't undersell it elsewhere, CK's buylist may reopen."
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
	// Zero when CK bought the card on no day of the window.
	LastBuying time.Time
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
// ago, its buy price a week ago, and the last days it had stock and CK bought
// it in the past month. It reruns only when the day or the newspaper's newest snapshot
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
		       MAX(date) FILTER (WHERE quantity_selling > 0),
		       MAX(date) FILTER (WHERE quantity_buying > 0)
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
		var lastInStock, lastBuying sql.NullTime
		err := rows.Scan(&id, &stockYesterday, &stockWeekAgo, &buyWeekAgo, &lastInStock, &lastBuying)
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
			LastBuying:        lastBuying.Time,
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
	// Set instead on a card CK is not buying.
	Pause ckPause
}

// ckPause is a card CK has paused: the pill on its last known offer, whether
// waiting for CK beats every other cash offer, and the tooltip behind both.
type ckPause struct {
	Label string
	Wait  bool
	Tip   string
}

// ckPauseFor tells how long CK has had a card paused, from the last day it
// bought it, and the chances of CK buying it again. listed is CK's price for
// it and others the other cash buylists' NM offers.
func ckPauseFor(listed float64, h ckHistory, today time.Time, others []float64) ckPause {
	if listed < ckMinBuyPrice {
		return ckPause{}
	}
	// The pause began the day after the last one CK bought the card; none in
	// the window means it began before the window did.
	days := ckHistoryWindow
	if !h.LastBuying.IsZero() {
		days = max(int(today.Sub(h.LastBuying).Hours()/24)-1, 0)
	}
	chances := ckPauseChances[len(ckPauseChances)-1]
	for _, c := range ckPauseChances {
		if days >= c.MinDays {
			chances = c
			break
		}
	}

	var p ckPause
	since := strconv.Itoa(days) + " days ago"
	switch {
	case days >= 30:
		p.Label, since = "Paused 30d+", "30+ days ago"
	case days == 0:
		p.Label, since = "Paused today", "today"
	case days == 1:
		p.Label, since = "Paused 1d", "yesterday"
	default:
		p.Label = "Paused " + strconv.Itoa(days) + "d"
	}

	best := 0.0
	for _, price := range others {
		best = max(best, price)
	}
	p.Wait = days < ckPauseWaitDays && best > 0 && best < listed*ckPauseWaitRatio

	verdict := "**Paused**: CK stopped buying this card " + since + "."
	if p.Wait {
		verdict = "**Wait**: CK stopped buying this card " + since +
			", and every other cash offer is 5%+ below the price it lists."
	}
	lines := []string{
		verdict,
		"Chances CK buys it again:",
		fmt.Sprintf("• within a week: **%d%%**", chances.Week),
		fmt.Sprintf("• within 30 days: **%d%%**", chances.Month),
	}
	if p.Wait {
		wait := ckPauseWaitFirstWeek
		if days >= 7 {
			wait = ckPauseWaitSecondWeek
		}
		lines = append(lines, fmt.Sprintf("• within 30 days, paying 5%% more than the best other offer: **%d%%**", wait))
	}
	p.Tip = strings.Join(lines, "\n")
	return p
}

// ckCashBuylist tells whether a vendor is a store's cash buylist, one a
// seller could take instead of waiting for CK: not CK's own, a credit list,
// sealed product, a list of wants or TCGplayer's marketplace payout.
func ckCashBuylist(info mtgban.ScraperInfo) bool {
	switch info.Shorthand {
	case "CK", "CKBLLast", "ABUCredit", "TCGDirectNet":
		return false
	}
	return !info.SealedMode && !info.MetadataOnly
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

// ckFacts describes CK's stock and recent buy price, e.g. "**CK stock**: 0 - out
// 9 days · buylist −25% this week". Unlike the rules it shows whatever is known.
func ckFacts(q ckQuote, h ckHistory, hasHistory bool, today time.Time) string {
	var parts []string
	if q.StockKnown {
		stock := "**CK stock**: " + strconv.Itoa(q.Stock)
		switch {
		case q.Stock == 0 && hasHistory && h.LastInStock.IsZero():
			stock += fmt.Sprintf(" - out %d+ days", ckHistoryWindow-1)
		case q.Stock == 0 && hasHistory:
			days := int(today.Sub(h.LastInStock).Hours() / 24)
			stock += " - out " + strconv.Itoa(days) + " day"
			if days != 1 {
				stock += "s"
			}
		case q.Stock > 0 && hasHistory && h.HasStockWeekAgo:
			stock += fmt.Sprintf(" - it was %d a week ago", h.StockWeekAgo)
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

// joinLines joins the lines that are not empty, one per line.
func joinLines(lines ...string) string {
	var kept []string
	for _, line := range lines {
		if line != "" {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// ckReferencePrices is CK's P90 and 90-day high on one line, or "".
func ckReferencePrices(good, highest float64) string {
	var parts []string
	if good > 0 {
		parts = append(parts, fmt.Sprintf("**P90**: $ %.2f", good))
	}
	if highest > 0 {
		parts = append(parts, fmt.Sprintf("**90d high**: $ %.2f", highest))
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

// ckSignalsPtr holds the signal of every card CK is buying, and the pause
// of every card it is not.
var ckSignalsPtr atomic.Pointer[map[string]ckSignal]

// ckSignalsMu runs one rebuild at a time, so the last one to start, which
// read the newest inputs, is the last one to publish.
var ckSignalsMu sync.Mutex

// rebuildCKSignals computes every card's signal from CK's live buylist and
// stock, the loaded history and the P90s, and every paused card's chances
// from its history and the other cash buylists. It runs when CK's data, the
// history or the P90s change, and hourly because the rules and facts count
// days and the other buylists reload.
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

	lastKnown, _ := findVendorBuylist("CKBLLast")
	var cash []mtgban.BuylistRecord
	for _, vendor := range GetVendors() {
		if ckCashBuylist(vendor.Info()) {
			cash = append(cash, vendor.Buylist())
		}
	}
	for cardID, entries := range lastKnown {
		q := ckQuoteFrom(entries, nil, false)
		if q.ID == "" || ckQuoteFrom(offers[cardID], nil, false).Buying {
			continue
		}
		h, found := history.historyFor(q.ID, today)
		if !found {
			continue
		}
		var others []float64
		for _, record := range cash {
			for _, entry := range record[cardID] {
				if entry.Conditions == "NM" {
					others = append(others, entry.BuyPrice)
					break
				}
			}
		}
		pause := ckPauseFor(q.Buy, h, today, others)
		if pause.Label != "" {
			signals[cardID] = ckSignal{Pause: pause}
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
