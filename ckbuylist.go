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
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/jobs"
)

// Card Kingdom pays one of a short list of prices at each retail price, and
// moves up and down that list with how many copies it needs; its retail
// carries the moves that last. These signals read CK's live buylist and
// stock, a month of the newspaper's daily snapshots of CK's list, and the odds
// file ckodds writes; docs/adr/0004-ck-buylist-signals.md has the rules.

const (
	// The signals apply where CK pays this much or more.
	ckMinBuyPrice = 3.0
	// A halving is of a stock of at least this.
	ckHalvedFrom = 3
	// TCG Market up this much over a week is a wait.
	ckMarketRise = 1.10
	// CK's retail at this many times TCG Market is a sell.
	ckPremiumSell = 2.0
	// A set this many days past its release, up to ckNewSetTo, is a sell.
	ckNewSetFrom = 28
	ckNewSetTo   = 55
	// So is a reprint (Modern Horizons-type, Commander, Masters) released this
	// many days ago or less.
	ckReprintDays = 60
	// Days back the loader looks for the last day CK had stock.
	ckHistoryWindow = 31
	// Days back it looks for the last day CK bought the card: one CK bought
	// on none of them has no pause, as CK never bought it.
	ckBoughtLookback = 365
	// Yesterday's snapshot may be this many days old: a missed day or two
	// carries over; more means the newspaper stopped.
	ckHistoryMaxAge = 3
)

// ckReasons are the first line of a verdict's tooltip, by the rule that gave
// it; the chances of the card's cell follow. The tooltip sets what sits
// between ** marks in bold (js/tooltips.js).
var ckReasons = map[string]string{
	"halved":     "**Wait**: CK's stock halved since yesterday.",
	"soldout":    "**Wait**: CK sold out today.",
	"marketrose": "**Wait**: TCG Market rose 10%+ this week.",
	"newset":     "**Sell now**: its set came out 4-7 weeks ago.",
	"reprinted":  "**Sell now**: reprinted in the last 60 days.",
	"premium":    "**Sell now**: CK sells it at 2x TCG Market.",
}

// ckNewHighVerdict is the New high pill's tooltip, before its chances.
const ckNewHighVerdict = "**New high**: Card Kingdom just beat every price of the last 90 days."

// ckPauseWaitTip is the wait arrow's own tooltip on a paused card; the pill
// and the price carry the chances.
const ckPauseWaitTip = "**Wait**: don't undersell it elsewhere, CK's buylist may reopen soon."

// ckHistory is what the newspaper's snapshots say about one CK product.
type ckHistory struct {
	StockYesterday    int
	HasStockYesterday bool
	StockWeekAgo      int
	HasStockWeekAgo   bool
	// CK's NM retail yesterday, which the newspaper has out of stock too.
	RetailYesterday float64
	// Zero when CK had no stock anywhere in the window.
	LastInStock time.Time
	// Zero when CK bought the card on no day of the past year.
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

// loadCKHistory reads, for every CK product, its stock and retail yesterday,
// its stock a week ago, the last day it had stock in the past month and the
// last day CK bought it in the past year. It reruns only when the day or the
// newspaper's newest snapshot changed, and keeps the last good load on any
// error.
func (s *site) loadCKHistory() {
	if SkipNewspaper || NewNewspaperDB == nil {
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
		       MAX(price_retail_nm) FILTER (WHERE date = $2),
		       MAX(quantity_selling) FILTER (WHERE date = $3),
		       MAX(date) FILTER (WHERE quantity_selling > 0 AND date >= $4),
		       MAX(date) FILTER (WHERE quantity_buying > 0)
		  FROM cardkingdomproductmodel
		 WHERE date >= $1 AND date <= $2
		 GROUP BY ck_id`, today.AddDate(0, 0, -ckBoughtLookback), yesterday, weekAgoDate,
		today.AddDate(0, 0, -ckHistoryWindow))
	if err != nil {
		log.Println("ck history:", err)
		return
	}
	defer rows.Close()

	products := map[string]ckHistory{}
	for rows.Next() {
		var id int64
		var stockYesterday, stockWeekAgo sql.NullInt64
		var retailYesterday sql.NullFloat64
		var lastInStock, lastBuying sql.NullTime
		err := rows.Scan(&id, &stockYesterday, &retailYesterday, &stockWeekAgo, &lastInStock, &lastBuying)
		if err != nil {
			log.Println("ck history:", err)
			return
		}
		products[strconv.FormatInt(id, 10)] = ckHistory{
			StockYesterday:    int(stockYesterday.Int64),
			HasStockYesterday: stockYesterday.Valid,
			StockWeekAgo:      int(stockWeekAgo.Int64),
			HasStockWeekAgo:   stockWeekAgo.Valid,
			RetailYesterday:   retailYesterday.Float64,
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

// ckQuote is CK's live offer, stock and retail for one card.
type ckQuote struct {
	ID         string // CK's product id
	Buy        float64
	Buying     bool
	Stock      int // across conditions
	StockKnown bool
	Retail     float64 // NM; zero while CK has none
}

// ckRuleFor applies the rules of ADR-0004 to a card CK buys: it returns
// "wait" or "sell" and the rule that gave it (a key of ckReasons), or
// nothing. Wait wins over sell. retail is CK's NM retail, live or else
// yesterday's.
func ckRuleFor(q ckQuote, h ckHistory, hasHistory bool, p ckProduct, retail float64, today time.Time) (string, string) {
	if !q.Buying || q.Buy < ckMinBuyPrice {
		return "", ""
	}
	yesterday := hasHistory && h.HasStockYesterday && q.StockKnown
	switch {
	case yesterday && h.StockYesterday > 0 && q.Stock == 0:
		return "wait", "soldout"
	case yesterday && h.StockYesterday >= ckHalvedFrom && q.Stock*2 <= h.StockYesterday:
		return "wait", "halved"
	case p.MarketWeekAgo > 0 && p.Market >= ckMarketRise*p.MarketWeekAgo:
		return "wait", "marketrose"
	}
	day := 24 * time.Hour
	switch {
	case !p.SetReleased.IsZero() && today.Sub(p.SetReleased) >= ckNewSetFrom*day && today.Sub(p.SetReleased) <= ckNewSetTo*day:
		return "sell", "newset"
	case !p.Reprinted.IsZero() && !today.Before(p.Reprinted) && today.Sub(p.Reprinted) <= ckReprintDays*day:
		return "sell", "reprinted"
	case p.Market > 0 && retail >= ckPremiumSell*p.Market:
		return "sell", "premium"
	}
	return "", ""
}

// ckFacts are CK's stock and TCG Market's as a tooltip's label rows, e.g.
// "|CK stock|0, out 9 days", "|TCG Market|+12% this week" and "|CK retail|1.4x
// TCG Market". Unlike the rules they show whatever is known.
func ckFacts(q ckQuote, h ckHistory, hasHistory bool, p ckProduct, retail float64, today time.Time) string {
	var lines []string
	if q.StockKnown {
		stock := "|CK stock|" + strconv.Itoa(q.Stock)
		switch {
		case q.Stock == 0 && hasHistory && h.LastInStock.IsZero():
			stock += fmt.Sprintf(", out %d+ days", ckHistoryWindow-1)
		case q.Stock == 0 && hasHistory:
			days := int(today.Sub(h.LastInStock).Hours() / 24)
			stock += ", out " + strconv.Itoa(days) + " day"
			if days != 1 {
				stock += "s"
			}
		case q.Stock > 0 && hasHistory && h.HasStockWeekAgo:
			stock += fmt.Sprintf(", it was %d a week ago", h.StockWeekAgo)
		}
		lines = append(lines, stock)
	}
	if p.Market > 0 && p.MarketWeekAgo > 0 {
		change := math.Round((p.Market/p.MarketWeekAgo - 1) * 100)
		move := "flat this week"
		if change != 0 {
			move = fmt.Sprintf("%+.0f%% this week", change)
		}
		lines = append(lines, "|TCG Market|"+move)
	}
	if p.Market > 0 && retail > 0 {
		lines = append(lines, fmt.Sprintf("|CK retail|%.1fx TCG Market", retail/p.Market))
	}
	return strings.Join(lines, "\n")
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

// ckReferencePrices is CK's P90 and 90-day high as a tooltip's label rows,
// or "".
func ckReferencePrices(good, highest float64) string {
	var rows []string
	if good > 0 {
		rows = append(rows, fmt.Sprintf("|P90|$ %.2f", good))
	}
	if highest > 0 {
		rows = append(rows, fmt.Sprintf("|90d high|$ %.2f", highest))
	}
	return strings.Join(rows, "\n")
}

// ckPause is a card CK has paused: for how many days, the chances in percent
// of CK buying it again within 30 days (Back) and of it then paying more than
// the best other cash offer (Beat), -1 where unknown, and whether to wait.
type ckPause struct {
	Paused     bool
	Days       int
	Back, Beat int
	Wait       bool
}

// ckPauseDays is how long CK has had a card paused, from the last day it
// bought it; false for a card CK did not buy in the past year.
func ckPauseDays(h ckHistory, today time.Time) (int, bool) {
	if h.LastBuying.IsZero() {
		return 0, false
	}
	// The pause began the day after the last one CK bought the card.
	return max(int(today.Sub(h.LastBuying).Hours()/24)-1, 0), true
}

// ckPauseFor is a pause of days on a card CK lists at listed, against the
// other cash buylists' NM offers, with the chances of its finish and age.
// It says wait when CK is more likely than not to come back within 30 days
// paying more than the best of them.
func ckPauseFor(listed float64, days int, others []float64, reopen *ckReopen) ckPause {
	p := ckPause{Paused: true, Days: days, Back: -1, Beat: -1}
	if reopen == nil {
		return p
	}
	p.Back = reopen.BackMonth
	best := 0.0
	for _, price := range others {
		best = max(best, price)
	}
	if best <= 0 || listed <= 0 || len(reopen.Deciles) == 0 {
		return p
	}
	// The deciles of CK's price on coming back over the price it lists.
	above := 0
	for _, ratio := range reopen.Deciles {
		if ratio*listed > best {
			above++
		}
	}
	p.Beat = int(math.Round(float64(reopen.BackMonth*above) / 10))
	p.Wait = p.Beat > 50
	return p
}

// ckPauseLabel is the pill of a pause that has lasted days.
func ckPauseLabel(days int) string {
	switch {
	case days >= 30:
		return "Paused 30d+"
	case days == 0:
		return "Paused today"
	}
	return "Paused " + strconv.Itoa(days) + "d"
}

// ckPauseTip is a pause's tooltip: since when, and the chances CK buys the
// card again within 30 days and pays more than the best other offer then.
func ckPauseTip(p ckPause) string {
	since := strconv.Itoa(p.Days) + " days ago"
	switch {
	case p.Days >= 30:
		since = "30+ days ago"
	case p.Days == 0:
		since = "today"
	case p.Days == 1:
		since = "yesterday"
	}
	verdict := "**Paused**: CK stopped buying this card " + since + "."
	if p.Wait {
		verdict = "**Wait**: CK stopped buying this card " + since + "."
	}
	var back, beat string
	if p.Back >= 0 {
		back = fmt.Sprintf("| CK buys it again | **%d%%**", p.Back)
	}
	if p.Beat >= 0 {
		beat = fmt.Sprintf("| Paying more than any other offer | **%d%%**", p.Beat)
	}
	if back == "" && beat == "" {
		return verdict
	}
	return joinLines(verdict, "|# Within a month | Chance", back, beat)
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

// ckQuoteFrom reads CK's offer for a card from its buylist entries, and its
// stock and NM retail from its inventory entries. CK's buylist keeps entries
// for cards it is not buying, with no quantity, so buying needs a quantity as
// well as a price. Its inventory keeps one for a card it has none of, a link
// with no price that the record files as one copy, so stock counts priced
// ones.
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
			if entry.Price > 0 {
				q.Stock += entry.Quantity
				if entry.Conditions == "NM" {
					q.Retail = entry.Price
				}
			}
		}
	}
	return q
}

// ckView is a card's CK signal as the pages show it, written by a rebuild.
type ckView struct {
	State      string // "sell", "wait" or ""
	Tip        string // the rule's reason, then the chances of its cell
	Facts      string
	PauseLabel string
	PauseWait  bool
	PauseTip   string
	NewHighTip string
}

// ckSignalsPtr holds the view of every card CK is buying at the floor or
// has paused, by card id.
var ckSignalsPtr atomic.Pointer[map[string]ckView]

// ckSignalsMu runs one rebuild at a time, so the last one to start, which
// read the newest inputs, is the last one to publish.
var ckSignalsMu sync.Mutex

// ckCellOf is where a CK product's chances are read: its group, finish and
// retail band, every band where its retail is unknown.
func ckCellOf(p ckProduct, retail float64) (group, finish, bucket string) {
	group, finish, bucket = "cohort", "nonfoil", "all"
	if p.Exception {
		group = "exceptions"
	}
	if p.Foil {
		finish = "foil"
	}
	if retail > 0 {
		bucket = ckBucketOf(retail)
	}
	return group, finish, bucket
}

// ckViewFor writes a buying card's view: its facts, and its verdict and New
// high with the chances of its cell. A verdict whose cell the odds do not
// list is not shown, nor one on a product they do not know.
func ckViewFor(q ckQuote, h ckHistory, hasHistory bool, odds *ckOdds, newHigh bool, today time.Time) ckView {
	p, known := odds.product(q.ID)
	retail := q.Retail
	if retail <= 0 && hasHistory {
		retail = h.RetailYesterday
	}
	v := ckView{Facts: ckFacts(q, h, hasHistory, p, retail, today)}
	if newHigh && q.Buy >= ckMinBuyPrice {
		v.NewHighTip = ckNewHighVerdict
	}
	if !known {
		return v
	}
	group, finish, bucket := ckCellOf(p, retail)
	verdict, reason := ckRuleFor(q, h, hasHistory, p, retail, today)
	if verdict != "" {
		cell, chances, typical, found := odds.chancesFor(group, finish, bucket, verdict)
		if found {
			v.State = verdict
			v.Tip = ckReasons[reason] + "\n" + ckChanceLines(cell, chances, typical)
		}
	}
	if v.NewHighTip != "" {
		cell, chances, typical, found := odds.chancesFor(group, finish, bucket, "newhigh")
		if found {
			v.NewHighTip += "\n" + ckChanceLines(cell, chances, typical)
		}
	}
	return v
}

// rebuildCKSignals writes every card's view from CK's live buylist, stock
// and retail, the loaded history and odds and the new highs, and every paused
// card's from its history, the odds and the other cash buylists. It runs when
// CK's data, the history or the new highs change, and hourly because the
// rules and facts count days and the other buylists reload.
func rebuildCKSignals() {
	if !ckAvailable() {
		return
	}
	ckSignalsMu.Lock()
	defer ckSignalsMu.Unlock()

	offers, _ := findVendorBuylist("CK")
	// A missing inventory leaves stock unknown rather than zero.
	stock, err := findSellerInventory("CK")
	stockKnown := err == nil && len(stock) > 0
	newHighs := GetInfos()["newhigh"]
	history := ckHistoryPtr.Load()
	odds := ckOddsPtr.Load()
	today := ckToday(time.Now())

	signals := map[string]ckView{}
	for cardID, entries := range offers {
		q := ckQuoteFrom(entries, stock[cardID], stockKnown)
		if !q.Buying || q.Buy < ckMinBuyPrice {
			continue
		}
		h, found := history.historyFor(q.ID, today)
		_, newHigh := newHighs[cardID]
		v := ckViewFor(q, h, found, odds, newHigh, today)
		if v != (ckView{}) {
			signals[cardID] = v
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
		if q.ID == "" || q.Buy < ckMinBuyPrice || ckQuoteFrom(offers[cardID], nil, false).Buying {
			continue
		}
		h, found := history.historyFor(q.ID, today)
		if !found {
			continue
		}
		days, paused := ckPauseDays(h, today)
		if !paused {
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
		// A product the odds do not know has no finish to read chances for.
		var reopen *ckReopen
		p, known := odds.product(q.ID)
		if known {
			_, finish, _ := ckCellOf(p, 0)
			reopen = odds.reopenFor(finish, days)
		}
		pause := ckPauseFor(q.Buy, days, others, reopen)
		signals[cardID] = ckView{PauseLabel: ckPauseLabel(days), PauseWait: pause.Wait, PauseTip: ckPauseTip(pause)}
	}
	ckSignalsPtr.Store(&signals)
	result, problem := ckSignalsReport(signals, history, odds, time.Now())
	backgroundJobs.Report(jobCKSignals, result, problem)
}

// ckAvailable tells whether this site serves Card Kingdom's buylist, which
// everything here starts from: the history, the odds and the signals are
// loaded and built only where it does.
func ckAvailable() bool {
	_, err := findVendorBuylist("CK")
	return err == nil
}

// ckOddsMaxStale is how old the odds may get: ckodds runs daily, so a day
// and a half means a run was missed.
const ckOddsMaxStale = 36 * time.Hour

// ckSignalsReport is what a rebuild of CK's signals found, and what is wrong
// with its inputs or with it: no stock history, or one a day behind; no odds,
// or odds a missed run old; not one sell now or wait.
func ckSignalsReport(signals map[string]ckView, history *ckHistorySnapshot, odds *ckOdds, now time.Time) (string, string) {
	var sell, wait, paused int
	for _, v := range signals {
		switch v.State {
		case "sell":
			sell++
		case "wait":
			wait++
		}
		if v.PauseLabel != "" {
			paused++
		}
	}
	result := fmt.Sprintf("%d sell now, %d wait, %d paused, of %d cards", sell, wait, paused, len(signals))
	var problem string
	switch {
	case history == nil:
		problem = "have no stock history"
	case ckToday(now).Sub(history.Today) > 24*time.Hour:
		problem = "read a stock history from " + history.Today.Format(time.DateOnly)
	case odds == nil:
		problem = "have no odds"
	case now.Sub(odds.Generated) > ckOddsMaxStale:
		problem = "quote odds " + jobs.Age(now.Sub(odds.Generated)) + " old"
	case sell+wait == 0:
		problem = "have no sell now or wait"
	}
	return result, problem
}

// refreshCKSignals reloads the history when the newspaper has a new day and
// the odds when they are a day old, and rebuilds the signals either way.
func (s *site) refreshCKSignals() {
	if !ckAvailable() {
		return
	}
	s.loadCKHistory()
	refreshCKOdds()
	rebuildCKSignals()
}

// ckSignalForCard is a card's CK signal as of the last rebuild.
func ckSignalForCard(co *mtgmatcher.CardObject) ckView {
	signals := ckSignalsPtr.Load()
	if signals == nil {
		return ckView{}
	}
	return (*signals)[co.UUID]
}

// ckNewHighTipFor is the New high pill's tooltip on a card.
func ckNewHighTipFor(co *mtgmatcher.CardObject) string {
	tip := ckSignalForCard(co).NewHighTip
	if tip == "" {
		return ckNewHighVerdict
	}
	return tip
}
