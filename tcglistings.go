package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TCGplayer's sellers and copies per grade, from the newspaper's nightly
// scrape of every listing. They fill the quantity TCGplayer's own row on
// search leaves empty.

// tcgListingsStore is the shorthand of the TCGplayer store the counts go on.
const tcgListingsStore = "TCGPlayer"

// The grades in the order the counts are kept, as the site names them and
// as TCGplayer does.
var (
	tcgGrades      = [...]string{"NM", "SP", "MP", "HP", "PO"}
	tcgGradeNames  = [...]string{"Near Mint", "Lightly Played", "Moderately Played", "Heavily Played", "Damaged"}
	tcgGradeByName = map[string]int{"Near Mint": 0, "Lightly Played": 1, "Moderately Played": 2, "Heavily Played": 3, "Damaged": 4}
	tcgGradeBySite = map[mtgban.Condition]int{mtgban.NM: 0, mtgban.SP: 1, mtgban.MP: 2, mtgban.HP: 3, mtgban.PO: 4}
)

// tcgListings is one printing's listings on TCGplayer: sellers and copies
// per grade, and Total, its listings across conditions. For a cheap card
// the scrape keeps only the cheapest 100 listings of the product, which
// leave its other printings short too (MTGBan_Newspaper#37): Capped marks a
// printing that stored fewer listings than TCGplayer counts, and its Total
// is that count. Direct is TCGplayer Direct's own stock per grade, which
// TCGplayer repeats on every listing of the grade whoever the seller.
type tcgListings struct {
	Sellers [len(tcgGrades)]int32
	Copies  [len(tcgGrades)]int32
	Direct  [len(tcgGrades)]int32
	Capped  bool
	Total   int32
}

// tcgListingsSnapshot is one load of the counts, keyed by card uuid.
type tcgListingsSnapshot struct {
	Date  time.Time // the day of the scrape
	Cards map[string]*tcgListings
}

var tcgListingsPtr atomic.Pointer[tcgListingsSnapshot]

// tcgListingsLoading gates concurrent loads (datastore loads and cron).
var tcgListingsLoading atomic.Bool

// tcgListingsFailure is the scrape day whose load last failed, and when.
type tcgListingsFailure struct {
	Day, At time.Time
}

var tcgListingsFailed atomic.Pointer[tcgListingsFailure]

// tcgListingsRetryAfter is how long a scrape day whose load failed waits
// before the hourly run tries it again: the query costs Magic 40-90s.
const tcgListingsRetryAfter = 6 * time.Hour

// The newspaper scores each game after scraping it, so a game's newest day
// of scores is the day of its last finished scrape.
const tcgListingsDayQuery = `SELECT MAX(calc_date) FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards WHERE game_name = $1`

// A printing is capped when it stored more than this many listings fewer
// than TCGplayer counts: on 2026-09-28, 2,870 printings that never reached
// the cap were short by one or two, listings that changed during the scrape.
const tcgListingsSlack = 2

// Sellers, listings, copies and Direct's stock per product, printing and
// grade on one day, with TCGplayer's own count of the printing's listings; a
// printing with none stored comes back once, with no grade. Counting per
// seller first keeps both steps plain groupings, ~40s on Magic's ~11M
// listings a day against ~2.5 minutes for count(DISTINCT seller_id).
const tcgListingsQuery = `
	WITH per_seller AS (
		SELECT l.product_id, l.printing, l.condition, l.seller_id,
		       count(*) AS listings, sum(l.quantity) AS copies,
		       max(l.direct_inventory) AS direct
		  FROM tcgplayersellerproductlistingmodel l
		  JOIN tcgplayerproductinfomodel p ON p.product_id = l.product_id
		 WHERE p.game_name = $1 AND l.date = $2
		 GROUP BY 1, 2, 3, 4
	), counts AS (
		SELECT product_id, printing, condition,
		       count(*) AS sellers, sum(listings) AS listings, sum(copies) AS copies,
		       max(direct) AS direct
		  FROM per_seller
		 GROUP BY 1, 2, 3
	), reported AS (
		SELECT r.product_id, r.variant, r.quantity_sellers
		  FROM tcgplayerproductpricesmodel r
		  JOIN tcgplayerproductinfomodel p ON p.product_id = r.product_id
		 WHERE p.game_name = $1 AND r.date = $2 AND r.quantity_sellers > 0
	)
	SELECT coalesce(c.product_id, r.product_id), coalesce(c.printing, r.variant), c.condition,
	       coalesce(c.sellers, 0), coalesce(c.listings, 0), coalesce(c.copies, 0), r.quantity_sellers,
	       coalesce(c.direct, 0)
	  FROM counts c
	  FULL JOIN reported r ON r.product_id = c.product_id AND r.variant = c.printing`

// tcgListingsRow is one row of tcgListingsQuery.
type tcgListingsRow struct {
	ProductID int64
	Printing  string
	Condition string // empty for a printing with no listings stored
	Sellers   int
	Listings  int
	Copies    int
	Reported  sql.NullInt64 // TCGplayer's count of the printing's listings
	Direct    int           // TCGplayer Direct's own stock of the grade
}

// loadTCGListings reads the counts of the newspaper's last finished scrape
// for this site's game. It reruns only when another scrape finished, keeps
// the last good load on any error, and waits tcgListingsRetryAfter before
// trying a failed day again. A datastore reload keeps the day's counts: card
// ids outlast it, and a card it adds gets counts with the next scrape.
func (s *site) loadTCGListings() {
	game, found := gameMap[Config().Game]
	if !found || SkipNewspaper || NewNewspaperDB == nil {
		return
	}
	b := s.backend()
	if len(b.GetUUIDs()) == 0 {
		// No datastore yet: its load runs this once it is in.
		return
	}
	if !tcgListingsLoading.CompareAndSwap(false, true) {
		return
	}
	defer tcgListingsLoading.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var day sql.NullTime
	err := NewNewspaperDB.QueryRowContext(ctx, tcgListingsDayQuery, game).Scan(&day)
	if err != nil {
		log.Println("tcg listings:", err)
		backgroundJobs.Report(jobTCGListings, "", "cannot read the newspaper: "+err.Error())
		return
	}
	if !day.Valid {
		log.Println("tcg listings: the newspaper has no finished scrape")
		return
	}
	if !tcgListingsDue(tcgListingsPtr.Load(), tcgListingsFailed.Load(), day.Time, time.Now()) {
		return
	}

	cards, unmatched, err := queryTCGListings(ctx, b, game, day.Time)
	if err != nil {
		log.Println("tcg listings:", err)
		tcgListingsFailed.Store(&tcgListingsFailure{Day: day.Time, At: time.Now()})
		backgroundJobs.Report(jobTCGListings, "", "failed to load "+day.Time.Format(time.DateOnly)+": "+err.Error())
		return
	}
	tcgListingsPtr.Store(&tcgListingsSnapshot{Date: day.Time, Cards: cards})
	log.Println("tcg listings: loaded", len(cards), "printings from", day.Time.Format(time.DateOnly)+",", unmatched, "not matched")
	backgroundJobs.Report(jobTCGListings, fmt.Sprintf("%d printings from %s, %d not matched", len(cards), day.Time.Format(time.DateOnly), unmatched), "")
}

// tcgListingsDue reports whether day's counts should be loaded, given the
// current load and the last failed one: only a day other than the loaded
// one, and a day that failed only once tcgListingsRetryAfter has passed.
func tcgListingsDue(current *tcgListingsSnapshot, failed *tcgListingsFailure, day, now time.Time) bool {
	if current != nil && current.Date.Equal(day) {
		return false
	}
	return failed == nil || !failed.Day.Equal(day) || now.Sub(failed.At) >= tcgListingsRetryAfter
}

// queryTCGListings reads day's counts for game and keys them by b's card
// ids, answering how many printings matched no card. A load matching none
// is an error, so the previous one stays.
func queryTCGListings(ctx context.Context, b *mtgmatcher.Backend, game string, day time.Time) (map[string]*tcgListings, int, error) {
	rows, err := NewNewspaperDB.QueryContext(ctx, tcgListingsQuery, game, day)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var all []tcgListingsRow
	for rows.Next() {
		var row tcgListingsRow
		var condition sql.NullString
		err := rows.Scan(&row.ProductID, &row.Printing, &condition, &row.Sellers, &row.Listings, &row.Copies, &row.Reported, &row.Direct)
		if err != nil {
			return nil, 0, err
		}
		row.Condition = condition.String
		all = append(all, row)
	}
	err = rows.Err()
	if err != nil {
		return nil, 0, err
	}

	// The card ids TCGplayer's own prices are filed under: the product id,
	// with the printing as its finish.
	match := func(productID int64, printing string) (string, error) {
		return b.Match(&mtgmatcher.InputCard{
			ID:     strconv.FormatInt(productID, 10),
			Finish: printing,
			Foil:   printing != "Normal",
		})
	}
	cards, unmatched := buildTCGListings(all, match)
	if len(cards) == 0 {
		return nil, unmatched, fmt.Errorf("no cards matched in %d rows from %s, keeping the previous load", len(all), day.Format(time.DateOnly))
	}
	return cards, unmatched, nil
}

type tcgPrintingKey struct {
	productID int64
	printing  string
}

// buildTCGListings groups the rows by printing, marks the printings that
// stored fewer listings than TCGplayer counts, and keys them by card uuid.
// It also answers how many printings matched no card.
func buildTCGListings(rows []tcgListingsRow, match func(productID int64, printing string) (string, error)) (map[string]*tcgListings, int) {
	printings := map[tcgPrintingKey]*tcgListings{}
	stored := map[tcgPrintingKey]int{}
	reported := map[tcgPrintingKey]sql.NullInt64{}
	for _, row := range rows {
		key := tcgPrintingKey{row.ProductID, row.Printing}
		counts := printings[key]
		if counts == nil {
			counts = &tcgListings{}
			printings[key] = counts
		}
		stored[key] += row.Listings
		reported[key] = row.Reported

		grade, found := tcgGradeByName[row.Condition]
		if !found {
			continue
		}
		counts.Sellers[grade] = int32(row.Sellers)
		counts.Copies[grade] = int32(row.Copies)
		counts.Direct[grade] = int32(row.Direct)
	}

	cards := make(map[string]*tcgListings, len(printings))
	unmatched := 0
	for key, counts := range printings {
		counts.Total = int32(stored[key])
		total := reported[key]
		if total.Valid && total.Int64-int64(stored[key]) > tcgListingsSlack {
			counts.Capped = true
			counts.Total = int32(total.Int64)
		}
		cardID, err := match(key.productID, key.printing)
		if err != nil {
			unmatched++
			continue
		}
		cards[cardID] = counts
	}
	return cards, unmatched
}

// tcgListingsFor is what the TCGplayer row of a grade shows: sellers/copies,
// with a tooltip tabling every condition that has a seller, Damaged aside,
// the grade's own in bold; or, for a printing the scrape cut short,
// TCGplayer's own count on the NM row only.
func tcgListingsFor(cardID string, grade mtgban.Condition) (text, title string) {
	snap := tcgListingsPtr.Load()
	if snap == nil {
		return "", ""
	}
	counts, found := snap.Cards[cardID]
	if !found {
		return "", ""
	}
	i, found := tcgGradeBySite[grade]
	if !found {
		return "", ""
	}
	total := plural(int(counts.Total), "total listing") + " across conditions"
	day := "(as of " + snap.Date.Format("Jan 2") + ")"
	if counts.Capped {
		if i != 0 {
			return "", ""
		}
		return fmt.Sprintf("%d*", counts.Total), total + "\nPer-condition counts unavailable\n" + day
	}
	if counts.Sellers[i] == 0 {
		return "", ""
	}
	text = fmt.Sprintf("%d/%d", counts.Sellers[i], counts.Copies[i])
	var rows []string
	for g, name := range tcgGradeNames {
		if g == tcgGradeByName["Damaged"] || counts.Sellers[g] == 0 {
			continue
		}
		row := fmt.Sprintf("| %s | %d | %d", name, counts.Sellers[g], counts.Copies[g])
		if g == i {
			row = fmt.Sprintf("| **%s** | **%d** | **%d**", name, counts.Sellers[g], counts.Copies[g])
		}
		rows = append(rows, row)
	}
	foot := plural(int(counts.Total), "listing") + " across conditions · " + snap.Date.Format("Jan 2")
	if len(rows) == 0 {
		return text, foot
	}
	return text, "|# Condition | Sellers | Copies\n" + strings.Join(rows, "\n") + "\n" + foot
}

// tcgDirectStore is the shorthand of TCGplayer Direct's own prices, whose
// entries carry no quantity of their own.
const tcgDirectStore = "TCGDirect"

// tcgDirectStock is TCGplayer Direct's own stock of a card in a grade, as of
// the last listings load, where the scrape saw some.
func tcgDirectStock(cardID string, grade mtgban.Condition) (int, bool) {
	snap := tcgListingsPtr.Load()
	if snap == nil {
		return 0, false
	}
	counts, found := snap.Cards[cardID]
	if !found {
		return 0, false
	}
	i, found := tcgGradeBySite[grade]
	if !found || counts.Direct[i] == 0 {
		return 0, false
	}
	return int(counts.Direct[i]), true
}

// tcgDirectStockNote is the tooltip on Direct's stock where it is shown,
// dating the scrape it comes from. Empty until the listings load.
func tcgDirectStockNote() string {
	snap := tcgListingsPtr.Load()
	if snap == nil {
		return ""
	}
	return "Direct stock as of " + snap.Date.Format("Jan 2")
}

// tcgDirectStocked is seller with Direct's stock as the quantity of every
// entry that has one, when seller is TCGplayer Direct, and seller itself
// otherwise. Only the arbitrage pages read it: search does not show Direct's
// stock.
func tcgDirectStocked(seller mtgban.Seller) mtgban.Seller {
	if seller.Info().Shorthand != tcgDirectStore {
		return seller
	}
	return &stockedSeller{Seller: seller}
}

// stockedSeller is a TCGplayer Direct seller for one request.
type stockedSeller struct {
	mtgban.Seller
	once      sync.Once
	inventory mtgban.InventoryRecord
}

// Inventory copies the entries Direct has stock of, once, and shares the
// rest with the seller's own.
func (s *stockedSeller) Inventory() mtgban.InventoryRecord {
	s.once.Do(func() {
		base := s.Seller.Inventory()
		s.inventory = make(mtgban.InventoryRecord, len(base))
		for cardID, entries := range base {
			var stocked []mtgban.InventoryEntry
			for i, entry := range entries {
				stock, found := tcgDirectStock(cardID, entry.Conditions)
				if !found {
					continue
				}
				if stocked == nil {
					stocked = slices.Clone(entries)
				}
				stocked[i].Quantity = stock
			}
			if stocked == nil {
				stocked = entries
			}
			s.inventory[cardID] = stocked
		}
	})
	return s.inventory
}

// plural spells a count with its noun, "1 seller" or "14 copies".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "y") {
		noun = strings.TrimSuffix(noun, "y") + "ie"
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
