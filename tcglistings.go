package main

import (
	"context"
	"database/sql"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TCGplayer's sellers and copies per grade, from the newspaper's nightly
// scrape of every listing. They fill the quantity TCGplayer's own row on
// search leaves empty.

// The grades in the order the counts are kept, as the site names them and
// as TCGplayer does.
var (
	tcgGrades      = [...]string{"NM", "SP", "MP", "HP", "PO"}
	tcgGradeByName = map[string]int{"Near Mint": 0, "Lightly Played": 1, "Moderately Played": 2, "Heavily Played": 3, "Damaged": 4}
)

// tcgListings is one printing's listings on TCGplayer: sellers and copies
// per grade, and Total, its listings across conditions. For a cheap card
// the scrape keeps only the cheapest 100 listings of the product, which
// leave its other printings short too (MTGBan_Newspaper#37): Capped marks a
// printing that stored fewer listings than TCGplayer counts, and its Total
// is that count.
type tcgListings struct {
	Sellers [len(tcgGrades)]int32
	Copies  [len(tcgGrades)]int32
	Capped  bool
	Total   int32
}

// tcgListingsSnapshot is one load of the counts, keyed by card uuid.
type tcgListingsSnapshot struct {
	Date    time.Time // the day of the scrape
	Backend *mtgmatcher.Backend
	Cards   map[string]*tcgListings
}

var tcgListingsPtr atomic.Pointer[tcgListingsSnapshot]

// tcgListingsLoading gates concurrent loads (datastore loads and cron).
var tcgListingsLoading atomic.Bool

// The newspaper scores each game after scraping it, so a game's newest day
// of scores is the day of its last finished scrape.
const tcgListingsDayQuery = `SELECT MAX(calc_date) FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards WHERE game_name = $1`

// A printing is capped when it stored more than this many listings fewer
// than TCGplayer counts: on 2026-09-28, 2,870 printings that never reached
// the cap were short by one or two, listings that changed during the scrape.
const tcgListingsSlack = 2

// Sellers, listings and copies per product, printing and grade on one day,
// with TCGplayer's own count of the printing's listings; a printing with
// none stored comes back once, with no grade. Counting per seller first
// keeps both steps plain groupings, ~40s on Magic's ~11M listings a day
// against ~2.5 minutes for count(DISTINCT seller_id).
const tcgListingsQuery = `
	WITH per_seller AS (
		SELECT l.product_id, l.printing, l.condition, l.seller_id,
		       count(*) AS listings, sum(l.quantity) AS copies
		  FROM tcgplayersellerproductlistingmodel l
		  JOIN tcgplayerproductinfomodel p ON p.product_id = l.product_id
		 WHERE p.game_name = $1 AND l.date = $2
		 GROUP BY 1, 2, 3, 4
	), counts AS (
		SELECT product_id, printing, condition,
		       count(*) AS sellers, sum(listings) AS listings, sum(copies) AS copies
		  FROM per_seller
		 GROUP BY 1, 2, 3
	), reported AS (
		SELECT r.product_id, r.variant, r.quantity_sellers
		  FROM tcgplayerproductpricesmodel r
		  JOIN tcgplayerproductinfomodel p ON p.product_id = r.product_id
		 WHERE p.game_name = $1 AND r.date = $2 AND r.quantity_sellers > 0
	)
	SELECT coalesce(c.product_id, r.product_id), coalesce(c.printing, r.variant), c.condition,
	       coalesce(c.sellers, 0), coalesce(c.listings, 0), coalesce(c.copies, 0), r.quantity_sellers
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
}

// loadTCGListings reads the counts of the newspaper's last finished scrape
// for this site's game. It reruns only when a newer scrape finished or the
// datastore changed, and keeps the last good load on any error.
func (s *site) loadTCGListings() {
	game, found := gameMap[Config.Game]
	if !found || SkipNewspaper || NewNewspaperDB == nil {
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
		return
	}
	if !day.Valid {
		log.Println("tcg listings: the newspaper has no finished scrape")
		return
	}
	b := s.backend()
	current := tcgListingsPtr.Load()
	if current != nil && current.Date.Equal(day.Time) && current.Backend == b {
		return
	}

	rows, err := NewNewspaperDB.QueryContext(ctx, tcgListingsQuery, game, day.Time)
	if err != nil {
		log.Println("tcg listings:", err)
		return
	}
	defer rows.Close()

	var all []tcgListingsRow
	for rows.Next() {
		var row tcgListingsRow
		var condition sql.NullString
		err := rows.Scan(&row.ProductID, &row.Printing, &condition, &row.Sellers, &row.Listings, &row.Copies, &row.Reported)
		if err != nil {
			log.Println("tcg listings:", err)
			return
		}
		row.Condition = condition.String
		all = append(all, row)
	}
	err = rows.Err()
	if err != nil {
		log.Println("tcg listings:", err)
		return
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
		log.Println("tcg listings: no cards matched, keeping the previous load")
		return
	}

	tcgListingsPtr.Store(&tcgListingsSnapshot{Date: day.Time, Backend: b, Cards: cards})
	log.Println("tcg listings: loaded", len(cards), "printings from", day.Time.Format(time.DateOnly)+",", unmatched, "not matched")
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
