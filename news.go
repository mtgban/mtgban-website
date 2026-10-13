package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	DefaultPageSize = 25

	MaxSYPResults      = 2500
	MaxSYPTotalResults = 100000
)

type Heading struct {
	// The header string
	Title string
	// The field can be sorted
	CanSort bool
	// The name of the field to be sorted
	Field string
	// Need dolla sign prepended
	IsDollar bool
	// This is a percentage
	IsPerc bool
	// This is a Number
	IsNum bool
	// Do not display this field in HTML
	IsHidden bool
	// This field can be sorted when filtered
	ConditionalSort bool
}

type NewspaperResult struct {
	// Common fields (all pages)
	Date     string // calc_date (hidden)
	UUID     string // product_id or uuid (hidden)
	Ranking  int
	CardName string
	Edition  string
	Number   string
	Variant  string // variant, the finish
	Rarity   string // the matched card's rarity

	// Spike score pages
	BucketName string
	BucketRank int

	// Price fields
	CKRetailPrice  float64
	TCGMarketPrice float64
	CKBuyPrice     float64
	CurrentPrice   float64
	Retail         float64
	Buylist        float64

	// Seller listing fields
	SellersToday    int
	SellersLastWeek int
	SellersMonthAgo int

	// Buylist level fields
	TodaysBuylist    float64
	YesterdayBuylist float64
	LastWeekBuylist  float64
	LastMonthBuylist float64

	// Change fields
	WeeklyPctChange float64

	// Vendor count
	Vendors int

	// Forecast fields
	RecentBL            float64
	HistoricalPlusMinus float64
	HistoricalMedian    float64
	HistoricalMax       float64
	ForecastedBL        float64
	ForecastPlusMinus   float64
	TargetDate          string
	Tier                string
	Behavior            string
	CustomSort          string
}

// FieldValue returns the value of the named field as a string for template rendering.
// The name parameter corresponds to the SQL column name (Heading.Field).
func (r NewspaperResult) FieldValue(name string) string {
	switch name {
	// Common
	case "ranking", "Ranking":
		if r.Ranking == 0 {
			return ""
		}
		return strconv.Itoa(r.Ranking)
	case "product_name", "Name":
		return r.CardName
	case "set_name", "Set":
		return r.Edition
	case "product_number", "Number":
		return r.Number
	case "variant", "Rarity":
		return r.Variant
	// Bucket
	case "bucket_name":
		return r.BucketName
	case "bucket_rank":
		if r.BucketRank == 0 {
			return ""
		}
		return strconv.Itoa(r.BucketRank)
	// Prices
	case "ck_retail_price":
		return formatFloat(r.CKRetailPrice)
	case "tcg_market_price":
		return formatFloat(r.TCGMarketPrice)
	case "ck_buy_price":
		return formatFloat(r.CKBuyPrice)
	case "current_price":
		return formatFloat(r.CurrentPrice)
	case "Retail":
		return formatFloat(r.Retail)
	case "Buylist":
		return formatFloat(r.Buylist)
	// Sellers
	case "sellers_Today", "Todays_Sellers":
		return strconv.Itoa(r.SellersToday)
	case "sellers_d7", "Week_Ago_Sellers":
		return strconv.Itoa(r.SellersLastWeek)
	case "sellers_d30", "Month_Ago_Sellers":
		return strconv.Itoa(r.SellersMonthAgo)
	// Buylist levels
	case "ck_buy_price_today", "Todays_BL":
		return formatFloat(r.TodaysBuylist)
	case "ck_buy_1d", "Yesterday_BL":
		return formatFloat(r.YesterdayBuylist)
	case "ck_buy_7d", "Week_Ago_BL":
		return formatFloat(r.LastWeekBuylist)
	case "ck_buy_30d", "Month_Ago_BL":
		return formatFloat(r.LastMonthBuylist)
	// Percentage change
	case "pct_gain_7d", "pct_drop_7d", "pct_increase_7d", "pct_decrease_7d",
		"Week_Ago_Sellers_Chg", "Week_Ago_BL_Chg":
		return formatFloat(r.WeeklyPctChange)
	// Vendors
	case "Vendors":
		return strconv.Itoa(r.Vendors)
	// Forecast
	case "Recent_BL":
		return formatFloat(r.RecentBL)
	case "Historical_plus_minus":
		return formatFloat(r.HistoricalPlusMinus)
	case "Historical_Median":
		return formatFloat(r.HistoricalMedian)
	case "Historical_Max":
		return formatFloat(r.HistoricalMax)
	case "Forecasted_BL":
		return formatFloat(r.ForecastedBL)
	case "Forecast_plus_minus":
		return formatFloat(r.ForecastPlusMinus)
	case "Target_Date":
		return r.TargetDate
	case "Tier":
		return r.Tier
	case "Behavior":
		return r.Behavior
	case "custom_sort":
		return r.CustomSort
	default:
		return ""
	}
}

func formatFloat(f float64) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

type NewspaperPage struct {
	// Title of the page
	Title string
	// Short description of the current page
	Desc string
	// Name of the page used in the query parameter
	Option string
	// The query run to obtain data
	Query string
	// Default orting option
	Sort string
	// The name of the columns and their properties
	Head []Heading
	// How many elements are present before the card triplet
	Offset int
	// Which field to use for price comparison
	Priced string
	// Which field to use for percentage change comparison
	PercChanged string
	// Whether the page can be filtered by bucket name
	HasBucket bool
	// Short label for tab navigation
	Short string
	// SVG icon for TOC card display
	Icon template.HTML

	// Cached results of the various queries
	Results     []NewspaperResult
	Results3Day []NewspaperResult

	// Which editions are available in the cache
	AvailableEditions     []string
	AvailableEditions3Day []string

	// Which finishes are available in the cache
	PossibleFinish     []string
	PossibleFinish3Day []string

	// Whether a relevant buylist is present for the game
	NeedsBuylist bool
}

// shown reports whether the newspaper shows the page on this deployment:
// the pages built on a buylist are Magic's alone.
func (page NewspaperPage) shown() bool {
	return !page.NeedsBuylist || Config().Game == DefaultGame
}

// newspaperColumnSetters maps a SQL column name (everything past the
// seven-column positional header read by getResults) to a function that
// parses the raw cell value and writes it to the NewspaperResult. Several
// SQL column names alias to the same target field (e.g. "sellers_Today" and
// "Todays_Sellers" both feed SellersToday) — those appear as separate
// adjacent entries pointing at the same setter shape.
var newspaperColumnSetters = map[string]func(*NewspaperResult, string){
	"bucket_name":           func(r *NewspaperResult, s string) { r.BucketName = s },
	"bucket_rank":           func(r *NewspaperResult, s string) { r.BucketRank, _ = strconv.Atoi(s) },
	"ck_retail_price":       func(r *NewspaperResult, s string) { r.CKRetailPrice, _ = strconv.ParseFloat(s, 64) },
	"tcg_market_price":      func(r *NewspaperResult, s string) { r.TCGMarketPrice, _ = strconv.ParseFloat(s, 64) },
	"ck_buy_price":          func(r *NewspaperResult, s string) { r.CKBuyPrice, _ = strconv.ParseFloat(s, 64) },
	"current_price":         func(r *NewspaperResult, s string) { r.CurrentPrice, _ = strconv.ParseFloat(s, 64) },
	"Retail":                func(r *NewspaperResult, s string) { r.Retail, _ = strconv.ParseFloat(s, 64) },
	"Buylist":               func(r *NewspaperResult, s string) { r.Buylist, _ = strconv.ParseFloat(s, 64) },
	"sellers_today":         func(r *NewspaperResult, s string) { r.SellersToday, _ = strconv.Atoi(s) },
	"Todays_Sellers":        func(r *NewspaperResult, s string) { r.SellersToday, _ = strconv.Atoi(s) },
	"sellers_d7":            func(r *NewspaperResult, s string) { r.SellersLastWeek, _ = strconv.Atoi(s) },
	"Week_Ago_Sellers":      func(r *NewspaperResult, s string) { r.SellersLastWeek, _ = strconv.Atoi(s) },
	"sellers_d30":           func(r *NewspaperResult, s string) { r.SellersMonthAgo, _ = strconv.Atoi(s) },
	"Month_Ago_Sellers":     func(r *NewspaperResult, s string) { r.SellersMonthAgo, _ = strconv.Atoi(s) },
	"Todays_BL":             func(r *NewspaperResult, s string) { r.TodaysBuylist, _ = strconv.ParseFloat(s, 64) },
	"Yesterday_BL":          func(r *NewspaperResult, s string) { r.YesterdayBuylist, _ = strconv.ParseFloat(s, 64) },
	"ck_buy_1d":             func(r *NewspaperResult, s string) { r.YesterdayBuylist, _ = strconv.ParseFloat(s, 64) },
	"Week_Ago_BL":           func(r *NewspaperResult, s string) { r.LastWeekBuylist, _ = strconv.ParseFloat(s, 64) },
	"ck_buy_7d":             func(r *NewspaperResult, s string) { r.LastWeekBuylist, _ = strconv.ParseFloat(s, 64) },
	"Month_Ago_BL":          func(r *NewspaperResult, s string) { r.LastMonthBuylist, _ = strconv.ParseFloat(s, 64) },
	"ck_buy_30d":            func(r *NewspaperResult, s string) { r.LastMonthBuylist, _ = strconv.ParseFloat(s, 64) },
	"pct_gain_7d":           func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"pct_drop_7d":           func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"pct_increase_7d":       func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"pct_decrease_7d":       func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"Week_Ago_Sellers_Chg":  func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"Week_Ago_BL_Chg":       func(r *NewspaperResult, s string) { r.WeeklyPctChange, _ = strconv.ParseFloat(s, 64) },
	"Vendors":               func(r *NewspaperResult, s string) { r.Vendors, _ = strconv.Atoi(s) },
	"Recent_BL":             func(r *NewspaperResult, s string) { r.RecentBL, _ = strconv.ParseFloat(s, 64) },
	"Historical_plus_minus": func(r *NewspaperResult, s string) { r.HistoricalPlusMinus, _ = strconv.ParseFloat(s, 64) },
	"Historical_Median":     func(r *NewspaperResult, s string) { r.HistoricalMedian, _ = strconv.ParseFloat(s, 64) },
	"Historical_Max":        func(r *NewspaperResult, s string) { r.HistoricalMax, _ = strconv.ParseFloat(s, 64) },
	"Forecasted_BL":         func(r *NewspaperResult, s string) { r.ForecastedBL, _ = strconv.ParseFloat(s, 64) },
	"Forecast_plus_minus":   func(r *NewspaperResult, s string) { r.ForecastPlusMinus, _ = strconv.ParseFloat(s, 64) },
	"Target_Date":           func(r *NewspaperResult, s string) { r.TargetDate = s },
	"Tier":                  func(r *NewspaperResult, s string) { r.Tier = s },
	"Trending":              func(r *NewspaperResult, s string) { r.Tier = s },
	"Behavior":              func(r *NewspaperResult, s string) { r.Behavior = s },
	"custom_sort":           func(r *NewspaperResult, s string) { r.CustomSort = s },
}

func getResults(b *mtgmatcher.Backend, db *sql.DB, query string) ([]NewspaperResult, error) {
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Retrieve columns to know how many fields to read
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	if len(cols) < 7 {
		return nil, errors.New("not enough data in rows")
	}

	// Result is your slice of raw bytes
	rawResult := make([][]byte, len(cols))

	// A temporary interface{} slice, containing a variable number of fields
	dest := make([]any, len(cols))
	for e := range rawResult {
		// Put pointers to each string in the interface slice
		dest[e] = &rawResult[e]
	}

	// Allocate the main result slice
	var results []NewspaperResult

	for rows.Next() {
		err := rows.Scan(dest...)
		if err != nil {
			log.Println(err)
			continue
		}

		// Convert the parsed fields into usable strings
		raw := make([]string, len(cols))
		for j, r := range rawResult {
			if r != nil {
				raw[j] = string(r)
			}
		}

		result, ok := newspaperRow(b, cols, raw, db == NewNewspaperDB)
		if !ok {
			continue
		}

		// Allocate a result row with all mapped fields
		results = append(results, result)
	}

	return results, nil
}

// newspaperRow maps one row's cells to a result. With match set it resolves
// the TCGplayer id to a card, whose values replace the row's, or drops the row.
func newspaperRow(b *mtgmatcher.Backend, cols, raw []string, match bool) (NewspaperResult, bool) {
	// Map common fields (first 7 columns are always the same order)
	result := NewspaperResult{
		Date:     raw[0],
		UUID:     raw[1],
		CardName: raw[3],
		Edition:  raw[4],
		Number:   raw[5],
		Variant:  raw[6],
	}

	// Override a few fields for better integration with the site
	if match {
		uuid, err := b.MatchID(raw[1], raw[6] != "Normal")
		if err != nil {
			LogPages["Newspaper"].Println("match", raw[1], raw[6], "as", raw[3], raw[4], raw[5], "failed:", err)
			return NewspaperResult{}, false
		}
		co, _ := b.GetUUID(uuid)
		result.UUID = uuid
		result.CardName = co.Name
		result.Edition = co.Edition
		result.Number = co.Number
		result.Rarity = co.Rarity
	}
	if raw[2] != "" {
		result.Ranking, _ = strconv.Atoi(raw[2])
	}

	// Map remaining columns by SQL column name; unknown columns are
	// ignored, matching the original switch's lack of a default case.
	for j := 7; j < len(cols); j++ {
		if raw[j] == "" {
			continue
		}
		if set := newspaperColumnSetters[cols[j]]; set != nil {
			set(&result, raw[j])
		}
	}
	return result, true
}

// gameMap names every game a deployment can be configured as. For a game
// missing from it, the newspaper stays empty and every refresh logs an
// error, so an entry has to exist before an instance of that game is stood
// up - which is why the games mtgmatcher registers are all here whether or
// not one is deployed yet. Each name is TCGplayer's productLineName, spelled
// exactly: the newspaper files its rows under it and the pages match it
// with =.
var gameMap = map[mtgmatcher.Game]string{
	mtgmatcher.GameMagic:         "Magic: The Gathering",
	mtgmatcher.GameLorcana:       "Disney Lorcana",
	mtgmatcher.GameOnePiece:      "One Piece Card Game",
	mtgmatcher.GameYuGiOh:        "YuGiOh",
	mtgmatcher.GameRiftbound:     "Riftbound: League of Legends Trading Card Game",
	mtgmatcher.GameFleshAndBlood: "Flesh and Blood TCG",
	mtgmatcher.GamePokemon:       "Pokemon",
	mtgmatcher.GameGundam:        "Gundam Card Game",
	mtgmatcher.GamePalworld:      "Palworld OFFICIAL CARD GAME",
}

// gameBadgeMap is the short form the brand wears under the wordmark on a
// non-Magic deployment. gameMap's full names are what prose wants and what a
// two-line lockup cannot hold: "Riftbound: League of Legends Trading Card
// Game" is wider than the navbar leaves for the logo.
var gameBadgeMap = map[mtgmatcher.Game]string{
	mtgmatcher.GameLorcana:       "Lorcana",
	mtgmatcher.GameOnePiece:      "One Piece",
	mtgmatcher.GameYuGiOh:        "Yu-Gi-Oh!",
	mtgmatcher.GameRiftbound:     "Riftbound",
	mtgmatcher.GameFleshAndBlood: "Flesh and Blood",
	mtgmatcher.GamePokemon:       "Pokémon",
	mtgmatcher.GameGundam:        "Gundam",
	mtgmatcher.GamePalworld:      "Palworld",
}

// Cache of card UUIDs that appear in the newspaper spike score pages.
// Published atomically alongside newspaperPagesPtr so readers always see a
// fully-built map.
var newspaperUUIDsPtr atomic.Pointer[map[string]struct{}]

// GetNewspaperUUIDs returns the current set of UUIDs that appear in the
// newspaper spike-score pages. The returned map is shared and MUST NOT be
// modified by callers. Returns nil before the first successful cache run.
func GetNewspaperUUIDs() map[string]struct{} {
	p := newspaperUUIDsPtr.Load()
	if p == nil {
		return nil
	}
	return *p
}

// newspaperStaleAfter is how old the cached slices may get before the page says
// so. The cache refreshes every three hours, so this is four missed runs: past
// any single hiccup, and soon enough that a reader is told the same day.
const newspaperStaleAfter = 12 * time.Hour

// newspaperStaleNotice is what a page tells a reader when it has stopped
// refreshing, or "" while it is current. Every page keeps its last good slice
// through a bad refresh, which is what stops a gap in the scoring data from
// blanking the tables -- but it also means the numbers look live when they are
// not, and the reader is the one acting on them.
func newspaperStaleNotice(last time.Time) string {
	if !newsStale(last, time.Now()) {
		return ""
	}
	return "these numbers last refreshed " + last.Format("Jan 2 15:04 MST") + " and are not current"
}

// newsStale reports the cache refreshed, and newspaperStaleAfter or more before now.
func newsStale(refreshed, now time.Time) bool {
	return !refreshed.IsZero() && now.Sub(refreshed) >= newspaperStaleAfter
}

// noteNewspaperStaleness appends the notice to whatever the page was already
// saying, since InfoMessage carries the page description.
func noteNewspaperStaleness(pageVars *PageVars) {
	notice := newspaperStaleNotice(pageVars.LastUpdate)
	if notice == "" {
		return
	}
	if pageVars.InfoMessage == "" {
		pageVars.InfoMessage = notice
		return
	}
	pageVars.InfoMessage += " - " + notice
}

// refreshNewspaperEdition runs one edition of a page's query. The second
// return value reports whether the results are good enough to replace what is
// already cached: a failed query, an empty response, or a response that lost
// more than half of the rows we had all keep the older data.
func refreshNewspaperEdition(b *mtgmatcher.Backend, label, query string, cached []NewspaperResult) ([]NewspaperResult, bool) {
	results, err := getResults(b, NewNewspaperDB, query)
	if err != nil {
		log.Println(query, err)
		return nil, false
	}
	if len(results) == 0 {
		log.Println("newspaper:", label, "results are empty, keeping the cached slice")
		return nil, false
	}
	if cached != nil && len(results) < len(cached)/2 {
		log.Println("newspaper:", label, "returned", len(results), "rows against", len(cached), "cached, keeping the cached slice")
		return nil, false
	}

	log.Println(label, "has", len(results), "elements")
	return results, true
}

// newspaperFilterValues collects the editions and the finishes present in a
// set of results, for the dropdown filters.
func newspaperFilterValues(results []NewspaperResult) (editions, variants []string) {
	editions = []string{""}
	variants = []string{""}
	for _, result := range results {
		if !slices.Contains(editions, result.Edition) {
			editions = append(editions, result.Edition)
		}
		if !slices.Contains(variants, result.Variant) {
			variants = append(variants, result.Variant)
		}
	}
	sort.Strings(editions)
	sort.Strings(variants)
	return editions, variants
}

func (s *site) cacheNewspaper() {
	if SkipNewspaper {
		return
	}

	b := s.backend()
	log.Println("Caching Newspaper data")

	newspaperUUIDs := map[string]struct{}{}

	game, found := gameMap[Config().Game]
	if !found {
		log.Printf("newspaper: %q is missing from gameMap, not caching", Config().Game)
		return
	}

	if NewNewspaperDB == nil {
		log.Println("NewNewspaper DB connection was not established, no cache")
		return
	}

	// Build a fresh slice from the current snapshot so readers never observe
	// torn struct fields (slice headers, in particular) while we update them.
	current := GetNewspaperPages()
	next := make([]NewspaperPage, len(current))
	copy(next, current)

	// How many editions actually took new rows this run. The update time is
	// what the page shows as its own, so it may only move when something did.
	var refreshed int

	for i := range next {
		if next[i].Query == "" {
			continue
		}
		if !next[i].shown() {
			continue
		}

		query := strings.ReplaceAll(next[i].Query, "__GAME__", game) + " ORDER BY ranking ASC;"

		// Both editions are fetched independently: a bad refresh on one of
		// them keeps the previously cached data for that edition instead of
		// blanking the page or skipping the other edition entirely.
		if results, ok := refreshNewspaperEdition(b, next[i].Option, query, next[i].Results); ok {
			next[i].Results = results
			next[i].AvailableEditions, next[i].PossibleFinish = newspaperFilterValues(results)
			refreshed++
		}

		query3day := strings.ReplaceAll(query, "0 DAY", "3 DAY")
		if results, ok := refreshNewspaperEdition(b, next[i].Option+" (3day)", query3day, next[i].Results3Day); ok {
			next[i].Results3Day = results
			next[i].AvailableEditions3Day, next[i].PossibleFinish3Day = newspaperFilterValues(results)
			refreshed++
		}

		// Cache UUIDs from spike score pages for the "on:newspaper" search filter
		if next[i].Option == "combined_spike_score" || next[i].Option == "spike_score" {
			for _, result := range next[i].Results {
				newspaperUUIDs[result.UUID] = struct{}{}
			}
		}
	}

	newspaperPagesPtr.Store(&next)
	newspaperUUIDsPtr.Store(&newspaperUUIDs)
	log.Println("Newspaper UUIDs cached:", len(newspaperUUIDs))
	backgroundJobs.Report(jobNewspaper, fmt.Sprintf("%d cards cached", len(newspaperUUIDs)), "")

	// Only stamp a new update time when an edition actually took new rows.
	// Every page keeps its last good slice through a bad refresh, so stamping
	// unconditionally dated stale data to the minute the refresh failed, and the
	// page then advertised it as current.
	if refreshed > 0 {
		SetLastNewspaperUpdate(time.Now())
	} else {
		log.Println("newspaper: no edition refreshed, leaving the update time at", GetLastNewspaperUpdate())
	}
	log.Println("Newspaper All Ready")
}

// newspaperPagesPtr holds the current cached newspaper data. cacheNewspaper
// builds a fresh slice from the previous snapshot and publishes it with a
// single Store so readers always see a fully-constructed slice.
var newspaperPagesPtr atomic.Pointer[[]NewspaperPage]

// GetNewspaperPages returns the current newspaper-pages snapshot. The
// returned slice and the structs it contains are shared and MUST NOT be
// modified by callers.
func GetNewspaperPages() []NewspaperPage {
	p := newspaperPagesPtr.Load()
	if p == nil {
		return nil
	}
	return *p
}

func init() {
	// Seed the atomic pointer with the static literal so readers see the
	// configured pages even before the first cacheNewspaper run completes.
	initial := newspaperPagesInitial
	newspaperPagesPtr.Store(&initial)
}

// newspaperCalcDateFilter builds the WHERE fragment that picks which stored
// slice a page shows, and applies the page's own row filter.
//
// Every edition is anchored on the newest calc_date that actually has usable
// rows for that page: the live edition uses "0 DAY" and cacheNewspaper rewrites
// it to "3 DAY" for the delayed edition. Slices where the page's metric came
// out NULL for every row are skipped rather than displayed as an empty table --
// a gap in the price history leaves the 7-day checkpoint with nothing to
// compare against, which wipes out a whole day of scores -- so an edition keeps
// walking back until it finds a slice with data. If nothing is old enough,
// it settles for the oldest usable slice.
func newspaperCalcDateFilter(table, rowFilter string) string {
	if rowFilter == "" {
		rowFilter = "TRUE"
	}
	return fmt.Sprintf(`%[2]s
                   AND calc_date = COALESCE(
                       (SELECT MAX(calc_date)
                          FROM %[1]s
                         WHERE game_name = '__GAME__'
                           AND %[2]s
                           AND calc_date <= (SELECT MAX(calc_date)
                                               FROM %[1]s
                                              WHERE game_name = '__GAME__'
                                                AND %[2]s) - INTERVAL '0 DAY'),
                       (SELECT MIN(calc_date)
                          FROM %[1]s
                         WHERE game_name = '__GAME__'
                           AND %[2]s))`, table, rowFilter)
}

var newspaperPagesInitial = []NewspaperPage{
	{
		Title:  "Top Singles by Combined Spike Score",
		Desc:   "Best cards to buy, combining TCGplayer sales data and Card Kingdom pricing changes",
		Offset: 3,
		Option: "combined_spike_score",
		Query: `SELECT calc_date, tcgplayer_id,
                       ROW_NUMBER() OVER (ORDER BY spike_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       bucket_name, bucket_rank,
                       ck_retail_price, tcg_market_price, ck_buy_price
                  FROM scripts__tcgplayersalesdata_plus_cardkingdom_spike_score_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__tcgplayersalesdata_plus_cardkingdom_spike_score_cards", ""),
		Sort:   "ranking ASC",
		Priced: "tcg_market_price",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:   "Bucket",
				CanSort: true,
				Field:   "bucket_name",
			},
			{
				Title:   "Bucket Rank",
				CanSort: true,
				Field:   "bucket_rank",
				IsNum:   true,
			},
			{
				Title:    "CK Retail",
				CanSort:  true,
				Field:    "ck_retail_price",
				IsDollar: true,
			},
			{
				Title:    "TCG Market",
				CanSort:  true,
				Field:    "tcg_market_price",
				IsDollar: true,
			},
			{
				Title:    "CK Buylist",
				CanSort:  true,
				Field:    "ck_buy_price",
				IsDollar: true,
			},
		},
		HasBucket:    true,
		NeedsBuylist: true,
		Short:        "Combined Spike",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff0000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3q1 4 4 6.5t3 5.5a1 1 0 0 1-14 0 5 5 0 0 1 1-3 1 1 0 0 0 5 0c0-2-1.5-3-1.5-5q0-2 2.5-4"/></svg>`,
	},
	{
		Title:  "Top Singles by Spike Score",
		Desc:   "Best cards to buy, using TCGplayer sales data",
		Offset: 3,
		Option: "spike_score",
		Query: `SELECT calc_date, product_id,
                       ROW_NUMBER() OVER (ORDER BY spike_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       bucket_name, bucket_rank,
                       current_price
                  FROM scripts__tcgplayersalesdata_spike_score_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__tcgplayersalesdata_spike_score_cards", ""),
		Sort:   "ranking ASC",
		Priced: "current_price",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:   "Bucket",
				CanSort: true,
				Field:   "bucket_name",
			},
			{
				Title:   "Bucket Rank",
				CanSort: true,
				Field:   "bucket_rank",
				IsNum:   true,
			},
			{
				Title:    "Current Price",
				CanSort:  true,
				Field:    "current_price",
				IsDollar: true,
			},
		},
		HasBucket: true,
		Short:     "Spike Score",
		Icon:      `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff0000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3q1 4 4 6.5t3 5.5a1 1 0 0 1-14 0 5 5 0 0 1 1-3 1 1 0 0 0 5 0c0-2-1.5-3-1.5-5q0-2 2.5-4"/></svg>`,
	},
	{
		Title:  "Greatest Increase in Vendor Listings",
		Desc:   "Cards with substantial stock increases, indicating that there is more than enough supply to meet current demand across the reviewed time period (tl:dr - Avoid These)",
		Offset: 3,
		Option: "greatest_increase_listings",
		Query: `SELECT calc_date, product_id,
                       ROW_NUMBER() OVER (ORDER BY raw_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       sellers_Today, sellers_d7, sellers_d30, pct_gain_7d
                  FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__tcgplayer_greatest_increase_in_vendor_listings_cards", "pct_gain_7d <> 0"),
		Sort:        "ranking ASC",
		PercChanged: "pct_gain_7d",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:   "Today's Sellers",
				CanSort: true,
				Field:   "sellers_Today",
				IsNum:   true,
			},
			{
				Title:   "Last Week Sellers",
				CanSort: true,
				Field:   "sellers_d7",
				IsNum:   true,
			},
			{
				Title:   "Month Ago Sellers",
				CanSort: true,
				Field:   "sellers_d30",
				IsNum:   true,
			},
			{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "pct_gain_7d",
				IsPerc:  true,
			},
		},
		Short: "Vendors \u2191",
		Icon:  `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#08f730" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 7h6v6"/><path d="m22 7-8.5 8.5-5-5L2 17"/></svg>`,
	},
	{
		Title:  "Greatest Decrease in Vendor Listings",
		Desc:   "Cards with relevant stock decrease, indicating that there is not enough supply to meet current demand across the reviewed time period (tl:dr - Seek these out)",
		Offset: 3,
		Option: "greatest_decrease_listings",
		Query: `SELECT calc_date, product_id,
                       ROW_NUMBER() OVER (ORDER BY raw_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       sellers_Today, sellers_d7, sellers_d30, pct_drop_7d
                  FROM scripts__tcgplayer_greatest_decrease_in_vendor_listings_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__tcgplayer_greatest_decrease_in_vendor_listings_cards", "pct_drop_7d <> 0"),
		Sort:        "ranking ASC",
		PercChanged: "pct_drop_7d",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:   "Today's Sellers",
				CanSort: true,
				Field:   "sellers_Today",
				IsNum:   true,
			},
			{
				Title:   "Last Week Sellers",
				CanSort: true,
				Field:   "sellers_d7",
				IsNum:   true,
			},
			{
				Title:   "Month Ago Sellers",
				CanSort: true,
				Field:   "sellers_d30",
				IsNum:   true,
			},
			{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "pct_drop_7d",
				IsPerc:  true,
			},
		},
		Short: "Vendors \u2193",
		Icon:  `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 17h6v-6"/><path d="m22 17-8.5-8.5-5 5L2 7"/></svg>`,
	},
	{
		Title:  "Greatest Increase in Buylist Offer",
		Desc:   "Buylist increases indicate a higher sales rate (eg. higher demand). These may be fleeting, do not base a purchase solely off this metric unless dropshipping",
		Offset: 3,
		Option: "greatest_increase_buylist",
		Query: `SELECT calc_date, tcgplayer_id,
                       ROW_NUMBER() OVER (ORDER BY raw_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       ck_buy_price, ck_buy_1d, ck_buy_7d, ck_buy_30d, pct_increase_7d
                  FROM scripts__cardkingdom_buylist_increase_score_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__cardkingdom_buylist_increase_score_cards", "pct_increase_7d <> 0"),
		Sort:        "ranking ASC",
		Priced:      "ck_buy_price",
		PercChanged: "pct_increase_7d",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:    "Today's Buylist",
				CanSort:  true,
				Field:    "ck_buy_price",
				IsDollar: true,
			},
			{
				Title:    "Yesterday",
				CanSort:  true,
				Field:    "ck_buy_1d",
				IsDollar: true,
			},
			{
				Title:    "Last Week",
				CanSort:  true,
				Field:    "ck_buy_7d",
				IsDollar: true,
			},
			{
				Title:    "Last Month",
				CanSort:  true,
				Field:    "ck_buy_30d",
				IsDollar: true,
			},
			{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "pct_increase_7d",
				IsPerc:  true,
			},
		},
		NeedsBuylist: true,
		Short:        "Buylist \u2191",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#08f730" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5"/><path d="M18 12h.01"/><path d="M19 22v-6"/><path d="m22 19-3-3-3 3"/><path d="M6 12h.01"/><circle cx="12" cy="12" r="2"/></svg>`,
	},
	{
		Title:  "Greatest Decrease in Buylist Offer",
		Desc:   "Buylist deecreases indicating a declining sales rate (eg, Less demand). These may be fleeting, do not base a purchase solely off this metric unless dropshipping",
		Offset: 3,
		Option: "greatest_decrease_buylist",
		Query: `SELECT calc_date, tcgplayer_id,
                       ROW_NUMBER() OVER (ORDER BY raw_score DESC) AS ranking,
                       product_name, set_name, product_number, variant,
                       ck_buy_price, ck_buy_1d, ck_buy_7d, ck_buy_30d, pct_decrease_7d
                  FROM scripts__cardkingdom_buylist_decrease_score_cards
                 WHERE game_name = '__GAME__'
                   AND ` + newspaperCalcDateFilter("scripts__cardkingdom_buylist_decrease_score_cards", "pct_decrease_7d <> 0"),
		Sort:        "ranking ASC",
		Priced:      "ck_buy_price",
		PercChanged: "pct_decrease_7d",
		Head: []Heading{
			{
				IsHidden: true,
			},
			{
				IsHidden: true,
			},
			{
				Title:   "Ranking",
				CanSort: true,
				Field:   "ranking",
				IsNum:   true,
			},
			{
				Title:   "Card Name",
				CanSort: true,
				Field:   "product_name",
			},
			{
				Title:   "Edition",
				CanSort: true,
				Field:   "set_name",
			},
			{
				Title: "#",
				Field: "product_number",
			},
			{
				Title: "Finish",
				Field: "variant",
			},
			{
				Title:    "Today's Buylist",
				CanSort:  true,
				Field:    "ck_buy_price",
				IsDollar: true,
			},
			{
				Title:    "Yesterday",
				CanSort:  true,
				Field:    "ck_buy_1d",
				IsDollar: true,
			},
			{
				Title:    "Last Week",
				CanSort:  true,
				Field:    "ck_buy_7d",
				IsDollar: true,
			},
			{
				Title:    "Last Month",
				CanSort:  true,
				Field:    "ck_buy_30d",
				IsDollar: true,
			},
			{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "pct_decrease_7d",
				IsPerc:  true,
			},
		},
		NeedsBuylist: true,
		Short:        "Buylist \u2193",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5"/><path d="m16 19 3 3 3-3"/><path d="M18 12h.01"/><path d="M19 16v6"/><path d="M6 12h.01"/><circle cx="12" cy="12" r="2"/></svg>`,
	},
	{
		Title:  "Newspaper Settings",
		Option: "options",
	},
}

var NewspaperAllRarities = []string{
	"", "M", "R", "U", "C", "S", "M/R", "U/C",
}

var BucketNames = []string{
	"", "$2+", "$5+", "$10+", "$20+", "$35+", "$50+", "$75+",
}

// NewsVars are the PageVars fields only the newspaper fills and reads.
type NewsVars struct {
	ToC            []NewspaperPage
	Headings       []Heading
	Table          []NewspaperResult
	IsOneDay       bool
	CanSwitchDay   bool
	OffsetCards    int
	FilterSet      string
	FilterRarity   string
	FilterBucket   string
	FilterFinish   string
	FilterMinPrice float64
	FilterMaxPrice float64

	CanFilterByPercentage bool
	FilterMinPercChange   float64
	FilterMaxPercChange   float64

	Rarities []string
	Finishes []string
}

// newsQuery is a report's filters and sort, as the page and the API read them.
type newsQuery struct {
	Sort, Dir            string
	Set, Rarity, Finish  string
	Bucket               string
	MinPrice, MaxPrice   *float64
	MinChange, MaxChange *float64
	SkipSets             []string // the page's NewspaperList cookie, by set code
}

// newsFilter applies the query's filters and sort to a report's rows.
func newsFilter(b *mtgmatcher.Backend, page NewspaperPage, rows []NewspaperResult, q newsQuery) []NewspaperResult {
	out := make([]NewspaperResult, 0, len(rows))
	for _, row := range rows {
		if newsKeep(b, page, row, q) {
			out = append(out, row)
		}
	}
	if q.Sort != "" {
		newsSort(out, q.Sort, q.Dir)
	}
	return out
}

// newsKeep reports whether a row passes every filter the query sets.
func newsKeep(b *mtgmatcher.Backend, page NewspaperPage, row NewspaperResult, q newsQuery) bool {
	if len(q.SkipSets) > 0 {
		set, err := b.GetSetByName(row.Edition)
		if err == nil && slices.Contains(q.SkipSets, set.Code) {
			return false
		}
	}
	if q.Set != "" && q.Set != row.Edition {
		return false
	}
	if q.Bucket != "" && q.Bucket != row.BucketName {
		return false
	}
	if q.Finish != "" && q.Finish != row.Variant {
		return false
	}
	if q.Rarity != "" && !newsRarityMatches(q.Rarity, row.Rarity) {
		return false
	}
	return newsInBounds(row, page.Priced, q.MinPrice, q.MaxPrice) &&
		newsInBounds(row, page.PercChanged, q.MinChange, q.MaxChange)
}

// newsRarityMatches compares a rarity's first letter to M, R, U, C, S or a pair like M/R; no rarity passes.
func newsRarityMatches(want, rarity string) bool {
	if rarity == "" {
		return true
	}
	first := strings.ToLower(rarity[:1])
	for _, letter := range strings.Split(want, "/") {
		if strings.ToLower(letter) == first {
			return true
		}
	}
	return false
}

// newsInBounds reports whether a row's field lies within inclusive bounds; no field or no bound passes.
func newsInBounds(row NewspaperResult, field string, lo, hi *float64) bool {
	if field == "" || (lo == nil && hi == nil) {
		return true
	}
	v, _ := strconv.ParseFloat(row.FieldValue(field), 64)
	return (lo == nil || v >= *lo) && (hi == nil || v <= *hi)
}

// newsSort orders rows by a field, numerically when either side is a nonzero number, ties kept.
func newsSort(rows []NewspaperResult, field, dir string) {
	sort.SliceStable(rows, func(i, j int) bool {
		vi := rows[i].FieldValue(field)
		vj := rows[j].FieldValue(field)
		var vif, vjf float64
		vif, _ = strconv.ParseFloat(vi, 64)
		vjf, _ = strconv.ParseFloat(vj, 64)
		numberSort := vif != 0 || vjf != 0
		if dir == "asc" {
			if numberSort {
				return vif < vjf
			}
			return vi < vj
		}
		if numberSort {
			return vif > vjf
		}
		return vi > vj
	})
}

// newsParseBound reads a price or change bound: nil when blank, an error when not a finite number.
func newsParseBound(s string) (*float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, err
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, errors.New("not a finite number")
	}
	return &v, nil
}

// newsPageBound is a bound from the page's form, whose links send 0 for none.
func newsPageBound(s string) *float64 {
	v, err := newsParseBound(s)
	if err != nil || v == nil || *v == 0 {
		return nil
	}
	return v
}

// newsBoundValue is a bound as the page's inputs show it, 0 for none.
func newsBoundValue(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func (s *site) Newspaper(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	b := ds.backend
	sig := verifiedSignature(r)

	pageVars := genPageNav(s, r, "Newspaper", sig)

	// Check if any DB connection was made
	if NewNewspaperDB == nil {
		pageVars.Title = "This feature is not enabled"
		pageVars.ErrorMessage = ErrMsgDenied

		render(w, "news.html", pageVars)
		return
	}

	enabled := GetParamFromSig(sig, "NewsEnabled")
	switch {
	case enabled == "1day":
		pageVars.IsOneDay = true
	case enabled == "3day":
		// the default newspaper view needs no flag
	case enabled == "0day" || (DevMode && !SigCheck):
		force3day := readSetFlag(w, r, "force3day", "BanNewspaperPref")
		if !force3day {
			pageVars.IsOneDay = true
		}
		pageVars.CanSwitchDay = true
	default:
		pageVars.Title = "This feature is BANned"
		pageVars.ErrorMessage = ErrMsgDenied

		render(w, "news.html", pageVars)
		return
	}

	r.ParseForm()
	page := r.FormValue("page")
	sorting := r.FormValue("sort")
	dir := r.FormValue("dir")
	filter := r.FormValue("filter")
	rarity := r.FormValue("rarity")
	bucket := r.FormValue("bucket")
	finish := r.FormValue("finish")
	minPrice := newsPageBound(r.FormValue("min_price"))
	maxPrice := newsPageBound(r.FormValue("max_price"))
	minPercChange := newsPageBound(r.FormValue("min_change"))
	maxPercChange := newsPageBound(r.FormValue("max_change"))
	pageIndex, _ := strconv.Atoi(r.FormValue("index"))

	preferFlavor := readSearchMiscOpts(r).has("preferFlavor")

	newspaperPages := GetNewspaperPages()
	for _, newspage := range newspaperPages {
		if !newspage.shown() {
			continue
		}
		pageVars.ToC = append(pageVars.ToC, newspage)
	}

	pageVars.LastUpdate = GetLastNewspaperUpdate()

	switch page {
	case "":
		render(w, "news.html", pageVars)

		return
	case "options":
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
		return
	case "syp":
		pageVars.Title = "TCGplayer Store-Your-Products List"
		pageVars.ScraperShort = "SYP"
		pageVars.Metadata = map[string]GenericCard{}

		syp, err := findVendorBuylist("SYP")
		if err != nil {
			pageVars.InfoMessage = "SYP not configured yet"
			render(w, "syp.html", pageVars)
			return
		}

		// Handle CSV download using the mtgban-provided writer on the full list
		if r.FormValue("format") == "csv" {
			setCSVDownloadHeaders(w, "syp-buylist.csv")
			if err := mtgban.WriteBuylistToCSV(b, syp, 1, w); err != nil {
				dropDownloadHeaders(w)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		var cardIDs []string
		for cardID := range syp {
			cardIDs = append(cardIDs, cardID)
		}

		var arbit []mtgban.ArbitEntry
		for _, cardID := range cardIDs {
			for _, entry := range syp[cardID] {
				converted := mtgban.InventoryEntry{
					Price:      entry.BuyPrice,
					Quantity:   entry.Quantity,
					Conditions: entry.Conditions,
					URL:        entry.URL,
				}
				arbit = append(arbit, mtgban.ArbitEntry{
					CardID:         cardID,
					InventoryEntry: converted,
					Quantity:       entry.Quantity,
				})
			}
		}

		switch sorting {
		default:
			sortData := resolveSortingData(b, arbitCardIDs(arbit))
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardID == arbit[j].CardID {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return cmpSets(sortData[arbit[i].CardID], sortData[arbit[j].CardID])
			})
		case "alpha":
			sortData := resolveSortingData(b, arbitCardIDs(arbit))
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardID == arbit[j].CardID {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return cmpSetsAlphabetical(sortData[arbit[i].CardID], sortData[arbit[j].CardID])
			})
		case "available":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].InventoryEntry.Quantity > arbit[j].InventoryEntry.Quantity
			})
		case "sell_price":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].InventoryEntry.Price > arbit[j].InventoryEntry.Price
			})
		}
		pageVars.SortOption = sorting

		// If results can't fit in one page, chunk response and enable pagination
		if len(arbit) > MaxSYPResults {
			pageIndex, _ := strconv.Atoi(r.FormValue("p"))
			arbit, pageVars.Pagination = Paginate(arbit, pageIndex, MaxSYPResults, MaxSYPTotalResults)
		}

		// Resolve card metadata only for the visible page: the full SYP list
		// runs to tens of thousands of cards and all the template reads are
		// keyed by the paginated entries.
		for _, entry := range arbit {
			pageVars.Metadata.add(b, entry.CardID, preferFlavor)
		}

		// The HasNo* flags and the name were how this list asked arbit.html
		// to stop being an arbitrage table. syp.html has fixed columns, so
		// the entries are all that is left to carry.
		entry := Arbitrage{Arbit: arbit}

		pageVars.Arb = append(pageVars.Arb, entry)

		render(w, "syp.html", pageVars)

		return
	}

	pageVars.SortOption = sorting
	pageVars.SortDir = dir
	pageVars.FilterSet = filter
	pageVars.FilterRarity = rarity
	pageVars.FilterBucket = bucket
	pageVars.FilterFinish = finish
	pageVars.FilterMinPrice = newsBoundValue(minPrice)
	pageVars.FilterMaxPrice = newsBoundValue(maxPrice)
	pageVars.FilterMinPercChange = newsBoundValue(minPercChange)
	pageVars.FilterMaxPercChange = newsBoundValue(maxPercChange)
	pageVars.Rarities = NewspaperAllRarities

	skipEditionsOpt := readCookie(r, "NewspaperList")

	var results []NewspaperResult
	var report NewspaperPage
	for _, newspage := range pageVars.ToC {
		if newspage.Option != page {
			continue
		}
		report = newspage
		pageVars.Page = newspage.Option
		pageVars.Subtitle = newspage.Title
		pageVars.InfoMessage = newspage.Desc
		pageVars.Headings = newspage.Head
		pageVars.OffsetCards = newspage.Offset

		if newspage.Priced != "" {
			pageVars.CanFilterByPrice = true
		}
		if newspage.PercChanged != "" {
			pageVars.CanFilterByPercentage = true
		}

		if newspage.HasBucket {
			pageVars.Tiers = BucketNames
		}

		results = newspage.Results
		pageVars.Editions = newspage.AvailableEditions
		pageVars.Finishes = newspage.PossibleFinish
		if !pageVars.IsOneDay {
			results = newspage.Results3Day
			pageVars.Editions = newspage.AvailableEditions3Day
			pageVars.Finishes = newspage.PossibleFinish3Day
		}

		// Checked per edition: the delayed edition can be missing while the
		// live one is cached, and an empty table reads as a broken page
		if len(results) == 0 {
			pageVars.InfoMessage = "This data is not ready yet, please try again in a few minutes"
			noteNewspaperStaleness(&pageVars)
			render(w, "news.html", pageVars)
			return
		}

		break
	}

	query := newsQuery{
		Sort:      sorting,
		Dir:       dir,
		Set:       filter,
		Rarity:    rarity,
		Finish:    finish,
		Bucket:    bucket,
		MinPrice:  minPrice,
		MaxPrice:  maxPrice,
		MinChange: minPercChange,
		MaxChange: maxPercChange,
	}
	if skipEditionsOpt != "" {
		query.SkipSets = strings.Split(skipEditionsOpt, ",")
	}
	// A new slice: the cached one is shared and never reordered.
	results = newsFilter(b, report, results, query)

	// Set the page size depending on level
	pageSize := DefaultPageSize
	extraSize, _ := strconv.ParseBool(GetParamFromSig(sig, "NewsLarge"))
	if extraSize {
		pageSize *= 2
	}

	pageVars.Table, pageVars.Pagination = Paginate(results, pageIndex, pageSize, len(results))

	for _, result := range pageVars.Table {
		c := uuid2card(b, result.UUID, preferFlavor)
		pageVars.Cards = append(pageVars.Cards, c)
		pageVars.CardHashes = append(pageVars.CardHashes, result.UUID)
	}

	if len(pageVars.Cards) == 0 {
		unfiltered := filter == "" && rarity == "" && bucket == "" && finish == "" &&
			minPrice == nil && maxPrice == nil && minPercChange == nil && maxPercChange == nil
		if unfiltered {
			pageVars.InfoMessage = "Newspaper is on strike (notify devs!)"
		} else {
			pageVars.InfoMessage = "No results for the current filter options"
		}
	}

	noteNewspaperStaleness(&pageVars)
	render(w, "news.html", pageVars)
}
