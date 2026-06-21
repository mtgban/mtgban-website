package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
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
	newsPageSize = 25

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
	Date     string // calc_date or row_names (hidden)
	UUID     string // product_id or uuid (hidden)
	Ranking  int
	CardName string
	Edition  string
	Number   string
	Variant  string // variant or rarity

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
	// Whether this table has lots of fields that need wider display
	Large bool
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
	"sellers_Today":         func(r *NewspaperResult, s string) { r.SellersToday, _ = strconv.Atoi(s) },
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

func getResults(db *sql.DB, query string) ([]NewspaperResult, error) {
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
	dest := make([]interface{}, len(cols))
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

		// Override a few fields for better integration with the site
		if db == NewNewspaperDB {
			uuid, err := mtgmatcher.MatchId(raw[1], raw[6] != "Normal")
			if err != nil {
				LogPages["Newspaper"].Println("match", raw[1], raw[6], "as", raw[3], raw[4], raw[5], "failed:", err)
				continue
			}
			co, _ := mtgmatcher.GetUUID(uuid)
			raw[0] = co.Rarity
			raw[1] = uuid
			raw[3] = co.Name
			raw[4] = co.Edition
			raw[5] = co.Number
		}

		// Map common fields (first 7 columns are always the same order)
		result := NewspaperResult{
			Date:     raw[0],
			UUID:     raw[1],
			CardName: raw[3],
			Edition:  raw[4],
			Number:   raw[5],
			Variant:  raw[6],
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

		// Allocate a result row with all mapped fields
		results = append(results, result)
	}

	return results, nil
}

var gameMap = map[string]string{
	"magic":     "Magic: The Gathering",
	"lorcana":   "Disney Lorcana",
	"onepiece":  "One Piece Card Game",
	"yugioh":    "YuGiOh",
	"riftbound": "Riftbound: League of Legends Trading Card Game",
	"pokemon":   "Pokemon",
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

func cacheNewspaper() {
	if Config.OfflineKey != "" || SkipNewspaper {
		return
	}

	log.Println("Caching Newspaper data")

	newspaperUUIDs := map[string]struct{}{}

	game, found := gameMap[Config.Game]
	if !found {
		panic("missing game in newspaper map")
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

	for i := range next {
		if next[i].Query == "" {
			continue
		}
		if next[i].NeedsBuylist && Config.Game != DefaultGame {
			continue
		}

		query := strings.ReplaceAll(next[i].Query, "__GAME__", game) + " ORDER BY ranking ASC;"

		results, err := getResults(NewNewspaperDB, query)
		if err != nil {
			log.Println(query, err)
			continue
		}
		if len(results) == 0 {
			ServerNotify("newspaper", next[i].Option+" results are empty", true)
			continue
		}
		if next[i].Results != nil && len(results) < len(next[i].Results)/2 {
			ServerNotify("newspaper", next[i].Option+" too few results "+fmt.Sprint(len(results)), true)
			continue
		}

		editions := []string{""}
		variants := []string{""}
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

		log.Println(next[i].Option, "has", len(results), "elements")
		next[i].Results = results
		next[i].AvailableEditions = editions
		next[i].PossibleFinish = variants

		// Cache UUIDs from spike score pages for the "on:newspaper" search filter
		if next[i].Option == "combined_spike_score" || next[i].Option == "spike_score" {
			for _, result := range results {
				newspaperUUIDs[result.UUID] = struct{}{}
			}
		}

		query = strings.Replace(query, "0 DAY", "3 DAY", -1)
		results3day, err := getResults(NewNewspaperDB, query)
		if err != nil {
			log.Println(query, err)
			continue
		}

		editions3day := []string{""}
		variants3day := []string{""}
		for _, result := range results3day {
			if !slices.Contains(editions3day, result.Edition) {
				editions3day = append(editions3day, result.Edition)
			}
			if !slices.Contains(variants3day, result.Variant) {
				variants3day = append(variants3day, result.Variant)
			}
		}
		sort.Strings(editions3day)
		sort.Strings(variants3day)

		log.Println(next[i].Option, "(3day) has", len(results3day), "elements")
		next[i].Results3Day = results3day
		next[i].AvailableEditions3Day = editions3day
		next[i].PossibleFinish3Day = variants3day
	}

	newspaperPagesPtr.Store(&next)
	newspaperUUIDsPtr.Store(&newspaperUUIDs)
	log.Println("Newspaper UUIDs cached:", len(newspaperUUIDs))

	SetLastNewspaperUpdate(time.Now())
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__tcgplayersalesdata_plus_cardkingdom_spike_score_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__tcgplayersalesdata_plus_cardkingdom_spike_score_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')`,
		Sort: "ranking ASC",
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__tcgplayersalesdata_spike_score_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__tcgplayersalesdata_spike_score_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')`,
		Sort: "ranking ASC",
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')
                   AND pct_gain_7d <> 0`,
		Sort: "ranking ASC",
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__tcgplayer_greatest_decrease_in_vendor_listings_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__tcgplayer_greatest_decrease_in_vendor_listings_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')
                   AND pct_drop_7d <> 0`,
		Sort: "ranking ASC",
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__cardkingdom_buylist_increase_score_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__cardkingdom_buylist_increase_score_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')
                   AND pct_increase_7d <> 0`,
		Sort: "ranking ASC",
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
                   AND calc_date = (SELECT MAX(calc_date)
                                      FROM scripts__cardkingdom_buylist_decrease_score_cards
                                     WHERE game_name = '__GAME__'
                                       AND calc_date <= (SELECT MAX(calc_date)
                                                           FROM scripts__cardkingdom_buylist_decrease_score_cards
                                                          WHERE game_name = '__GAME__') - INTERVAL '0 DAY')
                   AND pct_decrease_7d <> 0`,
		Sort: "ranking ASC",
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
	NewspaperPage{
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

func Newspaper(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Newspaper", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	editions := GetEditions()
	pageVars.EditionsCategories = editions.AllEditionsCategoriesSorted
	pageVars.EditionsByCategory = editions.AllEditionsByCategory
	pageVars.PickerID = "news-editions-picker"

	// Check if any DB connection was made
	if Config.NewNewspaperConfigLine == "" {
		pageVars.Title = "This feature is not enabled"
		pageVars.ErrorMessage = ErrMsgDenied

		render(w, "news.html", pageVars)
		return
	}

	enabled := GetParamFromSig(sig, "NewsEnabled")
	if enabled == "1day" {
		pageVars.IsOneDay = true
	} else if enabled == "3day" {
		// do nothing
	} else if enabled == "0day" || (DevMode && !SigCheck) {
		force3day := readSetFlag(w, r, "force3day", "BanNewspaperPref")
		if !force3day {
			pageVars.IsOneDay = true
		}
		pageVars.CanSwitchDay = true
	} else {
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
	minPrice, _ := strconv.ParseFloat(r.FormValue("min_price"), 64)
	maxPrice, _ := strconv.ParseFloat(r.FormValue("max_price"), 64)
	minPercChange, _ := strconv.ParseFloat(r.FormValue("min_change"), 64)
	maxPercChange, _ := strconv.ParseFloat(r.FormValue("max_change"), 64)
	pageIndex, _ := strconv.Atoi(r.FormValue("index"))

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")

	newspaperPages := GetNewspaperPages()
	for _, newspage := range newspaperPages {
		if newspage.NeedsBuylist && Config.Game != DefaultGame {
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
		pageVars.LargeTable = true
		pageVars.Metadata = map[string]GenericCard{}
		pageVars.NoSettings = true

		syp, err := findVendorBuylist("SYP")
		if err != nil {
			pageVars.InfoMessage = "SYP not configured yet"
			render(w, "arbit.html", pageVars)
			return
		}

		// Handle CSV download using the mtgban-provided writer on the full list
		if r.FormValue("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", `attachment; filename="syp-buylist.csv"`)
			if err := mtgban.WriteBuylistToCSV(syp, 1, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		var cardIds []string
		for cardId := range syp {
			cardIds = append(cardIds, cardId)
		}

		var arbit []mtgban.ArbitEntry
		for _, cardId := range cardIds {
			for _, entry := range syp[cardId] {
				converted := mtgban.InventoryEntry{
					Price:      entry.BuyPrice,
					Quantity:   entry.Quantity,
					Conditions: entry.Conditions,
					URL:        entry.URL,
				}
				arbit = append(arbit, mtgban.ArbitEntry{
					CardId:         cardId,
					InventoryEntry: converted,
					Quantity:       entry.Quantity,
				})
			}

			_, found := pageVars.Metadata[cardId]
			if found {
				continue
			}
			pageVars.Metadata[cardId] = uuid2card(cardId, true, false, preferFlavor)
		}

		switch sorting {
		default:
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardId == arbit[j].CardId {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return sortSets(arbit[i].CardId, arbit[j].CardId)
			})
		case "alpha":
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardId == arbit[j].CardId {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return sortSetsAlphabetical(arbit[i].CardId, arbit[j].CardId, preferFlavor)
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

		entry := Arbitrage{
			Name:        "SYP",
			Key:         "SYP",
			Arbit:       arbit,
			HasNoCredit: true,
			HasNoPrice:  true,
			HasNoArbit:  true,
		}

		pageVars.Arb = append(pageVars.Arb, entry)

		render(w, "arbit.html", pageVars)

		return
	}

	pageVars.SortOption = sorting
	pageVars.SortDir = dir
	pageVars.FilterSet = filter
	pageVars.FilterRarity = rarity
	pageVars.FilterBucket = bucket
	pageVars.FilterFinish = finish
	pageVars.FilterMinPrice = minPrice
	pageVars.FilterMaxPrice = maxPrice
	pageVars.FilterMinPercChange = minPercChange
	pageVars.FilterMaxPercChange = maxPercChange
	pageVars.Rarities = NewspaperAllRarities

	skipEditionsOpt := readCookie(r, "NewspaperList")

	var results []NewspaperResult
	for _, newspage := range pageVars.ToC {
		if newspage.Option != page {
			continue
		}
		pageVars.Page = newspage.Option
		pageVars.Subtitle = newspage.Title
		pageVars.InfoMessage = newspage.Desc
		pageVars.Headings = newspage.Head
		pageVars.LargeTable = newspage.Large
		pageVars.OffsetCards = newspage.Offset

		if newspage.Priced != "" {
			pageVars.CanFilterByPrice = true
		}
		if newspage.PercChanged != "" {
			pageVars.CanFilterByPercentage = true
		}

		if newspage.Results == nil {
			pageVars.InfoMessage = "This data is not ready yet, please try again in a few minutes"
			pageVars.LastUpdate = time.Now()
			render(w, "news.html", pageVars)
			return
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

		break
	}

	if skipEditionsOpt != "" || rarity != "" || filter != "" || bucket != "" || finish != "" {
		var output []NewspaperResult
		for _, result := range results {
			if skipEditionsOpt != "" {
				filters := strings.Split(skipEditionsOpt, ",")
				set, err := mtgmatcher.GetSetByName(result.Edition)
				if err == nil && slices.Contains(filters, set.Code) {
					continue
				}
			}
			if filter != "" && filter != result.Edition {
				continue
			}
			if bucket != "" && bucket != result.BucketName {
				continue
			}
			if finish != "" && finish != result.Variant {
				continue
			}
			if rarity != "" && result.Date != "" {
				cardRarity := result.Date // Date field holds rarity for overridden rows
				if strings.Contains(rarity, "/") {
					rarities := strings.Split(rarity, "/")
					if string(cardRarity[0]) != strings.ToLower(rarities[0]) && string(cardRarity[0]) != strings.ToLower(rarities[1]) {
						continue
					}
				} else if string(cardRarity[0]) != strings.ToLower(rarity) {
					continue
				}
			}
			output = append(output, result)
		}

		results = output
	}

	if sorting != "" {
		for _, newspage := range pageVars.ToC {
			if newspage.Option != page {
				continue
			}

			sort.SliceStable(results, func(i, j int) bool {
				a := results[i].FieldValue(sorting)
				b := results[j].FieldValue(sorting)
				var af, bf float64
				af, _ = strconv.ParseFloat(a, 64)
				bf, _ = strconv.ParseFloat(b, 64)
				numberSort := af != 0 || bf != 0
				if dir == "asc" {
					if numberSort {
						return af < bf
					}
					return a < b
				}
				if numberSort {
					return af > bf
				}
				return a > b
			})
			break
		}
	}

	// Set the page size depending on level
	pageSize := DefaultPageSize
	extraSize, _ := strconv.ParseBool(GetParamFromSig(sig, "NewsLarge"))
	if extraSize {
		pageSize *= 2
	}

	pageVars.Table, pageVars.Pagination = Paginate(results, pageIndex, pageSize, len(results))

	for _, result := range pageVars.Table {
		c := uuid2card(result.UUID, true, false, preferFlavor)
		pageVars.Cards = append(pageVars.Cards, c)
		pageVars.CardHashes = append(pageVars.CardHashes, result.UUID)
	}

	if len(pageVars.Cards) == 0 {
		if filter == "" && rarity == "" && bucket == "" && finish == "" {
			pageVars.InfoMessage = "Newspaper is on strike (notify devs!)"
		} else {
			pageVars.InfoMessage = "No results for the current filter options"
		}
	}

	render(w, "news.html", pageVars)
}
