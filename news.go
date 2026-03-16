package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
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
	// Whether the query applies to the New Newspaper
	NewNewspaper bool
	// Whether the page can be filtered by bucket name
	HasBucket bool
	// Short label for tab navigation
	Short string
	// SVG icon for TOC card display
	Icon template.HTML

	// Cached results of the various queries
	Results     [][]string
	Results3Day [][]string

	// Which editions are available in the cache
	AvailableEditions     []string
	AvailableEditions3Day []string

	// Which finishes are available in the cache
	PossibleFinish     []string
	PossibleFinish3Day []string

	// Whether a relevant buylist is present for the game
	NeedsBuylist bool
}

func getResults(db *sql.DB, query string) ([][]string, error) {
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

	// Result is your slice string
	rawResult := make([][]byte, len(cols))

	// A temporary interface{} slice, containing a variable number of fields
	dest := make([]interface{}, len(cols))
	for e := range rawResult {
		// Put pointers to each string in the interface slice
		dest[e] = &rawResult[e]
	}

	// Allocate the main table scheleton
	var results [][]string

	for rows.Next() {
		result := make([]string, len(cols))
		err := rows.Scan(dest...)
		if err != nil {
			log.Println(err)
			continue
		}

		// Convert the parsed fields into usable strings
		for j, raw := range rawResult {
			if raw != nil {
				result[j] = string(raw)
			}
		}

		// Override a few fields for better integration with the site
		if db == NewNewspaperDB {
			uuid, err := mtgmatcher.MatchId(result[1], result[6] != "Normal")
			if err != nil {
				log.Println("match", result[1], result[6], "as", result[3], result[4], result[5], "failed:", err)
				continue
			}
			co, _ := mtgmatcher.GetUUID(uuid)
			result[0] = co.Rarity
			result[1] = uuid
			result[3] = co.Name
			result[4] = co.Edition
			result[5] = co.Number
		}

		// Allocate a table row with as many fields as returned by the SELECT
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

func cacheNewspaper() {
	log.Println("Caching Newspaper data")

	game, found := gameMap[Config.Game]
	if !found {
		panic("missing game in newspaper map")
	}

	if NewNewspaperDB == nil {
		log.Println("NewNewspaper DB connection was not established, no cache")
		return
	}

	for i := range NewspaperPages {
		if !NewspaperPages[i].NewNewspaper {
			continue
		}
		if NewspaperPages[i].Query == "" {
			continue
		}
		if NewspaperPages[i].NeedsBuylist && Config.Game != DefaultGame {
			continue
		}

		query := NewspaperPages[i].Query + " AND game_name = '" + game + "' ORDER BY ranking ASC;"

		results, err := getResults(NewNewspaperDB, query)
		if err != nil {
			log.Println(query, err)
			continue
		}
		if len(results) == 0 {
			ServerNotify("newspaper", NewspaperPages[i].Option+" results are empty", true)
			continue
		}
		if NewspaperPages[i].Results != nil && len(results) < len(NewspaperPages[i].Results)/2 {
			ServerNotify("newspaper", NewspaperPages[i].Option+" too few results "+fmt.Sprint(len(results)), true)
			continue
		}

		editions := []string{""}
		variants := []string{""}
		for _, result := range results {
			edition := result[4]
			if !slices.Contains(editions, edition) {
				editions = append(editions, edition)
			}
			variant := result[6]
			if !slices.Contains(variants, variant) {
				variants = append(variants, variant)
			}
		}
		sort.Strings(editions)
		sort.Strings(variants)

		log.Println(NewspaperPages[i].Option, "has", len(results), "elements")
		NewspaperPages[i].Results = results
		NewspaperPages[i].AvailableEditions = editions
		NewspaperPages[i].PossibleFinish = variants

		query = strings.Replace(query, "0 DAY", "3 DAY", -1)
		results3day, err := getResults(NewNewspaperDB, query)
		if err != nil {
			log.Println(query, err)
			continue
		}

		editions3day := []string{""}
		variants3day := []string{""}
		for _, result := range results3day {
			edition := result[4]
			if !slices.Contains(editions3day, edition) {
				editions3day = append(editions3day, edition)
			}
			variant := result[6]
			if !slices.Contains(variants3day, variant) {
				variants3day = append(variants3day, variant)
			}
		}
		sort.Strings(editions3day)
		sort.Strings(variants3day)

		log.Println(NewspaperPages[i].Option, "(3day) has", len(results3day), "elements")
		NewspaperPages[i].Results3Day = results3day
		NewspaperPages[i].AvailableEditions3Day = editions3day
		NewspaperPages[i].PossibleFinish3Day = variants3day
	}

	LastNewspaperUpdate = time.Now()
	log.Println("Newspaper All Ready")
}

var NewspaperPages = []NewspaperPage{
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__tcgplayersalesdata_plus_cardkingdom_spike_score_cards)`,
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
		NewNewspaper: true,
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__tcgplayersalesdata_spike_score_cards)`,
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
		NewNewspaper: true,
		HasBucket:    true,
		Short:        "Spike Score",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff0000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3q1 4 4 6.5t3 5.5a1 1 0 0 1-14 0 5 5 0 0 1 1-3 1 1 0 0 0 5 0c0-2-1.5-3-1.5-5q0-2 2.5-4"/></svg>`,
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__tcgplayer_greatest_increase_in_vendor_listings_cards)
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
		NewNewspaper: true,
		Short:        "Vendors \u2191",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#08f730" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 7h6v6"/><path d="m22 7-8.5 8.5-5-5L2 17"/></svg>`,
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__tcgplayer_greatest_decrease_in_vendor_listings_cards)
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
		NewNewspaper: true,
		Short:        "Vendors \u2193",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 17h6v-6"/><path d="m22 17-8.5-8.5-5 5L2 7"/></svg>`,
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__cardkingdom_buylist_increase_score_cards)
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
		NewNewspaper: true,
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
                 WHERE calc_date = (SELECT MAX(calc_date) - INTERVAL '0 DAY'
                                      FROM scripts__cardkingdom_buylist_decrease_score_cards)
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
		NewNewspaper: true,
		NeedsBuylist: true,
		Short:        "Buylist \u2193",
		Icon:         `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5"/><path d="m16 19 3 3 3-3"/><path d="M18 12h.01"/><path d="M19 16v6"/><path d="M6 12h.01"/><circle cx="12" cy="12" r="2"/></svg>`,
	},
	NewspaperPage{
		Title:        "Newspaper Settings",
		Option:       "options",
		NewNewspaper: true,
	},
	NewspaperPage{
		Title:  "Top 25 Singles (3 Week Market Review)",
		Desc:   "Rankings are weighted via prior 21, 15, and 7 days via Retail, Buylist, and several other criteria to arrive at an overall ranking",
		Offset: 3,
		Priced: "n.Buylist",
		Option: "review",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff0000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3q1 4 4 6.5t3 5.5a1 1 0 0 1-14 0 5 5 0 0 1 1-3 1 1 0 0 0 5 0c0-2-1.5-3-1.5-5q0-2 2.5-4"/></svg>`,
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       n.Ranking,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Retail, n.Buylist, n.Vendors
                FROM top_25 n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.uuid <> ''`,
		Sort: "Ranking",
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Ranking",
				CanSort: true,
				Field:   "Ranking",
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:    "Retail",
				CanSort:  true,
				Field:    "Retail",
				IsDollar: true,
			},
			Heading{
				Title:    "Buylist",
				CanSort:  true,
				Field:    "Buylist",
				IsDollar: true,
			},
			Heading{
				Title:   "Vendors",
				CanSort: true,
				Field:   "Vendors",
			},
		},
	},
	NewspaperPage{
		Title:  "Buylist Growth Forecast",
		Desc:   "Forecasting Card Kingdom's Buylist Offers on Cards",
		Offset: 2,
		Priced: "n.Recent_BL",
		Option: "ensemble_forecast",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fae500" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.828 14.828 21 21"/><path d="M21 16v5h-5"/><path d="m21 3-9 9-4-4-6 6"/><path d="M21 8V3h-5"/></svg>`,
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Recent_BL, n.Historical_plus_minus, n.Historical_Median, n.Historical_Max, n.Forecasted_BL, n.Forecast_plus_minus, n.Target_Date, n.Tier, n.Behavior, n.custom_sort
                FROM ensemble_forecast n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.uuid <> ''`,
		Sort:  "n.custom_sort",
		Large: true,
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:    "Most Recent BL",
				CanSort:  true,
				Field:    "Recent_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Historical +/-",
				CanSort:  true,
				Field:    "Historical_plus_minus",
				IsDollar: true,
			},
			Heading{
				Title:    "Historical Median",
				CanSort:  true,
				Field:    "Historical_Median",
				IsDollar: true,
			},
			Heading{
				Title:    "Historical Max",
				CanSort:  true,
				Field:    "Historical_Max",
				IsDollar: true,
			},
			Heading{
				Title:    "Forecasted BL",
				CanSort:  true,
				Field:    "Forecasted_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Forecast +/-",
				CanSort:  true,
				Field:    "Forecast_plus_minus",
				IsDollar: true,
			},
			Heading{
				Title:   "Forecasted Date",
				CanSort: true,
				Field:   "Target_Date",
			},
			Heading{
				Title:   "Tier",
				CanSort: true,
				Field:   "Tier",
			},
			Heading{
				Title:   "Behavior",
				CanSort: true,
				Field:   "Behavior",
			},
			Heading{
				IsHidden: true,
			},
		},
	},
	NewspaperPage{
		Title:  "Greatest Increase in Vendor Listings",
		Desc:   "Information Sourced from TCG: Stock Increases indicate that there is more than enough supply to meet current demand across the reviewed time period (tl:dr - Avoid These)",
		Offset: 2,
		Option: "stock_inc",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#08f730" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 7h6v6"/><path d="m22 7-8.5 8.5-5-5L2 17"/></svg>`,

		PercChanged: "n.Week_Ago_Sellers_Chg",
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Todays_Sellers, n.Week_Ago_Sellers, n.Month_Ago_Sellers, n.Week_Ago_Sellers_Chg
                FROM vendor_levels n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.Week_Ago_Sellers_Chg is not NULL and n.Week_Ago_Sellers_Chg != 0 AND a.rdate <= CURRENT_DATE()`,
		Sort: "n.Week_Ago_Sellers_Chg ASC",
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Today's Seller",
				CanSort: true,
				Field:   "Todays_Sellers",
			},
			Heading{
				Title:   "Last Week",
				CanSort: true,
				Field:   "Week_Ago_Sellers",
			},
			Heading{
				Title:   "Month Ago",
				CanSort: true,
				Field:   "Month_Ago_Sellers",
			},
			Heading{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "Week_Ago_Sellers_Chg",
				IsPerc:  true,
			},
		},
	},
	NewspaperPage{
		Title:  "Greatest Decrease in Vendor Listings",
		Desc:   "Information Sourced from TCG: Stock decreases indicate that there is not enough supply to meet current demand across the reviewed time period (tl:dr - Seek these out)",
		Offset: 2,
		Option: "stock_dec",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 17h6v-6"/><path d="m22 17-8.5-8.5-5 5L2 7"/></svg>`,

		PercChanged: "n.Week_Ago_Sellers_Chg",
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Todays_Sellers, n.Week_Ago_Sellers, n.Month_Ago_Sellers, n.Week_Ago_Sellers_Chg,
                       CASE
                           WHEN n.Week_Ago_Sellers < n.Month_Ago_Sellers
                           THEN CASE
                               WHEN n.Todays_Sellers <= n.Week_Ago_Sellers / 3     THEN 'S'
                               WHEN n.Todays_Sellers <= n.Week_Ago_Sellers / 2     THEN 'A'
                               WHEN n.Todays_Sellers <= n.Week_Ago_Sellers * 2 / 3 THEN 'B'
                               WHEN n.Todays_Sellers <= n.Week_Ago_Sellers * 3 / 4 THEN 'C'
                               WHEN n.Todays_Sellers <= n.Week_Ago_Sellers * 4 / 5 THEN 'D'
                               WHEN n.Todays_Sellers <  n.Week_Ago_Sellers         THEN 'E'
                               ELSE ''
                           END
                           ELSE ''
                       END AS 'Trending'
                FROM vendor_levels n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.Week_Ago_Sellers_Chg is not NULL and n.Week_Ago_Sellers_Chg != 0`,
		Sort: "n.Week_Ago_Sellers_Chg DESC",
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Today's Sellers",
				CanSort: true,
				Field:   "Todays_Sellers",
			},
			Heading{
				Title:   "Last Week Sellers",
				CanSort: true,
				Field:   "Week_Ago_Sellers",
			},
			Heading{
				Title:   "Month Ago Sellers",
				CanSort: true,
				Field:   "Month_Ago_Sellers",
			},
			Heading{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "Week_Ago_Sellers_Chg",
				IsPerc:  true,
			},
			Heading{
				Title:   "Tier",
				CanSort: true,
				Field:   "Trending",
			},
		},
	},
	NewspaperPage{
		Title:  "Greatest Increase in Buylist Offer",
		Desc:   "Information Sourced from CK: buylist increases indicate a higher sales rate (eg. higher demand). These may be fleeting, do not base a purchase solely off this metric unless dropshipping",
		Offset: 2,
		Priced: "n.Todays_BL",
		Option: "buylist_inc",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#08f730" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5"/><path d="M18 12h.01"/><path d="M19 22v-6"/><path d="m22 19-3-3-3 3"/><path d="M6 12h.01"/><circle cx="12" cy="12" r="2"/></svg>`,
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Todays_BL, n.Yesterday_BL, n.Week_Ago_BL, n.Month_Ago_BL, n.Week_Ago_BL_Chg
                FROM buylist_levels n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.Week_Ago_BL_Chg is not NULL and n.Week_Ago_BL_Chg != 0 and n.Yesterday_BL >= 1.25 and n.Todays_BL >= 1.25`,
		Sort: "n.Week_Ago_BL_Chg DESC",
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:    "Today's Buylist",
				CanSort:  true,
				Field:    "Todays_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Yesterday",
				CanSort:  true,
				Field:    "Yesterday_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Last Week",
				CanSort:  true,
				Field:    "Week_Ago_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Last Month",
				CanSort:  true,
				Field:    "Month_Ago_BL",
				IsDollar: true,
			},
			Heading{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "Week_Ago_BL_Chg",
				IsPerc:  true,
			},
		},
	},
	NewspaperPage{
		Title:  "Greatest Decrease in Buylist Offer",
		Desc:   "Information Sourced from CK: Buylist Decreases indicate a declining sales rate (eg, Less demand). These may be fleeting, do not base a purchase solely off this metric unless dropshipping",
		Offset: 2,
		Priced: "n.Todays_BL",
		Option: "buylist_dec",
		Icon:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fa7000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5"/><path d="m16 19 3 3 3-3"/><path d="M18 12h.01"/><path d="M19 16v6"/><path d="M6 12h.01"/><circle cx="12" cy="12" r="2"/></svg>`,
		Query: `SELECT DISTINCT n.row_names, n.uuid,
                       a.Name, a.Set, a.Number, a.Rarity,
                       n.Todays_BL, n.Yesterday_BL, n.Week_Ago_BL, n.Month_Ago_BL, n.Week_Ago_BL_Chg
                FROM buylist_levels n
                LEFT JOIN mtgjson_portable a ON n.uuid = a.uuid
                WHERE n.Week_Ago_BL_Chg is not NULL and n.Week_Ago_BL_Chg != 0 and n.Yesterday_BL >= 1.25 and n.Todays_BL >= 1.25`,
		Sort: "n.Week_Ago_BL_Chg ASC",
		Head: []Heading{
			Heading{
				IsHidden: true,
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:   "Card Name",
				CanSort: true,
				Field:   "Name",
			},
			Heading{
				Title:   "Edition",
				CanSort: true,
				Field:   "a.Set",
			},
			Heading{
				Title:           "#",
				ConditionalSort: true,
				Field:           "a.Number",
			},
			Heading{
				IsHidden: true,
			},
			Heading{
				Title:    "Today's Buylist",
				CanSort:  true,
				Field:    "Todays_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Yesterday",
				CanSort:  true,
				Field:    "Yesterday_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Last Week",
				CanSort:  true,
				Field:    "Week_Ago_BL",
				IsDollar: true,
			},
			Heading{
				Title:    "Last Month",
				CanSort:  true,
				Field:    "Month_Ago_BL",
				IsDollar: true,
			},
			Heading{
				Title:   "Weekly % Change",
				CanSort: true,
				Field:   "Week_Ago_BL_Chg",
				IsPerc:  true,
			},
		},
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

func getLastDBUpdate(db *sql.DB) (time.Time, error) {
	var lastUpdate string
	err := db.QueryRow("SELECT data_value FROM newspaper_updated").Scan(&lastUpdate)
	if err != nil {
		return time.Now(), err
	}
	return time.Parse("2006-01-02", lastUpdate)
}

func Newspaper(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Newspaper", sig)

	// Check if any DB connection was made
	if Config.DBAddress == "" && Config.NewNewspaperConfigLine == "" {
		pageVars.Title = "This feature is not enabled"
		pageVars.ErrorMessage = ErrMsgDenied

		render(w, "news.html", pageVars)
		return
	}

	var db *sql.DB
	enabled := GetParamFromSig(sig, "NewsEnabled")
	if enabled == "1day" {
		db = Newspaper1dayDB
		pageVars.IsOneDay = true
	} else if enabled == "3day" {
		db = Newspaper3dayDB
	} else if enabled == "0day" || (DevMode && !SigCheck) {
		force3day := readSetFlag(w, r, "force3day", "BanNewspaperPref")
		if force3day {
			db = Newspaper3dayDB
		} else {
			db = Newspaper1dayDB
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

	var query, defSort string

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")

	oldMode := page == "old"
	for _, newspage := range NewspaperPages {
		if page == newspage.Option {
			oldMode = !newspage.NewNewspaper
			break
		}
	}

	for _, newspage := range NewspaperPages {
		if (oldMode && newspage.NewNewspaper) || (!oldMode && !newspage.NewNewspaper) {
			continue
		}
		if newspage.NeedsBuylist && Config.Game != DefaultGame {
			continue
		}
		if !newspage.NewNewspaper && Config.Game != DefaultGame {
			continue
		}
		pageVars.ToC = append(pageVars.ToC, newspage)
	}

	if Config.Game == DefaultGame {
		pageVars.Nav = insertNavBar("Newspaper", pageVars.Nav, []NavElem{
			NavElem{
				Name:   "Archive",
				Short:  "📰",
				Link:   "/newspaper?page=old",
				Active: oldMode,
				Class:  "selected",
			},
			NavElem{
				Name:   "TCG Syp List",
				Short:  "📋",
				Link:   "/newspaper?page=syp",
				Active: page == "syp",
				Class:  "selected",
			},
		})
	}

	pageVars.LastUpdate = LastNewspaperUpdate
	if oldMode {
		var err error
		pageVars.LastUpdate, err = getLastDBUpdate(db)
		if err != nil {
			log.Println(err)
		}
		pageVars.Page = "old"
	}

	switch page {
	case "", "old":
		render(w, "news.html", pageVars)

		return
	case "options":
		pageVars.Subtitle = "Options"

		pageVars.Editions = AllEditionsKeys
		pageVars.EditionsMap = AllEditionsMap

		render(w, "news.html", pageVars)

		return
	case "syp":
		pageVars.Title = "TCGplayer Store-Your-Products List"
		pageVars.ScraperShort = "SYP"
		pageVars.LargeTable = true
		pageVars.Metadata = map[string]GenericCard{}

		syp, err := findVendorBuylist("SYP")
		if err != nil {
			pageVars.InfoMessage = "SYP not configured yet"
			render(w, "arbit.html", pageVars)
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

			meta := uuid2card(cardId, true, false, preferFlavor)

			// This is the SYP-specific page, turn off the small reminder
			// character that says whether a card is on SYP or not
			meta.SypList = false

			pageVars.Metadata[cardId] = meta
			if pageVars.Metadata[cardId].Reserved {
				pageVars.HasReserved = true
			}
			if pageVars.Metadata[cardId].Stocks {
				pageVars.HasStocks = true
			}
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

		// Handle CSV download
		if r.FormValue("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", `attachment; filename="syp-buylist.csv"`)
			writer := csv.NewWriter(w)
			writer.Write([]string{"Card Name", "Edition", "Number", "Finish", "Condition", "Buy Price", "Quantity"})
			for _, entry := range arbit {
				co, err := mtgmatcher.GetUUID(entry.CardId)
				if err != nil {
					continue
				}
				finish := "Regular"
				if co.Foil {
					finish = "Foil"
				} else if co.Etched {
					finish = "Etched"
				}
				writer.Write([]string{
					co.Card.Name,
					co.Edition,
					co.Card.Number,
					finish,
					entry.InventoryEntry.Conditions,
					fmt.Sprintf("%.2f", entry.InventoryEntry.Price),
					fmt.Sprintf("%d", entry.Quantity),
				})
			}
			writer.Flush()
			return
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

	var skipEditions string
	skipEditionsOpt := readCookie(r, "NewspaperList")
	if skipEditionsOpt != "" {
		filters := strings.Split(skipEditionsOpt, ",")
		for _, code := range filters {
			// XXX: is set code available on the db row?
			set, err := mtgmatcher.GetSet(code)
			if err != nil {
				continue
			}
			skipEditions += " AND a.Set <> '" + set.Name + "'"
		}
	}

	var results [][]string
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

		if newspage.NewNewspaper {
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

		// Get the total number of rows for the query
		qs := strings.Split(newspage.Query, "FROM")
		if len(qs) < 2 {
			log.Println("Invalid query for page", page, " - \n", newspage.Query)
			panic("Invalid query, missing at least a FROM to split on")
		}

		// Set query to retrieve total number of matches
		subQuery := "SELECT COUNT(DISTINCT n.uuid) FROM" + strings.Join(qs[1:], "FROM")

		// Add any extra filter that might affect number of results
		if filter != "" {
			subQuery += " AND a.Set = '" + strings.Replace(filter, "'", "''", -1) + "'"
		}
		if rarity != "" {
			subQuery += " AND "
			if strings.Contains(rarity, "/") {
				subQuery += fmt.Sprintf("(a.Rarity = '%c' OR a.Rarity = '%c')", rarity[0], rarity[2])
			} else if rarity == "S" {
				// FIXME: this should be fixed in the DB
				subQuery += "a.Rarity = 'special'"
			} else {
				subQuery += "a.Rarity = '" + rarity + "'"
			}
		}
		if newspage.Priced != "" && minPrice != 0 {
			subQuery += " AND " + newspage.Priced + " > " + fmt.Sprintf("%.2f", minPrice)
		}
		if newspage.Priced != "" && maxPrice != 0 {
			subQuery += " AND " + newspage.Priced + " < " + fmt.Sprintf("%.2f", maxPrice)
		}
		if newspage.PercChanged != "" && minPercChange != 0 {
			subQuery += " AND " + newspage.PercChanged + " > " + fmt.Sprintf("%.2f", minPercChange/100)
		}
		if newspage.PercChanged != "" && maxPercChange != 0 {
			subQuery += " AND " + newspage.PercChanged + " < " + fmt.Sprintf("%.2f", maxPercChange/100)
		}

		subQuery += skipEditions

		// Sub Go!
		var elements int
		err := db.QueryRow(subQuery + ";").Scan(&elements)
		if err != nil {
			log.Println(subQuery)
			log.Println("pagination disabled", err)
		}
		// Ceiling division to get number of pages
		pages := (elements + newsPageSize - 1) / newsPageSize
		if DevMode {
			log.Println(page, "page has", elements, "elements, for a total of", pages, "pages")
		}
		pageVars.TotalIndex = pages
		if pageIndex <= 1 {
			pageIndex = 1
		} else if pageIndex > pageVars.TotalIndex {
			pageIndex = pageVars.TotalIndex
		}
		pageVars.CurrentIndex = pageIndex
		if pageVars.CurrentIndex > 1 {
			pageVars.PrevIndex = pageVars.CurrentIndex - 1
		}
		if pageVars.CurrentIndex < pageVars.TotalIndex {
			pageVars.NextIndex = pageVars.CurrentIndex + 1
		}

		query = newspage.Query
		defSort = newspage.Sort

		// Repeat as above to retrieve the possible editions
		subQuery = "SELECT DISTINCT a.Set FROM" + strings.Join(qs[1:], "FROM") + skipEditions + " ORDER BY a.Set ASC"
		rows, err := db.Query(subQuery + ";")
		if err != nil {
			log.Println(subQuery)
			log.Println("editions disabled", err)
			break
		}
		// First element is always initialized
		pageVars.Editions = []string{""}
		// Iterate over subresults
		for rows.Next() {
			var tmp string
			err := rows.Scan(&tmp)
			if err != nil {
				continue
			}
			pageVars.Editions = append(pageVars.Editions, tmp)
		}
	}

	if results == nil {
		// Add any extra filter before sorting
		// Note that this requires every query to end with an applicable WHERE clause
		if filter != "" {
			query += " AND a.Set = '" + strings.Replace(filter, "'", "''", -1) + "'"
		}
		if rarity != "" {
			query += " AND "
			if strings.Contains(rarity, "/") {
				query += fmt.Sprintf("(a.Rarity = '%c' OR a.Rarity = '%c')", rarity[0], rarity[2])
			} else if rarity == "S" {
				query += "a.Rarity = 'special'"
			} else {
				query += "a.Rarity = '" + rarity + "'"
			}
		}

		// Check for price limits
		if minPrice != 0 || maxPrice != 0 {
			for _, newspage := range pageVars.ToC {
				if newspage.Option != page || newspage.Priced == "" {
					continue
				}
				if minPrice != 0 {
					query += " AND " + newspage.Priced + " > " + fmt.Sprintf("%.2f", minPrice)
				}
				if maxPrice != 0 {
					query += " AND " + newspage.Priced + " < " + fmt.Sprintf("%.2f", maxPrice)
				}
			}
		}

		if minPercChange != 0 || maxPercChange != 0 {
			for _, newspage := range pageVars.ToC {
				if newspage.Option != page && newspage.PercChanged == "" {
					continue
				}
				if minPercChange != 0 {
					query += " AND " + newspage.PercChanged + " > " + fmt.Sprintf("%.2f", minPercChange/100)
				}
				if maxPercChange != 0 {
					query += " AND " + newspage.PercChanged + " < " + fmt.Sprintf("%.2f", maxPercChange/100)
				}
			}
		}

		query += skipEditions

		// Set sorting options
		if sorting != "" {
			// Make sure this field is allowed to be sorted
			canSort := false
			for i := range pageVars.Headings {
				if pageVars.Headings[i].Field == sorting {
					canSort = pageVars.Headings[i].CanSort
					if pageVars.Headings[i].ConditionalSort && filter != "" {
						canSort = true
					}
					break
				}
			}
			if canSort {
				// Define a custom order for our special scale
				if sorting == "Trending" {
					sorting = `CASE
                            WHEN Trending = 'S' THEN '7'
                            WHEN Trending = 'A' THEN '6'
                            WHEN Trending = 'B' THEN '5'
                            WHEN Trending = 'C' THEN '4'
                            WHEN Trending = 'D' THEN '3'
                            WHEN Trending = 'E' THEN '2'
                            WHEN Trending = ''  THEN '1'
                            ELSE Trending
                        END`
				}
				query += " ORDER BY " + sorting
				if dir == "asc" {
					query += " ASC"
				} else if dir == "desc" {
					query += " DESC"
				}
			}
		} else if defSort != "" {
			query += " ORDER BY " + defSort
		}
		// Keep things limited + pagination
		query = fmt.Sprintf("%s LIMIT %d OFFSET %d", query, newsPageSize, newsPageSize*(pageIndex-1))

		// GO GO GO
		output, err := getResults(db, query)
		if err != nil {
			log.Println(query, err)
		}
		pageVars.Table = output
	} else {
		if skipEditionsOpt != "" || rarity != "" || filter != "" || bucket != "" || finish != "" {
			var output [][]string
			for _, result := range results {
				cardRarity := result[0]
				edition := result[4]
				finishName := result[6]
				bucketName := result[7]
				if skipEditionsOpt != "" {
					filters := strings.Split(skipEditionsOpt, ",")
					set, err := mtgmatcher.GetSetByName(edition)
					if err == nil && slices.Contains(filters, set.Code) {
						continue
					}
				}
				if filter != "" && filter != edition {
					continue
				}
				if bucket != "" && bucket != bucketName {
					continue
				}
				if finish != "" && finish != finishName {
					continue
				}
				if rarity != "" && cardRarity != "" {
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
				numberSort := false
				col := -1
				for i, heading := range newspage.Head {
					if heading.Field == sorting {
						numberSort = heading.IsPerc || heading.IsDollar || heading.IsNum
						col = i
						break
					}
				}
				if col < 0 {
					break
				}

				sort.SliceStable(results, func(i, j int) bool {
					var a, b float64
					if numberSort {
						a, _ = strconv.ParseFloat(results[i][col], 64)
						b, _ = strconv.ParseFloat(results[j][col], 64)
					}
					if dir == "asc" {
						if numberSort {
							return a < b
						}
						return results[i][col] < results[j][col]
					}
					if numberSort {
						return a > b
					}
					return results[i][col] > results[j][col]
				})
			}
		}

		// Set the page size depending on level
		pageSize := DefaultPageSize
		extraSize, _ := strconv.ParseBool(GetParamFromSig(sig, "NewsLarge"))
		if extraSize {
			pageSize *= 2
		}

		pageVars.Table, pageVars.Pagination = Paginate(results, pageIndex, pageSize, len(results))
	}

	for _, result := range pageVars.Table {
		c := uuid2card(result[1], true, false, preferFlavor)
		pageVars.Cards = append(pageVars.Cards, c)
		pageVars.CardHashes = append(pageVars.CardHashes, result[1])

		if c.Reserved {
			pageVars.HasReserved = true
		}
		if c.Stocks {
			pageVars.HasStocks = true
		}
		if c.SypList {
			pageVars.HasSypList = true
		}
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
