package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"golang.org/x/exp/slices"
)

type SearchConfig struct {
	// The search strategy to be used
	SearchMode string

	// Sort strategy
	SortMode string

	// Only for SearchMode == "hashing"
	UUIDs []string

	// Name of the card being searched (may be blank)
	CleanQuery string

	// Full query searched (may be blank)
	FullQuery string

	// String where to stash non-user facing data
	PrivateData string

	// Chain of filters to be applied to card filtering
	CardFilters []FilterElem

	// Chain of filters to be applied to scraper filtering
	StoreFilters []FilterStoreElem

	// Chain of filters to be applied to single prices
	PriceFilters []*FilterPriceElem

	// Chain of filters to be applied to entries
	EntryFilters []FilterEntryElem

	// Chain of filters to be applied after the search
	PostFilters []FilterPostElem

	// Skip retail searches entirely
	SkipRetail bool

	// Skip buylist searches entirely
	SkipBuylist bool
}

type FilterElem struct {
	Name   string
	Negate bool
	Values []string

	// List of additional filters that are run *before* the main filter
	// and determine whether to run it or not
	Subfilters []FilterElem

	// List of SetCode the filter should be applied to
	ApplyTo []string
}

type FilterStoreElem struct {
	Name   string
	Negate bool
	Values []string

	// Whether or not the filter should treat index scrapers differently
	IncludeIndex bool

	OnlyForSeller bool
	OnlyForVendor bool
}

type FilterPriceElem struct {
	Name   string
	Negate bool
	Value  float64

	// Function used to derive a store price
	Price4Store func(string, string) float64

	// All stores sources (shorthands) present in the map
	Stores []string

	// Cache of cardId:prices used in the filter
	PriceCache map[string][]float64

	// Mutex protecting PriceCache map from concurrent access
	Mutex sync.RWMutex

	// List of stores the filter should be applied to
	ApplyTo []string

	OnlyForSeller bool
	OnlyForVendor bool
}

type FilterEntryElem struct {
	Name   string
	Negate bool
	Values []string

	OnlyForSeller bool
	OnlyForVendor bool
}

type FilterPostElem struct {
	Name   string
	Values []string

	OnlyForSeller bool
	OnlyForVendor bool
}

// Return a comma-separated string of set codes, from a comma-separated
// list of codes or edition names. If no match is found, the input code
// segment is returned as-is.
func fixupEditionNG(code string) []string {
	var out []string

	code = strings.TrimSpace(code)
	for _, field := range strings.Split(code, ",") {
		field = strings.TrimPrefix(field, "\"")
		field = strings.TrimSuffix(field, "\"")

		set, err := mtgmatcher.GetSet(field)
		if err == nil {
			out = append(out, set.Code)
			continue
		}
		set, err = mtgmatcher.GetSetByName(field)
		if err == nil {
			out = append(out, set.Code)
			continue
		}
		// Not found, return as-is
		out = append(out, field)
	}
	return out
}

// Return a list of shorthands representing the selected stores
func fixupStoreCodeNG(code string) []string {
	code = strings.TrimSpace(code)
	code = strings.ToLower(code)

	filters := strings.Split(code, ",")
	for i := range filters {
		filters[i] = strings.TrimPrefix(filters[i], "\"")
		filters[i] = strings.TrimSuffix(filters[i], "\"")

		// Validate the input against the registered scrapers
		for shorthand, name := range ScraperNames {
			if strings.ToLower(name) == filters[i] ||
				strings.ToLower(shorthand) == filters[i] {
				filters[i] = strings.ToLower(shorthand)
			}
		}

		// The manual renames from search.go
		switch filters[i] {
		case "TCGplayer":
			filters[i] = strings.ToLower("TCGPlayer")
		case "TCGplayer Direct":
			filters[i] = strings.ToLower("TCGDirect")
		}
	}
	return filters
}

func fixupRarityNG(code string) []string {
	code = strings.ToLower(code)
	filters := strings.Split(code, ",")
	for i := range filters {
		switch filters[i] {
		case "c":
			filters[i] = "common"
		case "u":
			filters[i] = "uncommon"
		case "r":
			filters[i] = "rare"
		case "m":
			filters[i] = "mythic"
		case "s":
			filters[i] = "special"
		case "t":
			filters[i] = "token"
		case "o":
			filters[i] = "oversize"
		}
	}
	return filters
}

func fixupNumberNG(code string) []string {
	code = strings.ToLower(code)
	filters := strings.Split(code, ",")
	for i := range filters {
		filters[i] = strings.TrimLeft(filters[i], "0")
	}
	return filters
}

func fixupFinishNG(code string) []string {
	return strings.Split(strings.ToLower(code), ",")
}

func fixupTypeNG(code string) []string {
	filters := strings.Split(code, ",")
	for i := range filters {
		filters[i] = strings.TrimPrefix(filters[i], "\"")
		filters[i] = strings.TrimSuffix(filters[i], "\"")

		filters[i] = mtgmatcher.Title(filters[i])
	}
	return filters
}

func fixupDateNG(code string) string {
	set, err := mtgmatcher.GetSet(strings.ToUpper(code))
	if err == nil {
		code = set.ReleaseDate
	}
	_, err = time.Parse("2006-01-02", code)
	if err == nil {
		return code
	}
	return ""
}

var colorMap = map[string][]string{
	"c":           {},
	"colorless":   {},
	"white":       {"W"},
	"blue":        {"U"},
	"black":       {"B"},
	"red":         {"R"},
	"green":       {"G"},
	"azorius":     {"W", "U"},
	"dimir":       {"U", "B"},
	"rakdos":      {"B", "R"},
	"gruul":       {"R", "G"},
	"selesnya":    {"G", "W"},
	"orzhov":      {"W", "B"},
	"izzet":       {"U", "R"},
	"golgari":     {"B", "G"},
	"boros":       {"R", "W"},
	"simic":       {"G", "U"},
	"bant":        {"G", "W", "U"},
	"esper":       {"W", "U", "B"},
	"grixis":      {"U", "B", "R"},
	"jund":        {"B", "G", "R"},
	"naya":        {"R", "G", "W"},
	"abzan":       {"W", "B", "G"},
	"jeskai":      {"U", "R", "W"},
	"sultai":      {"B", "G", "U"},
	"mardu":       {"R", "W", "B"},
	"temur":       {"G", "U", "R"},
	"lorehold":    {"R", "W"},
	"prismari":    {"U", "R"},
	"quandrix":    {"B", "G"},
	"silverquill": {"U", "R"},
	"witherbloom": {"B", "G"},
	"chaos":       {"B", "G", "R", "U"},
	"aggression":  {"B", "G", "R", "W"},
	"altruism":    {"G", "R", "U", "W"},
	"growth":      {"B", "G", "U", "W"},
	"artifice":    {"B", "R", "U", "W"},
	"m":           {"W", "U", "B", "R", "G"},
	"multi":       {"W", "U", "B", "R", "G"},
	"multicolor":  {"W", "U", "B", "R", "G"},
}

func fixupColorNG(code string) []string {
	code = strings.ToLower(code)
	colors, found := colorMap[code]
	if found {
		return colors
	}
	_, found = colorValues[code]
	if found {
		return []string{code}
	}
	return strings.Split(code, "")
}

// Validate UUIDs, convert them to mtgban format
func fixupIDs(code string) []string {
	fields := strings.Split(code, ",")
	for i, field := range fields {
		var uuid string
		_, err := mtgmatcher.GetUUID(field)
		if err == nil {
			continue
		}
		// XXX: id funcs report the first finish available
		uuid = mtgmatcher.Scryfall2UUID(field)
		if uuid != "" {
			fields[i] = uuid
			continue
		}
		uuid = mtgmatcher.Tcg2UUID(field)
		if uuid != "" {
			fields[i] = uuid
			continue
		}
	}
	return fields
}

func sealedname2uuid(name string) string {
	name = strings.TrimLeft(strings.TrimRight(name, "\" "), "\" ")
	res, err := mtgmatcher.SearchSealedEquals(name)
	if err != nil {
		return ""
	}
	return res[0]
}

func cardobject2sources(co *mtgmatcher.CardObject) []string {
	var values []string
	if co.Sealed {
		values = co.SourceProducts["sealed"]
	} else if co.Etched {
		values = co.SourceProducts["etched"]
		// Due to how `card` is represented in mtg-sealed-content,
		// some etched cards get mapped to plain foil finish
		if values == nil {
			values = co.SourceProducts["foil"]
		}
	} else if co.Foil {
		values = co.SourceProducts["foil"]
	} else {
		values = co.SourceProducts["nonfoil"]
	}
	return values
}

func fixupPicks(code string) []string {
	co, err := mtgmatcher.GetUUID(code)
	if err != nil {
		co, err = mtgmatcher.GetUUID(sealedname2uuid(code))
		if err != nil {
			return []string{}
		}
	}
	if !co.Sealed {
		return []string{}
	}

	picks, err := mtgmatcher.GetPicksForSealed(co.SetCode, co.UUID)
	if err != nil {
		return []string{}
	}

	return picks
}

func fixupContents(code string) []string {
	co, err := mtgmatcher.GetUUID(code)
	if err != nil {
		co, err = mtgmatcher.GetUUID(sealedname2uuid(code))
		if err != nil {
			return []string{}
		}
	}
	if !co.Sealed {
		return []string{}
	}

	return []string{co.UUID}
}

func fixupContainer(code string) []string {
	co, err := mtgmatcher.GetUUID(code)
	if err != nil {
		results, err := mtgmatcher.SearchEquals(code)
		if err != nil {
			return []string{}
		}

		var sources []string
		for _, result := range results {
			co, err := mtgmatcher.GetUUID(result)
			if err != nil {
				continue
			}
			sources = append(sources, cardobject2sources(co)...)
		}
		return sources
	}

	return cardobject2sources(co)
}

func price4seller(cardId, shorthand string) float64 {
	inv, err := findSellerInventory(shorthand)
	if err != nil {
		return 0
	}
	entries, found := inv[cardId]
	if !found {
		return 0
	}
	return entries[0].Price
}

func price4vendor(cardId, shorthand string) float64 {
	bl, err := findVendorBuylist(shorthand)
	if err != nil {
		return 0
	}
	entries, found := bl[cardId]
	if !found {
		return 0
	}
	return entries[0].BuyPrice
}

var re *regexp.Regexp

var FilterOperations = map[string][]string{
	"sm":        []string{":"},
	"skip":      []string{":"},
	"sort":      []string{":"},
	"edition":   []string{":"},
	"e":         []string{":"},
	"s":         []string{":"},
	"se":        []string{":"},
	"ee":        []string{":"},
	"number":    []string{":", ">", "<"},
	"cn":        []string{":", ">", "<"},
	"cne":       []string{":"},
	"date":      []string{":", ">", "<"},
	"r":         []string{":", ">", "<"},
	"t":         []string{":"},
	"f":         []string{":"},
	"c":         []string{":"},
	"color":     []string{":"},
	"unpack":    []string{":"},
	"contents":  []string{":"},
	"container": []string{":"},
	"decklist":  []string{":"},
	"ci":        []string{":"},
	"identity":  []string{":"},
	"cond":      []string{":", ">", "<"},
	"condr":     []string{":", ">", "<"},
	"condb":     []string{":", ">", "<"},
	"id":        []string{":"},
	"is":        []string{":"},
	"not":       []string{":"},
	"on":        []string{":"},
	"price":     []string{">", "<"},
	"buy_price": []string{">", "<"},
	"arb_price": []string{">", "<"},
	"rev_price": []string{">", "<"},
	"store":     []string{":"},
	"seller":    []string{":"},
	"vendor":    []string{":"},
	"region":    []string{":"},
}

func init() {
	var regexpOptions string
	var opts []string

	for key := range FilterOperations {
		opts = append(opts, key)
	}
	// Sort keys by shorter and alphabetical (since they may be the more common)
	sort.Slice(opts, func(i, j int) bool {
		if len(opts[i]) == len(opts[j]) {
			return opts[i] < opts[j]
		}
		return len(opts[i]) < len(opts[j])
	})

	regexpOptions = fmt.Sprintf(`-?(%s%s)[:<>](("([^"]+)"|\S+))+`, strings.Join(opts, "|"), strings.ToUpper(strings.Join(opts, "|")))

	re = regexp.MustCompile(regexpOptions)
}

func parseSearchOptionsNG(query string, blocklistRetail, blocklistBuylist []string, miscSearchOpts []string) (config SearchConfig) {
	rawQuery := query
	var filters []FilterElem
	var filterStores []FilterStoreElem
	var filterPrices []*FilterPriceElem
	var filterEntries []FilterEntryElem
	var filterPost []FilterPostElem

	// Apply blocklists as if they were options, need to pass them through
	// the fixup due to upper/lower casing
	// This needs to be the first element for performance and for supporting
	// hashing searches
	if blocklistRetail != nil {
		filterStores = append(filterStores, FilterStoreElem{
			Name:          "seller",
			Negate:        true,
			Values:        fixupStoreCodeNG(strings.Join(blocklistRetail, ",")),
			OnlyForSeller: true,
		})
	}
	if blocklistBuylist != nil {
		filterStores = append(filterStores, FilterStoreElem{
			Name:          "vendor",
			Negate:        true,
			Values:        fixupStoreCodeNG(strings.Join(blocklistBuylist, ",")),
			OnlyForVendor: true,
		})
	}

	// Support our UUID style when there are no options to parse
	if !strings.Contains(query, ":") && !strings.Contains(query, "|") {
		// XXX should use the idlookup filter
		uuids := fixupIDs(query)
		for _, uuid := range uuids {
			co, err := mtgmatcher.GetUUID(uuid)
			if err != nil {
				continue
			}

			// Save the last name found
			config.CleanQuery = co.Name
			// Rebuild the full query for this card
			config.FullQuery = genQuery(co)

			// Set the special search mode and its data source
			config.SearchMode = "hashing"
			config.UUIDs = append(config.UUIDs, uuid)
		}

		// Early return if hash was found
		if config.SearchMode != "" {
			// When multiple fields are requested it's impossible to rebuild
			// the query, so just ignore it
			if len(config.UUIDs) != 1 {
				config.CleanQuery = ""
				config.FullQuery = ""
			}
			config.StoreFilters = filterStores
			return
		}
	}

	// Clean any special characters from the main query, handle it later
	var lastChar string
	if strings.HasSuffix(query, "&") || strings.HasSuffix(query, "*") || strings.HasSuffix(query, "~") {
		lastChar = query[len(query)-1:]
		query = strings.TrimRight(query, "&*~")
	}

	// Iterate over the various possible filters
	fields := re.FindAllString(query, -1)
	for _, field := range fields {
		query = strings.Replace(query, field, "", 1)

		index := strings.Index(field, ":")
		if index == -1 {
			index = strings.Index(field, "<")
		}
		if index == -1 {
			index = strings.Index(field, ">")
		}
		// Safety check
		if index == -1 {
			continue
		}

		option := strings.ToLower(field[:index])
		operation := string(field[index])
		code := field[index+1:]

		negate := false
		if strings.HasPrefix(option, "-") {
			option = strings.TrimPrefix(option, "-")
			negate = true
		}

		// Check the operation is allowed on the given option
		if !slices.Contains(FilterOperations[option], operation) {
			continue
		}

		switch option {
		// Options that modify the search engine
		case "sm":
			config.SearchMode = strings.ToLower(code)
		case "skip":
			switch strings.ToLower(code) {
			case "retail":
				config.SkipRetail = true
			case "buylist":
				config.SkipBuylist = true
			case "empty", "emptyretail", "emptybuylist":
				code = strings.ToLower(code)
				filterPost = append(filterPost, FilterPostElem{
					Name:          "empty",
					OnlyForSeller: code == "emptyretail",
					OnlyForVendor: code == "emptybuylist",
				})
			case "index", "indexretail", "indexbuylist":
				filterStores = append(filterStores, FilterStoreElem{
					Name:          "index",
					Negate:        negate,
					OnlyForSeller: code == "indexretail",
					OnlyForVendor: code == "indexbuylist",
				})
			}
		case "sort":
			code = strings.ToLower(code)
			switch code {
			case "chrono", "hybrid", "alpha", "number", "retail", "buylist":
				config.SortMode = code
			}

		// This option loads a specific set of uuids from a deck list, which is similar
		// to "unpack", but with the difference that identical ids are not skipped
		case "decklist":
			uuids := fixupContents(code)
			if len(uuids) < 1 {
				continue
			}
			// Retrieve the data to search from the first uuid
			co, _ := mtgmatcher.GetUUID(uuids[0])
			// Stash original product reference (name)
			config.PrivateData = co.Name
			// Retrieve decklist
			uuids, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
			// Assign data so that on error the entire db is returned
			config.UUIDs = uuids
			config.SearchMode = "hashing"
			// Check error
			if err != nil {
				continue
			}

		// Options that modify the card searches
		case "s", "edition", "e":
			filters = append(filters, FilterElem{
				Name:   "edition",
				Negate: negate,
				Values: fixupEditionNG(code),
			})
		case "se", "ee":
			filters = append(filters, FilterElem{
				Name:   "edition_regexp",
				Negate: negate,
				Values: []string{code},
			})
		case "cn", "number":
			opt := "number"
			if operation == ">" {
				opt = "number_greater_than"
			} else if operation == "<" {
				opt = "number_less_than"
			}

			var applyToSets []string
			var subfilters []FilterElem
			if strings.Contains(code, ":") {
				codes := strings.Split(code, ":")
				applyToSets = fixupEditionNG(codes[0])
				code = codes[1]
			}
			if strings.Contains(code, "-") {
				codes := strings.Split(code, "-")
				// Validate that the first element is a number and not a year
				// to avoid interfering with PLST and similar
				_, err := strconv.Atoi(codes[0])
				if err == nil && mtgmatcher.ExtractYear(codes[0]) == "" {
					code = codes[0]
					opt = "number_greater_than"
					subfilters = append(subfilters, FilterElem{
						Name:    opt,
						Values:  fixupNumberNG(code),
						ApplyTo: applyToSets,
					})
					// Reset options to reuse the filter addition below
					code = codes[1]
					opt = "number_less_than"
				}
			}

			filters = append(filters, FilterElem{
				Name:       opt,
				Negate:     negate,
				Values:     fixupNumberNG(code),
				Subfilters: subfilters,
				ApplyTo:    applyToSets,
			})
		case "cne":
			filters = append(filters, FilterElem{
				Name:   "number_regexp",
				Negate: negate,
				// No fixup because we need to trust input
				Values: []string{code},
			})
		case "r":
			opt := "rarity"
			if operation == ">" {
				opt = "rarity_greater_than"
			} else if operation == "<" {
				opt = "rarity_less_than"
			}
			filters = append(filters, FilterElem{
				Name:   opt,
				Negate: negate,
				Values: fixupRarityNG(code),
			})
		case "f":
			filters = append(filters, FilterElem{
				Name:   "finish",
				Negate: negate,
				Values: fixupFinishNG(code),
			})
		case "t":
			filters = append(filters, FilterElem{
				Name:   "type",
				Negate: negate,
				Values: fixupTypeNG(code),
			})
		case "is", "not":
			if option == "not" {
				negate = !negate
			}
			filters = append(filters, FilterElem{
				Name:   "is",
				Negate: negate,
				Values: strings.Split(strings.ToLower(code), ","),
			})
		case "on":
			filters = append(filters, FilterElem{
				Name:   "on",
				Negate: negate,
				Values: strings.Split(strings.ToLower(code), ","),
			})
		case "date":
			opt := "date"
			switch operation {
			case ">":
				opt = "date_greater_than"
			case "<":
				opt = "date_less_than"
			}
			filters = append(filters, FilterElem{
				Name:   opt,
				Negate: negate,
				Values: []string{fixupDateNG(code)},
			})
		case "c", "color", "ci", "identity":
			opt := "color"
			if option == "ci" || option == "color_identity" {
				opt = "color_identity"
			}
			filters = append(filters, FilterElem{
				Name:   opt,
				Negate: negate,
				Values: fixupColorNG(code),
			})
		case "id":
			filters = append(filters, FilterElem{
				Name:   "idlookup",
				Negate: negate,
				Values: fixupIDs(code),
			})
		case "unpack":
			filters = append(filters, FilterElem{
				Name:   "idlookup",
				Negate: negate,
				Values: fixupPicks(code),
			})
		case "contents":
			config.SearchMode = "mixed"
			filters = append(filters, FilterElem{
				Name:   "contents",
				Negate: negate,
				Values: fixupContents(code),
			})
		case "container":
			filters = append(filters, FilterElem{
				Name:   "idlookup",
				Negate: negate,
				Values: fixupContainer(code),
			})

		// Options that modify the searched scrapers
		case "store", "seller", "vendor":
			subCodes := strings.Split(code, ":")
			subOpt := "any"
			if len(subCodes) > 1 {
				code = subCodes[1]
				subOpt = "empty"
			}

			stores := fixupStoreCodeNG(code)

			// If this option is negated, we assume that users just want to hide a store
			// ingoring the values-if-present function
			if negate {
				filterPost = append(filterPost, FilterPostElem{
					Name:          "empty",
					OnlyForSeller: option == "seller",
					OnlyForVendor: option == "vendor",
				})
			} else {
				filterPost = append(filterPost, FilterPostElem{
					Name:          subOpt,
					Values:        stores,
					OnlyForSeller: option == "seller",
					OnlyForVendor: option == "vendor",
				})
			}
			if subOpt == "empty" || negate {
				// We want to leave the index scrapers be with this filter
				includeIndex := !negate

				filterStores = append(filterStores, FilterStoreElem{
					Name:          option,
					Negate:        negate,
					Values:        stores,
					IncludeIndex:  includeIndex,
					OnlyForSeller: option == "seller",
					OnlyForVendor: option == "vendor",
				})
			}

		case "region":
			filterStores = append(filterStores, FilterStoreElem{
				Name:   option,
				Negate: negate,
				Values: strings.Split(strings.ToLower(code), ","),
			})
			// Filter away any empty result
			filterPost = append(filterPost, FilterPostElem{
				Name: "empty",
			})
		// Pricing Options
		case "cond", "condr", "condb":
			opt := "condition"
			if operation == ">" {
				opt = "condition_greater_than"
			} else if operation == "<" {
				opt = "condition_less_than"
			}
			filterEntries = append(filterEntries, FilterEntryElem{
				Name:          opt,
				Negate:        negate,
				Values:        strings.Split(strings.ToUpper(code), ","),
				OnlyForSeller: option == "condr",
				OnlyForVendor: option == "condb",
			})
		case "price", "buy_price", "arb_price", "rev_price":
			var isSeller, isVendor bool
			var price4store func(string, string) float64
			// Each of these entries applies to either retail or buylist
			// and needs different price sources for comparisons
			switch option {
			case "price":
				isSeller = true
				price4store = price4seller
			case "buy_price":
				isVendor = true
				price4store = price4vendor
			case "arb_price":
				isSeller = true
				price4store = price4vendor
			case "rev_price":
				isVendor = true
				price4store = price4seller
			}

			filterPost = append(filterPost, FilterPostElem{
				Name:          "empty",
				OnlyForSeller: isSeller,
				OnlyForVendor: isVendor,
			})

			var optName string
			switch operation {
			case ">":
				optName = option + "_greater_than"
			case "<":
				optName = option + "_less_than"
			}
			filter := &FilterPriceElem{
				Name:          optName,
				Negate:        negate,
				OnlyForSeller: isSeller,
				OnlyForVendor: isVendor,
				Price4Store:   price4store,
			}

			// If code is a price, just keep it, otherwise parse stores later
			// (because this needs to know which card to compare against)
			price, err := strconv.ParseFloat(code, 64)
			if err == nil {
				filter.Value = price
			} else {
				filter.Stores = fixupStoreCodeNG(code)
			}
			filterPrices = append(filterPrices, filter)
		}
	}

	// Leave as much as possible intact and ignore what was parsed
	if config.SearchMode == "scryfall" {
		query = strings.Replace(rawQuery, "sm:scryfall", "", -1)
		config.FullQuery = rawQuery
		filters = nil
	}

	// Check if we can apply a finish filter through the custom syntax
	// or restore the original regexp if it's the last element
	if lastChar != "" {
		lastElementIsRegexp := len(filters) > 0 && strings.HasSuffix(filters[len(filters)-1].Name, "regexp")
		if lastElementIsRegexp && len(filters[len(filters)-1].Values) > 0 {
			filters[len(filters)-1].Values[0] += lastChar
		} else {
			var finish string
			switch lastChar {
			case "&":
				finish = "nonfoil"
			case "*":
				finish = "foil"
			case "~":
				finish = "etched"
			}
			filters = append(filters, FilterElem{
				Name:   "finish",
				Values: []string{finish},
			})
		}
	}

	// Support Scryfall bot syntax only when the search mode is not set
	if config.SearchMode == "" && strings.Contains(query, "|") {
		elements := strings.Split(query, "|")
		query = elements[0]
		extraQuery := strings.TrimSpace(elements[0])
		if len(elements) > 1 {
			extraQuery += " s:" + strings.TrimSpace(elements[1])
		}
		if len(elements) > 2 {
			extraQuery += " cn:" + strings.TrimSpace(elements[2])
		}
		if len(elements) > 3 {
			extraQuery += " f:" + strings.TrimSpace(elements[3])
		}
		if len(elements) > 4 {
			extraQuery += " cond:" + strings.TrimSpace(elements[4])
		}
		extraConfig := parseSearchOptionsNG(extraQuery, nil, nil, miscSearchOpts)
		filters = append(filters, extraConfig.CardFilters...)
	}

	// Apply any search not coming from the query itself
	for _, optName := range miscSearchOpts {
		switch optName {
		// Skip promotional entries (unless specified)
		case "hidePromos":
			var skipOption bool
			for _, filter := range filters {
				if (filter.Name == "is" && !filter.Negate) || (filter.Name == "not" && filter.Negate) {
					for _, value := range filter.Values {
						if value == "promo" {
							skipOption = true
						}
					}
				}
			}
			if !skipOption {
				filters = append(filters, FilterElem{
					Name:   "is",
					Negate: true,
					Values: []string{"promo"},
				})
			}
		case "hidePrelPack":
			var skipOption bool
			for _, filter := range filters {
				if (filter.Name == "is" && !filter.Negate) || (filter.Name == "not" && filter.Negate) {
					for _, value := range filter.Values {
						switch value {
						case "promo", "promopack", "prerelease", "playpromo":
							skipOption = true
						}
					}
				}
			}
			if !skipOption {
				filters = append(filters, FilterElem{
					Name:   "is",
					Negate: true,
					Values: []string{"prerelease"},
				})
				filters = append(filters, FilterElem{
					Name:   "is",
					Negate: true,
					Values: []string{"promopack"},
				})
				filters = append(filters, FilterElem{
					Name:   "is",
					Negate: true,
					Values: []string{"playpromo"},
				})
			}
		// Skip non-NM buylist prices
		case "hideBLconds":
			filterEntries = append(filterEntries, FilterEntryElem{
				Name:          "condition",
				Values:        []string{"NM"},
				OnlyForVendor: true,
			})
		// Skip results with no prices
		case "skipEmpty":
			filterPost = append(filterPost, FilterPostElem{
				Name: "empty",
			})
		// Skip results with suspicious prices
		case "noSussy":
			filterPrices = append(filterPrices, &FilterPriceElem{
				Name:        "invalid_direct",
				Price4Store: price4seller,
				Stores:      []string{"TCGMarket"},
				ApplyTo:     []string{"TCGDirect", "TCGDirectNet"},
			})
		case "oembed":
			// Skip any store based outside of the US
			filterStores = append(filterStores, FilterStoreElem{
				Name:   "region",
				Values: []string{"us"},
			})
			// Skip non-NM buylist prices
			filterEntries = append(filterEntries, FilterEntryElem{
				Name:          "condition",
				Values:        []string{"NM"},
				OnlyForVendor: true,
			})
		}
	}

	// By default, check if a single card name was searched and if an alternate
	// name was used, filter away any other version
	if !slices.Contains(miscSearchOpts, "allFlavorVersions") {
		altName := mtgmatcher.Normalize(query)
		allNames := mtgmatcher.AllNames("alternate", false)
		if slices.Contains(allNames, altName) {
			filters = append(filters, FilterElem{
				Name:   "altname",
				Values: []string{altName},
			})
		}
	}

	config.CleanQuery = strings.TrimSpace(query)
	config.CardFilters = filters
	config.StoreFilters = filterStores
	config.PriceFilters = filterPrices
	config.EntryFilters = filterEntries
	config.PostFilters = filterPost

	return
}

const LargestIntValue = int(^uint(0) >> 1)

func compareCollectorNumber(filters []string, co *mtgmatcher.CardObject, cmpFunc func(a, b int) bool) bool {
	if filters == nil {
		return false
	}
	var values [2]int

	for i, num := range []string{filters[0], co.Number} {
		ref, err := strconv.Atoi(num)
		if err != nil {
			ref, err = strconv.Atoi(mtgmatcher.ExtractNumericalValue(num))
			if err != nil {
				// Exclude card in case the number is all letters
				ref = LargestIntValue
			}
		}
		values[i] = ref
	}

	return cmpFunc(values[0], values[1])
}

func findInDeck(sealedUUID, opt string) []string {
	var output []string

	sealed, err := mtgmatcher.GetUUID(sealedUUID)
	if err != nil {
		return nil
	}

	set, err := mtgmatcher.GetSet(sealed.SetCode)
	if err != nil {
		return nil
	}

	for _, product := range set.SealedProduct {
		if product.UUID != sealed.UUID {
			continue
		}
		contents, found := product.Contents["deck"]
		if !found {
			continue
		}
		for _, content := range contents {
			subset, err := mtgmatcher.GetSet(content.Set)
			if err != nil {
				continue
			}

			for _, deck := range subset.Decks {
				if deck.Name != content.Name {
					continue
				}

				var board []mtgmatcher.DeckCard
				switch opt {
				case "bonus":
					board = deck.Bonus
				case "commander":
					board = deck.Commander
				case "main":
					board = deck.MainBoard
				case "sideboard":
					board = deck.SideBoard
				}

				isEtched := strings.HasSuffix(deck.Name, "etched")

				for _, card := range board {
					uuid, err := mtgmatcher.MatchId(card.UUID, card.IsFoil, isEtched)
					if err != nil {
						continue
					}
					output = append(output, uuid)
				}
			}
		}
	}

	return output
}

func compareReleaseDate(filters []string, co *mtgmatcher.CardObject, cmpFunc func(a, b time.Time) bool) bool {
	if filters == nil {
		return false
	}
	value := filters[0]

	releaseDate, err := time.Parse("2006-01-02", value)
	if err != nil {
		return true
	}

	cardDate, err := mtgmatcher.CardReleaseDate(co.UUID)
	if err != nil {
		return true
	}

	return cmpFunc(cardDate, releaseDate)
}

var isKnownPromo = map[string]string{
	"bf":        mtgmatcher.PromoTypeBoosterfun,
	"v":         mtgmatcher.PromoTypeBoosterfun,
	"rewards":   mtgmatcher.PromoTypePlayerRewards,
	"mpr":       mtgmatcher.PromoTypePlayerRewards,
	"bab":       mtgmatcher.PromoTypeBuyABox,
	"buyabox":   mtgmatcher.PromoTypeBuyABox,
	"buy-a-box": mtgmatcher.PromoTypeBuyABox,
	"arena":     mtgmatcher.PromoTypeArenaLeague,
	"judge":     mtgmatcher.PromoTypeJudgeGift,
	"confetti":  mtgmatcher.PromoTypeConfettiFoil,
	"fracture":  mtgmatcher.PromoTypeFractureFoil,
	"galaxy":    mtgmatcher.PromoTypeGalaxyFoil,
	"halo":      mtgmatcher.PromoTypeHaloFoil,
	"mana":      mtgmatcher.PromoTypeManaFoil,
	"rainbow":   mtgmatcher.PromoTypeRainbowFoil,
	"raised":    mtgmatcher.PromoTypeRaisedFoil,
	"ripple":    mtgmatcher.PromoTypeRippleFoil,
	"silver":    mtgmatcher.PromoTypeSilverFoil,
	"surge":     mtgmatcher.PromoTypeSurgeFoil,
	"wpn":       mtgmatcher.PromoTypeWPN,
	"pre":       mtgmatcher.PromoTypePrerelease,
	"pp":        mtgmatcher.PromoTypePromoPack,
	"neon":      mtgmatcher.PromoTypeNeonInk,
	"thicc":     mtgmatcher.PromoTypeThickDisplay,
	"display":   mtgmatcher.PromoTypeThickDisplay,
}

var specialTags = map[string]string{
	"Badlands":             "dual",
	"Bayou":                "dual",
	"Plateau":              "dual",
	"Savannah":             "dual",
	"Scrubland":            "dual",
	"Taiga":                "dual",
	"Tropical Island":      "dual",
	"Tundra":               "dual",
	"Underground Sea":      "dual",
	"Volcanic Island":      "dual",
	"Blackcleave Cliffs":   "fastland",
	"Blooming Marsh":       "fastland",
	"Botanical Sanctum":    "fastland",
	"Concealed Courtyard":  "fastland",
	"Copperline Gorge":     "fastland",
	"Darkslick Shores":     "fastland",
	"Inspiring Vantage":    "fastland",
	"Razorverge Thicket":   "fastland",
	"Seachrome Coast":      "fastland",
	"Spirebluff Canal":     "fastland",
	"Arid Mesa":            "fetchland",
	"Bloodstained Mire":    "fetchland",
	"Flooded Strand":       "fetchland",
	"Marsh Flats":          "fetchland",
	"Misty Rainforest":     "fetchland",
	"Polluted Delta":       "fetchland",
	"Scalding Tarn":        "fetchland",
	"Verdant Catacombs":    "fetchland",
	"Windswept Heath":      "fetchland",
	"Wooded Foothills":     "fetchland",
	"Adarkar Wastes":       "painland",
	"Battlefield Forge":    "painland",
	"Brushland":            "painland",
	"Caves of Koilos":      "painland",
	"Karplusan Forest":     "painland",
	"Llanowar Wastes":      "painland",
	"Shivan Reef":          "painland",
	"Sulfurous Springs":    "painland",
	"Underground River":    "painland",
	"Yavimaya Coast":       "painland",
	"Blood Crypt":          "shockland",
	"Breeding Pool":        "shockland",
	"Godless Shrine":       "shockland",
	"Hallowed Fountain":    "shockland",
	"Overgrown Tomb":       "shockland",
	"Sacred Foundry":       "shockland",
	"Steam Vents":          "shockland",
	"Stomping Ground":      "shockland",
	"Temple Garden":        "shockland",
	"Watery Grave":         "shockland",
	"Clifftop Retreat":     "checkland",
	"Dragonskull Summit":   "checkland",
	"Drowned Catacomb":     "checkland",
	"Glacial Fortress":     "checkland",
	"Hinterland Harbor":    "checkland",
	"Isolated Chapel":      "checkland",
	"Rootbound Crag":       "checkland",
	"Sulfur Falls":         "checkland",
	"Sunpetal Grove":       "checkland",
	"Woodland Cemetery":    "checkland",
	"Ancestral Recall":     "power9",
	"Black Lotus":          "power9",
	"Mox Emerald":          "power9",
	"Mox Jet":              "power9",
	"Mox Pearl":            "power9",
	"Mox Ruby":             "power9",
	"Mox Sapphire":         "power9",
	"Timetwister":          "power9",
	"Time Walk":            "power9",
	"Commercial District":  "surveilland",
	"Elegant Parlor":       "surveilland",
	"Hedge Maze":           "surveilland",
	"Lush Portico":         "surveilland",
	"Meticulous Archive":   "surveilland",
	"Raucous Theater":      "surveilland",
	"Shadowy Backstreet":   "surveilland",
	"Thundering Falls":     "surveilland",
	"Undercity Sewers":     "surveilland",
	"Underground Mortuary": "surveilland",
	"Cascading Cataracts":  "filterland",
	"Crystal Quarry":       "filterland",
	"Cascade Bluffs":       "filterland",
	"Fetid Heath":          "filterland",
	"Fire-Lit Thicket":     "filterland",
	"Flooded Grove":        "filterland",
	"Graven Cairns":        "filterland",
	"Mystic Gate":          "filterland",
	"Rugged Prairie":       "filterland",
	"Sunken Ruins":         "filterland",
	"Twilight Mire":        "filterland",
	"Wooded Bastion":       "filterland",
	"Darkwater Catacombs":  "filterland",
	"Desolate Mire":        "filterland",
	"Ferrous Lake":         "filterland",
	"Mossfire Valley":      "filterland",
	"Overflowing Basin":    "filterland",
	"Shadowblood Ridge":    "filterland",
	"Skycloud Expanse":     "filterland",
	"Sungrass Prairie":     "filterland",
	"Sunscorched Divide":   "filterland",
	"Viridescent Bog":      "filterland",
}

var specialEditionTags = map[string]string{
	"LEA": "abu4h",
	"LEB": "abu4h",
	"2ED": "abu4h",
	"ARN": "abu4h",
	"ATQ": "abu4h",
	"LEG": "abu4h",
	"DRK": "abu4h",
}

var rarityMap = map[string]int{
	"common":   0,
	"uncommon": 1,
	"rare":     2,
	"mythic":   3,
	"special":  4,
}

var FilterCardFuncs = map[string]func(filters []string, co *mtgmatcher.CardObject) bool{
	"edition": func(filters []string, co *mtgmatcher.CardObject) bool {
		return !slices.Contains(filters, co.SetCode)
	},
	"edition_regexp": func(filters []string, co *mtgmatcher.CardObject) bool {
		matched, _ := regexp.MatchString(filters[0], co.Edition)
		return !matched
	},
	"rarity": func(filters []string, co *mtgmatcher.CardObject) bool {
		return !slices.Contains(filters, co.Rarity)
	},
	"rarity_greater_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		rarityIndex, found := rarityMap[filters[0]]
		if !found {
			return true
		}
		return rarityIndex >= rarityMap[co.Rarity]
	},
	"rarity_less_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		rarityIndex, found := rarityMap[filters[0]]
		if !found {
			return true
		}
		return rarityIndex <= rarityMap[co.Rarity]
	},
	"type": func(filters []string, co *mtgmatcher.CardObject) bool {
		if co.Sealed {
			for _, value := range filters {
				value = strings.ToLower(strings.Replace(value, " ", "_", -1))
				if strings.Contains(strings.ToLower(co.Layout), value) ||
					strings.Contains(strings.ToLower(co.Side), value) ||
					strings.Contains(strings.ToLower(co.Name), value) {
					return false
				}
			}
		} else {
			for _, value := range filters {
				if slices.Contains(co.Subtypes, value) ||
					slices.Contains(co.Types, value) ||
					slices.Contains(co.Supertypes, value) {
					return false
				}
			}
		}
		return true
	},
	"color": func(filters []string, co *mtgmatcher.CardObject) bool {
		if len(filters) == 0 {
			return len(co.Colors) != 0
		}
		if len(filters) == 5 {
			return len(co.Colors) <= 1
		}
		for _, value := range filters {
			if !slices.Contains(co.Colors, strings.ToUpper(value)) && !slices.Contains(co.Colors, strings.ToLower(value)) {
				return true
			}
		}
		return false
	},
	"color_identity": func(filters []string, co *mtgmatcher.CardObject) bool {
		if len(filters) == 0 {
			return len(co.ColorIdentity) != 0
		}
		if len(filters) == 5 {
			return len(co.ColorIdentity) <= 1
		}
		for _, value := range co.ColorIdentity {
			if !slices.Contains(filters, value) {
				return true
			}
		}
		return false
	},
	"idlookup": func(filters []string, co *mtgmatcher.CardObject) bool {
		return !slices.Contains(filters, co.UUID)
	},
	"contents": func(filters []string, co *mtgmatcher.CardObject) bool {
		values := cardobject2sources(co)
		for _, filter := range filters {
			if !slices.Contains(values, filter) {
				return true
			}
		}
		return false
	},
	"number": func(filters []string, co *mtgmatcher.CardObject) bool {
		return !slices.Contains(filters, strings.ToLower(co.Number))
	},
	"number_regexp": func(filters []string, co *mtgmatcher.CardObject) bool {
		matched, _ := regexp.MatchString(filters[0], co.Number)
		return !matched
	},
	"number_greater_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		return compareCollectorNumber(filters, co, func(a, b int) bool {
			return a > b
		})
	},
	"number_less_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		return compareCollectorNumber(filters, co, func(a, b int) bool {
			return a < b
		})
	},
	"finish": func(filters []string, co *mtgmatcher.CardObject) bool {
		for _, value := range filters {
			switch value {
			case "etched", "e":
				if co.Etched {
					return false
				}
			case "foil", "f":
				if co.Foil {
					return false
				}
			case "nonfoil", "nf", "r":
				if !co.Foil && !co.Etched {
					return false
				}
			}
		}
		return true
	},
	"date": func(filters []string, co *mtgmatcher.CardObject) bool {
		return compareReleaseDate(filters, co, func(a, b time.Time) bool {
			return !a.Equal(b)
		})
	},
	"date_greater_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		return compareReleaseDate(filters, co, func(a, b time.Time) bool {
			return a.Before(b)
		})
	},
	"date_less_than": func(filters []string, co *mtgmatcher.CardObject) bool {
		return compareReleaseDate(filters, co, func(a, b time.Time) bool {
			return a.After(b)
		})
	},
	"altname": func(filters []string, co *mtgmatcher.CardObject) bool {
		return (co.FlavorName != "" && mtgmatcher.Normalize(co.FlavorName) != filters[0]) ||
			(co.FaceFlavorName != "" && mtgmatcher.Normalize(co.FaceFlavorName) != filters[0])
	},
	"on": func(filters []string, co *mtgmatcher.CardObject) bool {
		for _, value := range filters {
			switch value {
			case "mtgstocks":
				inv, _ := findSellerInventory("STKS")
				_, found := inv[co.UUID]
				if found {
					return false
				}
			case "tcgsyp", "syp":
				bl, _ := findVendorBuylist("SYP")
				_, found := bl[co.UUID]
				if found {
					return false
				}
			}
		}
		return true
	},
	"is": func(filters []string, co *mtgmatcher.CardObject) bool {
		for _, value := range filters {
			switch value {
			case "foil":
				if co.Foil || co.Etched {
					return false
				}
			case "nonfoil":
				if !co.Foil && !co.Etched {
					return false
				}
			case "reserved":
				if co.IsReserved {
					return false
				}
			case "token":
				if co.Layout == "token" {
					return false
				}
			case "oversize", "oversized":
				if co.IsOversized {
					return false
				}
			case "funny":
				if co.IsFunny {
					return false
				}
			case "wcd", "gold":
				if co.BorderColor == "gold" {
					return false
				}
			case "fullart", "fa":
				if co.IsFullArt {
					return false
				}
			case "promo":
				if co.IsPromo {
					return false
				}
			case "gamechanger", "gc":
				if co.IsGameChanger {
					return false
				}
			case "extendedart", "ea":
				if co.HasFrameEffect(mtgmatcher.FrameEffectExtendedArt) {
					return false
				}
			case "showcase", "sc", "sh":
				if co.HasFrameEffect(mtgmatcher.FrameEffectShowcase) {
					return false
				}
			case "borderless", "bd", "bl":
				if co.BorderColor == mtgmatcher.BorderColorBorderless {
					return false
				}
			case "future":
				if co.FrameVersion == "future" {
					return false
				}
			case "retro", "old":
				if co.FrameVersion == "1993" || co.FrameVersion == "1997" {
					return false
				}
			case "reskin":
				if co.FlavorName != "" {
					return false
				}
			case "japanese", "jpn", "jp", "ja":
				if co.Language == mtgmatcher.LanguageJapanese {
					return false
				}
			case "phyrexian", "ph":
				if co.Language == mtgmatcher.LanguagePhyrexian {
					return false
				}
			case "commander":
				values := cardobject2sources(co)
				for _, sealedUUID := range values {
					res := findInDeck(sealedUUID, "commander")
					if slices.Contains(res, co.UUID) {
						return false
					}
				}
			case "productless":
				if cardobject2sources(co) == nil {
					return false
				}
			case "ampersand":
				if co.SetCode != "PAFR" {
					continue
				}
				if co.HasPromoType(mtgmatcher.PromoTypeEmbossed) {
					return false
				}
			case "p9":
				customTag, found := specialTags[co.Name]
				if found && customTag == "power9" {
					return false
				}
			default:
				// Adjust input for these known cases
				newValue, found := isKnownPromo[value]
				if found {
					value = newValue
				}

				// Fall back to any promo type currently supported
				if slices.Contains(mtgmatcher.AllPromoTypes(), value) {
					if co.HasPromoType(value) {
						return false
					}
				}

				// Finally check any leftover tags
				customTag, found := specialTags[co.Name]
				if found && customTag == value {
					return false
				}

				// same for set code tags
				customTag, found = specialEditionTags[co.SetCode]
				if found && customTag == value {
					return false
				}
			}
		}
		return true
	},
}

func shouldSkipCardNG(cardId string, filters []FilterElem) bool {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return true
	}

	for i := range filters {
		skip := shouldSkipCardNG(cardId, filters[i].Subfilters)
		if skip {
			return true
		}

		// Filter out any SetCode that wasn't selected
		if filters[i].ApplyTo != nil && !slices.Contains(filters[i].ApplyTo, co.SetCode) {
			continue
		}

		f, found := FilterCardFuncs[filters[i].Name]
		if !found {
			panic(filters[i].Name + " option not found")
		}
		res := f(filters[i].Values, co)
		if filters[i].Negate {
			res = !res
		}
		if res {
			return true
		}
	}

	return false
}

// Check whether the scraper is in the filtered region
// Index scrapers are always global
func localizeScraper(filters []string, scraper mtgban.Scraper) bool {
	for _, value := range filters {
		switch value {
		case "us":
			if scraper.Info().CountryFlag == "" {
				return false
			}
		case "eu":
			if scraper.Info().CountryFlag == "EU" {
				return false
			}
		case "jp":
			if scraper.Info().CountryFlag == "JP" {
				return false
			}
		}
	}
	return true
}

// Note that generic store functions should always return the index scrapers
// Those can be filtered out with the explicit index option
var FilterStoreFuncs = map[string]func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool{
	"index": func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
		return scraper.Info().MetadataOnly
	},
	"store": func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
		if includeIndex && scraper.Info().MetadataOnly {
			return false
		}
		return !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
	},
	"seller": func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
		if includeIndex && scraper.Info().MetadataOnly {
			return false
		}
		_, ok := scraper.(mtgban.Seller)
		return ok && !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
	},
	"vendor": func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
		if includeIndex && scraper.Info().MetadataOnly {
			return false
		}
		_, ok := scraper.(mtgban.Vendor)
		return ok && !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
	},
	"region": func(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
		if includeIndex && scraper.Info().MetadataOnly {
			return false
		}
		return localizeScraper(filters, scraper)
	},
}

func shouldSkipStoreNG(scraper mtgban.Scraper, filters []FilterStoreElem) bool {
	if scraper == nil {
		return true
	}

	_, isSeller := scraper.(mtgban.Seller)
	_, isVendor := scraper.(mtgban.Vendor)

	for i := range filters {
		// Do not call functions that do not apply to certain elements,
		// or the negate step might thwart results
		if filters[i].OnlyForSeller && !isSeller {
			continue
		} else if filters[i].OnlyForVendor && !isVendor {
			continue
		}

		f, found := FilterStoreFuncs[filters[i].Name]
		if !found {
			panic(filters[i].Name + " option not found")
		}
		res := f(filters[i].Values, scraper, filters[i].IncludeIndex)
		if filters[i].Negate {
			res = !res
		}
		if res {
			return true
		}
	}

	return false
}

// These functions include the referenced Price so that users can visualize it
func priceGreaterThan(filters []float64, refPrice float64) bool {
	for i := range filters {
		if filters[i] <= refPrice {
			return false
		}
	}
	return true
}

func priceLessThan(filters []float64, refPrice float64) bool {
	for i := range filters {
		if filters[i] >= refPrice {
			return false
		}
	}
	return true
}

var FilterPriceFuncs = map[string]func(filters []float64, refPrice float64) bool{
	"price_greater_than":     priceGreaterThan,
	"price_less_than":        priceLessThan,
	"buy_price_greater_than": priceGreaterThan,
	"buy_price_less_than":    priceLessThan,
	"arb_price_greater_than": priceGreaterThan,
	"arb_price_less_than":    priceLessThan,
	"rev_price_greater_than": priceGreaterThan,
	"rev_price_less_than":    priceLessThan,

	// Special function that doubles the check price, filtering out
	// anything that is twice as much the market price
	"invalid_direct": func(filters []float64, refPrice float64) bool {
		return priceLessThan(filters, refPrice/2)
	},
}

func shouldSkipPriceNG(cardId string, entry mtgban.GenericEntry, filters []*FilterPriceElem, shorthand string) bool {
	if entry.Pricing() == 0 {
		return true
	}

	_, isSeller := entry.(mtgban.InventoryEntry)
	_, isVendor := entry.(mtgban.BuylistEntry)

	for i := range filters {
		// Do not call functions that do not apply to certain elements
		if filters[i].OnlyForSeller && !isSeller {
			continue
		} else if filters[i].OnlyForVendor && !isVendor {
			continue
		}

		// Filter out any store that wasn't selected
		if filters[i].ApplyTo != nil && !slices.Contains(filters[i].ApplyTo, shorthand) {
			continue
		}

		// Check if we already have prices for this card
		filters[i].Mutex.RLock()
		prices, found := filters[i].PriceCache[cardId]
		filters[i].Mutex.RUnlock()
		if !found {
			// If there is no set value, then look it up with the price4store function
			if filters[i].Value == 0 {
				for j := range filters[i].Stores {
					price := filters[i].Price4Store(cardId, filters[i].Stores[j])
					// In case a store lacks a price
					if price == 0 {
						continue
					}
					prices = append(prices, price)
				}
			} else {
				// Else fill in the cache with the passed in
				prices = []float64{filters[i].Value}
			}

			// Update cache
			go func() {
				filters[i].Mutex.Lock()
				if filters[i].PriceCache == nil {
					filters[i].PriceCache = map[string][]float64{}
				}
				filters[i].PriceCache[cardId] = prices
				filters[i].Mutex.Unlock()
			}()
		}

		f, found := FilterPriceFuncs[filters[i].Name]
		if !found {
			panic(filters[i].Name + " option not found")
		}
		res := f(prices, entry.Pricing())
		if filters[i].Negate {
			res = !res
		}
		if res {
			return true
		}
	}

	return false
}

var conditionMap = map[string]int{
	"NM": 4,
	"SP": 3,
	"MP": 2,
	"HP": 1,
	"PO": 0,
}

var FilterEntryFuncs = map[string]func(filters []string, entry mtgban.GenericEntry) bool{
	"condition": func(filters []string, entry mtgban.GenericEntry) bool {
		return !slices.Contains(filters, entry.Condition())
	},
	"condition_greater_than": func(filters []string, entry mtgban.GenericEntry) bool {
		condIndex, found := conditionMap[filters[0]]
		if !found {
			return true
		}
		return condIndex >= conditionMap[entry.Condition()]
	},
	"condition_less_than": func(filters []string, entry mtgban.GenericEntry) bool {
		condIndex, found := conditionMap[filters[0]]
		if !found {
			return true
		}
		return condIndex <= conditionMap[entry.Condition()]
	},
}

func shouldSkipEntryNG(entry mtgban.GenericEntry, filters []FilterEntryElem) bool {
	_, isSeller := entry.(mtgban.InventoryEntry)
	_, isVendor := entry.(mtgban.BuylistEntry)

	for i := range filters {
		if filters[i].OnlyForSeller && !isSeller {
			continue
		} else if filters[i].OnlyForVendor && !isVendor {
			continue
		}

		f, found := FilterEntryFuncs[filters[i].Name]
		if !found {
			panic(filters[i].Name + " option not found")
		}
		res := f(filters[i].Values, entry)
		if filters[i].Negate {
			res = !res
		}
		if res {
			return true
		}
	}

	return false
}

var FilterPostFuncs = map[string]func(filters []string, cardId string, foundScraper map[string]map[string][]SearchEntry) bool{
	"empty": func(filters []string, cardId string, foundScraper map[string]map[string][]SearchEntry) bool {
		return len(foundScraper[cardId]) == 0 ||
			(len(foundScraper[cardId]) == 1 && len(foundScraper[cardId]["INDEX"]) != 0)
	},
	"any": func(filters []string, cardId string, foundScraper map[string]map[string][]SearchEntry) bool {
		for _, cond := range AllConditions {
			for _, entry := range foundScraper[cardId][cond] {
				for _, shorthand := range filters {
					if strings.ToLower(entry.Shorthand) == shorthand {
						return false
					}
				}
			}
		}
		return true
	},
}

func shouldSkipPostNG(cardId string, foundSellers, foundVendors map[string]map[string][]SearchEntry, filters []FilterPostElem) bool {
	for i := range filters {
		f, found := FilterPostFuncs[filters[i].Name]
		if !found {
			panic(filters[i].Name + " option not found")
		}

		var foundScrapers map[string]map[string][]SearchEntry
		if filters[i].OnlyForSeller {
			foundScrapers = foundSellers
		} else if filters[i].OnlyForVendor {
			foundScrapers = foundVendors
		} else {
			resS := f(filters[i].Values, cardId, foundSellers)
			resV := f(filters[i].Values, cardId, foundVendors)
			res := resS && resV
			if res {
				return true
			}
			continue
		}

		res := f(filters[i].Values, cardId, foundScrapers)
		if res {
			return true
		}
	}

	return false
}

func PostSearchFilter(config SearchConfig, allKeys []string, foundSellers, foundVendors map[string]map[string][]SearchEntry) []string {
	if len(config.PostFilters) == 0 {
		return allKeys
	}

	var keepIds []string

	for _, cardId := range allKeys {
		if shouldSkipPostNG(cardId, foundSellers, foundVendors, config.PostFilters) {
			continue
		}
		keepIds = append(keepIds, cardId)
	}

	return keepIds
}
