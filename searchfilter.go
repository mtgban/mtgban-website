package main

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/magic"
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

	// Raw filter tokens found in the query (eg "s:lea", "f:foil"),
	// used to suggest broader searches when nothing is found
	AppliedFilters []string

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

	// Regexp is Values[0] compiled, for the filters that carry a pattern.
	// The filter is built once and then run against every candidate, so
	// compiling here rather than at the comparison is the difference
	// between one compile and one per card.
	Regexp *regexp.Regexp
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

	// Cache of cardId:prices used in the filter. The retail and buylist
	// searches run concurrently and can share one filter (e.g. noSussy spans
	// TCGDirect retail and TCGDirectNet buylist), so cached slices are read
	// from multiple goroutines: never mutate one after it is stored — build a
	// new slice instead.
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
		field = strings.Trim(field, "\"")

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
		filters[i] = strings.Trim(filters[i], "\"")

		// Validate the input against the registered scrapers
		for _, seller := range GetSellers() {
			if filters[i] != strings.ToLower(scraperName(seller.Info().Shorthand)) &&
				filters[i] != strings.ToLower(seller.Info().Shorthand) {
				continue
			}
			filters[i] = strings.ToLower(seller.Info().Shorthand)
			break
		}
		for _, vendor := range GetVendors() {
			if filters[i] != strings.ToLower(scraperName(vendor.Info().Shorthand)) &&
				filters[i] != strings.ToLower(vendor.Info().Shorthand) {
				continue
			}
			filters[i] = strings.ToLower(vendor.Info().Shorthand)
			break
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

func fixupNumberNG(code string, strict bool) []string {
	code = strings.ToLower(code)
	filters := strings.Split(code, ",")
	for i := range filters {
		filters[i] = strings.TrimLeft(filters[i], "0")
		if !strict {
			filters[i] = strings.TrimRight(filters[i], magic.SuffixSpecial+magic.SuffixVariant+magic.SuffixPhi+"*")
		}
	}
	return filters
}

// fixupPatternNG takes the quotes off a pattern query. Nothing else comes
// off: every other character could be part of the pattern.
func fixupPatternNG(code string) string {
	return strings.Trim(code, "\"")
}

func fixupFinishNG(code string) []string {
	filters := strings.Split(strings.ToLower(code), ",")
	for i := range filters {
		// Spell the query the way a finish is stored: one lowercase word, no
		// separators. That is what makes "Rainbow Foil", "rainbow-foil" and
		// "rainbowfoil" one query, and it leaves the shared names alone -
		// foil, etched, nonfoil and the short forms are already one word.
		filters[i] = mtgmatcher.NormalizeFinish(filters[i])
	}
	return filters
}

func fixupTypeNG(code string) []string {
	filters := strings.Split(code, ",")
	for i := range filters {
		filters[i] = strings.Trim(filters[i], "\"")
		filters[i] = mtgmatcher.Title(filters[i])
	}
	return filters
}

func fixupDateNG(code string) string {
	if code == "now" || code == "today" {
		return time.Now().Format("2006-01-02")
	}
	set, err := mtgmatcher.GetSet(strings.ToUpper(code))
	if err == nil {
		return set.ReleaseDate
	}
	_, err = parseDate(code)
	if err != nil {
		return ""
	}
	return code
}

func parseDate(code string) (time.Time, error) {
	date, err := time.Parse("2006-01-02", code)
	if err != nil {
		date, err = time.Parse("2006-01", code)
		if err != nil {
			return time.Parse("2006", code)
		}
	}
	return date, nil
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
	"quandrix":    {"G", "U"},
	"silverquill": {"W", "B"},
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
		_, err := mtgmatcher.GetUUID(field)
		if err == nil {
			continue
		}
		// XXX: id funcs report the first finish available
		uuid := externalUUID(field)
		if uuid != "" {
			fields[i] = uuid
			continue
		}
	}
	return fields
}

func sealedname2uuid(name string) string {
	name = strings.TrimSpace(strings.Trim(name, "\""))
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

func price4seller(cardID, shorthand string) float64 {
	inv, err := findSellerInventory(shorthand)
	if err != nil {
		return 0
	}
	entries, found := inv[cardID]
	if !found {
		return 0
	}
	return entries[0].Price
}

func price4vendor(cardID, shorthand string) float64 {
	bl, err := findVendorBuylist(shorthand)
	if err != nil {
		return 0
	}
	entries, found := bl[cardID]
	if !found {
		return 0
	}
	return entries[0].BuyPrice
}

var re *regexp.Regexp

var FilterOperations = map[string][]string{
	"format":    []string{":"},
	"legal":     []string{":"},
	"sm":        []string{":"},
	"skip":      []string{":"},
	"sort":      []string{":"},
	"edition":   []string{":"},
	"set":       []string{":"},
	"e":         []string{":"},
	"s":         []string{":"},
	"se":        []string{":"},
	"ee":        []string{":"},
	"number":    []string{":", ">", "<"},
	"cn":        []string{":", ">", "<"},
	"cns":       []string{":"},
	"cne":       []string{":"},
	"date":      []string{":", ">", "<"},
	"year":      []string{":", ">", "<"},
	"name":      []string{":"},
	"namee":     []string{":"},
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
	"ratio":     []string{">", "<"},
	"store":     []string{":"},
	"seller":    []string{":"},
	"vendor":    []string{":"},
	"region":    []string{":"},
	"quantity":  []string{">", "<"},
	"qty":       []string{">", "<"},
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

	regexpOptions = fmt.Sprintf(`-?(%s|%s)[:<>](("([^"]+)"|\S+))+`, strings.Join(opts, "|"), strings.ToUpper(strings.Join(opts, "|")))

	re = regexp.MustCompile(regexpOptions)
}

// fixupFormatNG normalizes a comma-separated list of format names to the
// lowercase keys used in a card's legalities map, mapping a couple of aliases.
func fixupFormatNG(code string) []string {
	var out []string
	for _, format := range strings.Split(strings.ToLower(code), ",") {
		format = strings.TrimSpace(format)
		switch format {
		case "":
			continue
		case "edh":
			format = "commander"
		case "pdh":
			format = "paupercommander"
		}
		out = append(out, format)
	}
	return out
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
	switch query[len(query)-1] {
	case '&', '*', '~', '`':
		lastChar = query[len(query)-1:]
		query = strings.TrimRight(query, "&*~`")
	}

	// Iterate over the various possible filters
	fields := re.FindAllString(query, -1)
	config.AppliedFilters = fields
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
			// Scryfall is a Magic service, and what it returns is keyed by
			// Scryfall ids that only a Magic datastore resolves, so anywhere
			// else the mode spends a paginated network round trip to map
			// every hit to nothing. Drop it and let the game's own default
			// take the query, the way an unrecognised mode is already
			// dropped by the search itself.
			if config.SearchMode == "scryfall" && Config.Game != DefaultGame {
				config.SearchMode = ""
			}
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
		case "name":
			filters = append(filters, FilterElem{
				Name:   "name",
				Negate: negate,
				// No fixup because names will be normalized
				Values: []string{code},
			})
		case "namee":
			pattern := fixupPatternNG(code)
			re, _ := regexp.Compile(pattern)
			filters = append(filters, FilterElem{
				Name:   "name_regexp",
				Negate: negate,
				Values: []string{pattern},
				Regexp: re,
			})
		case "s", "set", "edition", "e":
			filters = append(filters, FilterElem{
				Name:   "edition",
				Negate: negate,
				Values: fixupEditionNG(code),
			})
		case "se", "ee":
			pattern := fixupPatternNG(code)
			re, _ := regexp.Compile(pattern)
			filters = append(filters, FilterElem{
				Name:   "edition_regexp",
				Negate: negate,
				Values: []string{pattern},
				Regexp: re,
			})
		case "cn", "cns", "number":
			opt := "number"
			if option == "cns" {
				opt = "number_strict"
			}
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
				// Treat as a range only when both ends are plain numbers in
				// ascending order, so that dashed collector numbers (PLST's
				// "SET-123" or year-prefixed promos like "2002-1") keep
				// matching literally
				first, errFirst := strconv.Atoi(codes[0])
				second, errSecond := strconv.Atoi(codes[1])
				if errFirst == nil && errSecond == nil && first < second {
					code = codes[0]
					opt = "number_greater_than"
					subfilters = append(subfilters, FilterElem{
						Name:    opt,
						Values:  fixupNumberNG(code, false),
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
				Values:     fixupNumberNG(code, option == "cns"),
				Subfilters: subfilters,
				ApplyTo:    applyToSets,
			})
		case "cne":
			pattern := fixupPatternNG(code)
			re, _ := regexp.Compile(pattern)
			filters = append(filters, FilterElem{
				Name:   "number_regexp",
				Negate: negate,
				Values: []string{pattern},
				Regexp: re,
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
		case "format", "legal":
			filters = append(filters, FilterElem{
				Name:   "format",
				Negate: negate,
				Values: fixupFormatNG(code),
			})
		case "date", "year":
			opt := "date"
			switch operation {
			case ">":
				opt = "date_greater_than"
			case "<":
				opt = "date_less_than"
			}
			if option == "year" {
				// Only use the first chunk of the ISO date if only year is requested
				code = strings.Split(code, "-")[0]

				// If a single year is selected, then we enable a range
				if opt == "date" {
					filters = append(filters, FilterElem{
						Name:   "date_greater_than",
						Negate: negate,
						Values: []string{fixupDateNG(code + "-01-01")},
					})
					opt = "date_less_than"
				}
				// If > then fixupDateNG will start from 01-01 which is fine, but
				// if < then we need to include as much time as possible
				if opt == "date_less_than" {
					code += "-12-31"
				}
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
		case "quantity", "qty":
			var optName string
			if operation == ">" {
				optName = "qty_greater_than"
			} else if operation == "<" {
				optName = "qty_less_than"
			}
			filterEntries = append(filterEntries, FilterEntryElem{
				Name:   optName,
				Negate: negate,
				Values: []string{code},
			})

			// Remove any empty entry if no results
			filterPost = append(filterPost, FilterPostElem{
				Name: "empty",
			})

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
		case "ratio":
			opt := "ratio_greater_than"
			if operation == "<" {
				opt = "ratio_less_than"
			}
			filterEntries = append(filterEntries, FilterEntryElem{
				Name:          opt,
				Negate:        negate,
				Values:        strings.Split(strings.ToUpper(code), ","),
				OnlyForVendor: true,
			})

			// Remove any empty entry if no results
			filterPost = append(filterPost, FilterPostElem{
				Name:          "empty",
				OnlyForVendor: true,
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
			case "`":
				finish = "foil"

				filters = append(filters, FilterElem{
					Name:   "is",
					Values: []string{"altfoil"},
				})
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

	// Rewrite bare "<set code> <number>" queries, eg "neo 234" or
	// "plst c16-177", to the equivalent s:CODE cn:NUMBER filters.
	// ExtractNumberAny doubles as validator and normalizer: it strips
	// leading # and zeroes, keeps dashed and starred numbers whole, and
	// rejects ordinals, months, and set-code-shaped tokens.
	// The shorthand is meaningful only for singles: sealed products have
	// no collector numbers, and the sealed handler assigns its SearchMode
	// after this parse, so such queries cannot be told apart here
	if config.SearchMode == "" {
		tokens := strings.Fields(query)
		if len(tokens) == 2 {
			number := mtgmatcher.ExtractNumberAny(tokens[1])
			if number != "" {
				set, err := mtgmatcher.GetSet(tokens[0])
				if err == nil {
					extraConfig := parseSearchOptionsNG("s:"+set.Code+" cn:"+number, nil, nil, nil)
					filters = append(filters, extraConfig.CardFilters...)
					query = ""
				}
			}
		}
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

	// A game other than Magic searches by substring unless the query said
	// otherwise. Its card names carry a subtitle - "Mickey Mouse - Brave
	// Little Tailor", "Monkey D. Luffy" - so the exact match the default mode
	// tries almost never lands on what someone typed, and the prefix widening
	// behind it only helps a query that started at the front of the name.
	// Magic names are searched whole, so it keeps the exact-then-prefix path.
	//
	// Last, so the modes parsed out of the query above win, and so the checks
	// above that read an unset mode - the Scryfall "|" syntax, the bare
	// "<set> <number>" shorthand - still see the state they were written for.
	if config.SearchMode == "" && Config.Game != DefaultGame {
		config.SearchMode = "any"
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

// minPromoFallbackLen is the shortest query allowed to match a promo type by
// substring. Two characters sit inside most of the list, so below this only an
// exact token counts.
const minPromoFallbackLen = 3

// squeezePromo reduces a promo type or a query to the form they can be
// compared in. A type is a token that lost its spaces so it could be typed
// into a search ("cosmicfoil"), so the query gives up the same characters and
// "cosmic foil" reaches it.
func squeezePromo(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '_', '\'':
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// promoTypeMatches names the promo types a bare query could have meant. An
// exact token stands alone - asking for "metal" is not asking for every type
// with "metal" inside it - and failing that every type carrying the query as a
// substring comes back, which is how "foil" reaches all sixteen of them.
func promoTypeMatches(query string) []string {
	needle := squeezePromo(query)
	if needle == "" {
		return nil
	}

	all := mtgmatcher.AllPromoTypes()
	for _, promoType := range all {
		if squeezePromo(promoType) == needle {
			return []string{promoType}
		}
	}
	if len(needle) < minPromoFallbackLen {
		return nil
	}

	var out []string
	for _, promoType := range all {
		if strings.Contains(squeezePromo(promoType), needle) {
			out = append(out, promoType)
		}
	}
	return out
}

// setCodeMatches names the sets a bare query could have meant, for the fallback
// a search with no results takes. An exact code or an exact name stands alone;
// failing that every set whose name carries the query as a substring comes
// back, so "shadows" reaches both Shadows over Innistrad and its remaster.
func setCodeMatches(query string) []string {
	needle := squeezePromo(query)
	if len(needle) < minPromoFallbackLen {
		return nil
	}

	codes := mtgmatcher.GetAllSets()
	var contains []string
	for _, code := range codes {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		if squeezePromo(code) == needle || squeezePromo(set.Name) == needle {
			return []string{code}
		}
		if strings.Contains(squeezePromo(set.Name), needle) {
			contains = append(contains, code)
		}
	}
	return contains
}

func compareCollectorNumber(filters []string, co *mtgmatcher.CardObject, cmpFunc func(a, b int) bool) bool {
	if filters == nil {
		return false
	}
	var values [2]int

	for i, num := range []string{filters[0], co.OriginalNumber} {
		ref, err := strconv.Atoi(num)
		if err != nil {
			ref, err = strconv.Atoi(mtgmatcher.ExtractNumberValue(num))
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
				case "commander":
					board = deck.Commander
				case "main":
					board = deck.MainBoard
				case "display_commander":
					board = deck.DisplayCommander
				case "schemes":
					board = deck.Schemes
				case "planes":
					board = deck.Planes
				case "sideboard":
					board = deck.SideBoard
				case "tokens":
					board = deck.Tokens
				}

				isEtched := strings.HasSuffix(deck.Name, "etched")

				for _, card := range board {
					uuid, err := mtgmatcher.MatchID(card.UUID, card.IsFoil, isEtched)
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

	releaseDate, err := parseDate(value)
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
	// The one expansion that is not a Magic promo type. Extended art is a
	// frame effect on a Magic card and a promo type on the games that print
	// it as a treatment, so the case in cardFilterIs answers the first
	// reading and this lets the short form reach the second: without it "ea"
	// arrives at the promo types as itself, which no game names anything.
	"ea":        magic.FrameEffectExtendedArt,
	"bf":        magic.PromoTypeBoosterfun,
	"v":         magic.PromoTypeBoosterfun,
	"rewards":   magic.PromoTypePlayerRewards,
	"mpr":       magic.PromoTypePlayerRewards,
	"bab":       magic.PromoTypeBuyABox,
	"buyabox":   magic.PromoTypeBuyABox,
	"buy-a-box": magic.PromoTypeBuyABox,
	"arena":     magic.PromoTypeArenaLeague,
	"judge":     magic.PromoTypeJudgeGift,
	"confetti":  magic.PromoTypeConfettiFoil,
	"fracture":  magic.PromoTypeFractureFoil,
	"galaxy":    magic.PromoTypeGalaxyFoil,
	"halo":      magic.PromoTypeHaloFoil,
	"mana":      magic.PromoTypeManaFoil,
	"rainbow":   magic.PromoTypeRainbowFoil,
	"raised":    magic.PromoTypeRaisedFoil,
	"ripple":    magic.PromoTypeRippleFoil,
	"silver":    magic.PromoTypeSilverFoil,
	"surge":     magic.PromoTypeSurgeFoil,
	"wpn":       magic.PromoTypeWPN,
	"pre":       magic.PromoTypePrerelease,
	"pp":        magic.PromoTypePromoPack,
	"neon":      magic.PromoTypeNeonInk,
	"thicc":     magic.PromoTypeThickDisplay,
	"display":   magic.PromoTypeThickDisplay,
}

var altFoilTags = []string{
	"chocobotrackfoil",
	"confettifoil",
	"cosmicfoil",
	"dazzlefoil",
	"doubleexposure",
	"doublerainbow",
	"dragonscalefoil",
	"embossed",
	"facetfoil",
	"firstplacefoil",
	"fracturefoil",
	"galaxyfoil",
	"gilded",
	"halofoil",
	"headliner",
	"invisibleink",
	"manafoil",
	"neonink",
	"oilslick",
	"rainbowfoil",
	"raisedfoil",
	"ripplefoil",
	"silverfoil",
	"silverscroll",
	"singularityfoil",
	"stepandcompleat",
	"surgefoil",
	"textured",
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
	"Floodfarm Verge":      "vergeland",
	"Gloomlake Verge":      "vergeland",
	"Blazemire Verge":      "vergeland",
	"Thornspire Verge":     "vergeland",
	"Hushwood Verge":       "vergeland",
	"Sunbillow Verge":      "vergeland",
	"Willowrush Verge":     "vergeland",
	"Bleachbone Verge":     "vergeland",
	"Riverpyre Verge":      "vergeland",
	"Wastewood Verge":      "vergeland",

	"Indatha Triome":           "triome",
	"Ketria Triome":            "triome",
	"Raugrin Triome":           "triome",
	"Savai Triome":             "triome",
	"Zagoth Triome":            "triome",
	"Jetmir's Garden":          "triome",
	"Raffine's Tower":          "triome",
	"Spara's Headquarters":     "triome",
	"Xander's Lounge":          "triome",
	"Ziatora's Proving Ground": "triome",
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

// applyCardFilter dispatches a card filter by name through a switch of
// named functions rather than a map of func values: shouldSkipCardNG calls
// this once per filter per examined uuid, and calling through an opaque
// func value forced the freshly copied CardObject to escape to the heap on
// every card examined (the dominant allocation of pool-scanning searches).
// Unknown names panic, preserving the old registry behavior.
func applyCardFilter(name string, filters []string, co *mtgmatcher.CardObject) bool {
	switch name {
	case "name":
		return cardFilterName(filters, co)
	case "edition":
		return cardFilterEdition(filters, co)
	case "rarity":
		return cardFilterRarity(filters, co)
	case "format":
		return cardFilterFormat(filters, co)
	case "rarity_greater_than":
		return cardFilterRarityGreaterThan(filters, co)
	case "rarity_less_than":
		return cardFilterRarityLessThan(filters, co)
	case "type":
		return cardFilterType(filters, co)
	case "color":
		return cardFilterColor(filters, co)
	case "color_identity":
		return cardFilterColorIdentity(filters, co)
	case "idlookup":
		return cardFilterIdlookup(filters, co)
	case "contents":
		return cardFilterContents(filters, co)
	case "number":
		return cardFilterNumber(filters, co)
	case "number_strict":
		return cardFilterNumberStrict(filters, co)
	case "number_greater_than":
		return cardFilterNumberGreaterThan(filters, co)
	case "number_less_than":
		return cardFilterNumberLessThan(filters, co)
	case "finish":
		return cardFilterFinish(filters, co)
	case "date":
		return cardFilterDate(filters, co)
	case "date_greater_than":
		return cardFilterDateGreaterThan(filters, co)
	case "date_less_than":
		return cardFilterDateLessThan(filters, co)
	case "altname":
		return cardFilterAltname(filters, co)
	case "on":
		return cardFilterOn(filters, co)
	case "is":
		return cardFilterIs(filters, co)
	}
	panic(name + " option not found")
}

func cardFilterName(filters []string, co *mtgmatcher.CardObject) bool {
	return !mtgmatcher.Equals(filters[0], co.Name) && !mtgmatcher.Equals(filters[0], co.FlavorName)
}

// cardFilterRegexp is where every pattern filter compares. The pattern was
// compiled when the query was parsed, and a pattern that would not compile
// arrives nil and matches nothing - which is what the error discarded by the
// MatchString these filters used to call already said.
func cardFilterRegexp(name string, re *regexp.Regexp, co *mtgmatcher.CardObject) bool {
	if re == nil {
		return true
	}
	switch name {
	case "name_regexp":
		return !re.MatchString(co.Name) && !re.MatchString(co.FlavorName)
	case "edition_regexp":
		return !re.MatchString(co.Edition)
	case "number_regexp":
		return !re.MatchString(co.Number)
	}
	return true
}

func cardFilterEdition(filters []string, co *mtgmatcher.CardObject) bool {
	return !slices.Contains(filters, co.SetCode)
}

func cardFilterRarity(filters []string, co *mtgmatcher.CardObject) bool {
	return !slices.Contains(filters, co.Rarity)
}

func cardFilterFormat(filters []string, co *mtgmatcher.CardObject) bool {
	// Keep the card if it's legal (or restricted) in any requested format.
	for _, value := range filters {
		switch co.Legalities[value] {
		case "Legal", "Restricted":
			return false
		}
	}
	return true
}

func cardFilterRarityGreaterThan(filters []string, co *mtgmatcher.CardObject) bool {
	rarityIndex, found := rarityMap[filters[0]]
	if !found {
		return true
	}
	return rarityIndex >= rarityMap[co.Rarity]
}

func cardFilterRarityLessThan(filters []string, co *mtgmatcher.CardObject) bool {
	rarityIndex, found := rarityMap[filters[0]]
	if !found {
		return true
	}
	return rarityIndex <= rarityMap[co.Rarity]
}

func cardFilterType(filters []string, co *mtgmatcher.CardObject) bool {
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
				slices.Contains(co.Supertypes, value) ||
				co.PrintedType == value {
				return false
			}
		}
	}
	return true
}

func cardFilterColor(filters []string, co *mtgmatcher.CardObject) bool {
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
}

func cardFilterColorIdentity(filters []string, co *mtgmatcher.CardObject) bool {
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
}

func cardFilterIdlookup(filters []string, co *mtgmatcher.CardObject) bool {
	return !slices.Contains(filters, co.UUID)
}

func cardFilterContents(filters []string, co *mtgmatcher.CardObject) bool {
	values := cardobject2sources(co)
	for _, filter := range filters {
		if !slices.Contains(values, filter) {
			return true
		}
	}
	return false
}

func cardFilterNumber(filters []string, co *mtgmatcher.CardObject) bool {
	return !slices.Contains(filters, strings.ToLower(co.OriginalNumber))
}

func cardFilterNumberStrict(filters []string, co *mtgmatcher.CardObject) bool {
	return !slices.Contains(filters, strings.ToLower(co.Number))
}

func cardFilterNumberGreaterThan(filters []string, co *mtgmatcher.CardObject) bool {
	return compareCollectorNumber(filters, co, func(a, b int) bool {
		return a > b
	})
}

func cardFilterNumberLessThan(filters []string, co *mtgmatcher.CardObject) bool {
	return compareCollectorNumber(filters, co, func(a, b int) bool {
		return a < b
	})
}

func cardFilterFinish(filters []string, co *mtgmatcher.CardObject) bool {
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

		// The game's own name for what this printing carries. Where a game
		// names no finishes of its own this is one of the three above and
		// agrees with them, so it costs those games nothing. Where it does,
		// it is the only thing telling two printings apart: Yu-Gi-Oh prices
		// print runs, so f:1stedition and f:unlimited are the whole
		// distinction and neither is a foilness a case can answer.
		if co.Finish != "" && value == co.Finish {
			return false
		}

		// A spelling this printing answers to. A game registers the bare
		// treatment name beside the run-qualified one a product is actually
		// sold under, so f:rainbowfoil reaches a product whose only rainbow
		// is the Unlimited printing. An alias names a finish rather than a
		// printing, so it counts only where it resolves to this one.
		alias, aliased := co.FinishAliases[value]
		if aliased && co.UUID != "" && co.FoilUUIDs[alias] == co.UUID {
			return false
		}

		// Magic keeps its foil treatments as promo types rather than finishes
		// - its CanonicalFinish answers with the three shared names and
		// nothing else - so a galaxy foil is a foil whose treatment is filed
		// elsewhere. A treatment is what a person means by finish, and
		// uuid2card already prints it in place of the foil chip, so f: should
		// reach it: altFoilTags is exactly the promo types that name a
		// foiling, which is why it gates this and any promo type does not.
		treatment := value
		expanded, known := isKnownPromo[value]
		if known {
			treatment = expanded
		}
		if slices.Contains(altFoilTags, treatment) && co.HasPromoType(treatment) {
			return false
		}
	}
	return true
}

func cardFilterDate(filters []string, co *mtgmatcher.CardObject) bool {
	return compareReleaseDate(filters, co, func(a, b time.Time) bool {
		return !a.Equal(b)
	})
}

func cardFilterDateGreaterThan(filters []string, co *mtgmatcher.CardObject) bool {
	return compareReleaseDate(filters, co, func(a, b time.Time) bool {
		return a.Before(b)
	})
}

func cardFilterDateLessThan(filters []string, co *mtgmatcher.CardObject) bool {
	return compareReleaseDate(filters, co, func(a, b time.Time) bool {
		return a.After(b)
	})
}

func cardFilterAltname(filters []string, co *mtgmatcher.CardObject) bool {
	return (co.FlavorName != "" && mtgmatcher.Normalize(co.FlavorName) != filters[0]) ||
		(co.FaceFlavorName != "" && mtgmatcher.Normalize(co.FaceFlavorName) != filters[0])
}

func cardFilterOn(filters []string, co *mtgmatcher.CardObject) bool {
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
		case "hotlist":
			_, found := GetInfos()["hotlist"][co.UUID]
			if found {
				return false
			}
		case "ckp90":
			// Cards whose current Card Kingdom buylist meets its latest P90.
			if good := getGoodBuylistPrice(co.UUID); good > 0 {
				if bl, err := findVendorBuylist("CK"); err == nil {
					if entries, ok := bl[co.UUID]; ok && len(entries) > 0 && entries[0].BuyPrice >= good {
						return false
					}
				}
			}
		case "newspaper":
			if uuids := GetNewspaperUUIDs(); uuids != nil {
				if _, found := uuids[co.UUID]; found {
					return false
				}
			}
		}
	}
	return true
}

func cardFilterIs(filters []string, co *mtgmatcher.CardObject) bool {
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
			if co.HasFrameEffect(magic.FrameEffectExtendedArt) {
				return false
			}
		case "showcase", "sc", "sh":
			if co.HasFrameEffect(magic.FrameEffectShowcase) {
				return false
			}
		case "borderless", "bd", "bl":
			if co.BorderColor == magic.BorderColorBorderless {
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
			if co.Language == magic.LanguageJapanese {
				return false
			}
		case "phyrexian", "ph":
			if co.Language == magic.LanguagePhyrexian {
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
			if co.HasPromoType(magic.PromoTypeEmbossed) {
				return false
			}
		case "p9":
			customTag, found := specialTags[co.Name]
			if found && customTag == "power9" {
				return false
			}
		case "altfoil":
			for _, tag := range altFoilTags {
				if co.HasPromoType(tag) {
					return false
				}
			}
		default:
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

		// Every value reaches the promo types, including the ones a case
		// above already asked about. Several names mean a Magic frame effect
		// and another game's promo type at once - "extendedart" is a frame
		// effect on a Magic card and a printing's own tag on a Flesh and
		// Blood one - and while the case answered first, the second meaning
		// was unreachable: is:extendedart asked a Flesh and Blood card for a
		// frame effect it never carries and matched nothing, which not:
		// turned into excluding nothing.
		//
		// A case that matched has already returned, so arriving here means
		// its own reading did not hold and the promo type is the reading left.
		newValue, found := isKnownPromo[value]
		if found {
			value = newValue
		}
		if slices.Contains(mtgmatcher.AllPromoTypes(), value) {
			if co.HasPromoType(value) {
				return false
			}
		}
	}
	return true
}

func shouldSkipCardNG(cardID string, filters []FilterElem) bool {
	co, err := mtgmatcher.GetUUID(cardID)
	if err != nil {
		return true
	}

	for i := range filters {
		skip := shouldSkipCardNG(cardID, filters[i].Subfilters)
		if skip {
			return true
		}

		// Filter out any SetCode that wasn't selected
		if filters[i].ApplyTo != nil && !slices.Contains(filters[i].ApplyTo, co.SetCode) {
			continue
		}

		var res bool
		switch filters[i].Name {
		case "name_regexp", "edition_regexp", "number_regexp":
			res = cardFilterRegexp(filters[i].Name, filters[i].Regexp, co)
		default:
			res = applyCardFilter(filters[i].Name, filters[i].Values, co)
		}
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
func storeFilterIndex(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	return scraper.Info().MetadataOnly
}

func storeFilterStore(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	if includeIndex && scraper.Info().MetadataOnly {
		return false
	}
	return !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
}

func storeFilterSeller(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	if includeIndex && scraper.Info().MetadataOnly {
		return false
	}
	_, ok := scraper.(mtgban.Seller)
	return ok && !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
}

func storeFilterVendor(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	if includeIndex && scraper.Info().MetadataOnly {
		return false
	}
	_, ok := scraper.(mtgban.Vendor)
	return ok && !slices.Contains(filters, strings.ToLower(scraper.Info().Shorthand))
}

func storeFilterRegion(filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	if includeIndex && scraper.Info().MetadataOnly {
		return false
	}
	return localizeScraper(filters, scraper)
}

// applyStoreFilter dispatches a store filter by name, mirroring
// applyCardFilter. Unknown names panic, preserving the old registry
// behavior.
func applyStoreFilter(name string, filters []string, scraper mtgban.Scraper, includeIndex bool) bool {
	switch name {
	case "index":
		return storeFilterIndex(filters, scraper, includeIndex)
	case "store":
		return storeFilterStore(filters, scraper, includeIndex)
	case "seller":
		return storeFilterSeller(filters, scraper, includeIndex)
	case "vendor":
		return storeFilterVendor(filters, scraper, includeIndex)
	case "region":
		return storeFilterRegion(filters, scraper, includeIndex)
	}
	panic(name + " option not found")
}

func shouldSkipStoreNG(scraper mtgban.Scraper, filters []FilterStoreElem) bool {
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

		res := applyStoreFilter(filters[i].Name, filters[i].Values, scraper, filters[i].IncludeIndex)
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

// priceFilterInvalidDirect doubles the check price, filtering out anything
// (above 1usd) that is at least twice as much the market price
func priceFilterInvalidDirect(filters []float64, refPrice float64) bool {
	if len(filters) > 0 && filters[0] < 1 {
		return false
	}
	return priceLessThan(filters, refPrice/2)
}

// applyPriceFilter dispatches a price filter by name, mirroring
// applyCardFilter. Unknown names panic, preserving the old registry
// behavior.
func applyPriceFilter(name string, filters []float64, refPrice float64) bool {
	switch name {
	case "price_greater_than", "buy_price_greater_than",
		"arb_price_greater_than", "rev_price_greater_than":
		return priceGreaterThan(filters, refPrice)
	case "price_less_than", "buy_price_less_than",
		"arb_price_less_than", "rev_price_less_than":
		return priceLessThan(filters, refPrice)
	case "invalid_direct":
		return priceFilterInvalidDirect(filters, refPrice)
	}
	panic(name + " option not found")
}

func shouldSkipPriceNG(cardID string, entry mtgban.GenericEntry, filters []*FilterPriceElem, shorthand string) bool {
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
		prices, found := filters[i].PriceCache[cardID]
		filters[i].Mutex.RUnlock()
		if !found {
			// If there is no set value, then look it up with the price4store function
			if filters[i].Value == 0 {
				for j := range filters[i].Stores {
					price := filters[i].Price4Store(cardID, filters[i].Stores[j])
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

			// Update cache synchronously so the card's next entries hit it: an
			// async write lands after the burst of same-card lookups has already
			// missed, recomputing the store prices for nearly every entry (and
			// spawning a goroutine per miss).
			filters[i].Mutex.Lock()
			if filters[i].PriceCache == nil {
				filters[i].PriceCache = map[string][]float64{}
			}
			filters[i].PriceCache[cardID] = prices
			filters[i].Mutex.Unlock()
		}

		res := applyPriceFilter(filters[i].Name, prices, entry.Pricing())
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

func entryFilterCondition(filters []string, entry mtgban.GenericEntry) bool {
	return !slices.Contains(filters, entry.Condition())
}

func entryFilterConditionGreaterThan(filters []string, entry mtgban.GenericEntry) bool {
	condIndex, found := conditionMap[filters[0]]
	if !found {
		return true
	}
	return condIndex >= conditionMap[entry.Condition()]
}

func entryFilterConditionLessThan(filters []string, entry mtgban.GenericEntry) bool {
	condIndex, found := conditionMap[filters[0]]
	if !found {
		return true
	}
	return condIndex <= conditionMap[entry.Condition()]
}

func entryFilterQtyGreaterThan(filters []string, entry mtgban.GenericEntry) bool {
	if entry.Qty() == 0 {
		return true
	}
	num, _ := strconv.Atoi(filters[0])
	return num >= entry.Qty()
}

func entryFilterQtyLessThan(filters []string, entry mtgban.GenericEntry) bool {
	if entry.Qty() == 0 {
		return true
	}
	num, _ := strconv.Atoi(filters[0])
	return num <= entry.Qty()
}

func entryFilterRatioGreaterThan(filters []string, entry mtgban.GenericEntry) bool {
	buylist, ok := entry.(mtgban.BuylistEntry)
	if !ok || buylist.PriceRatio == 0 {
		return true
	}
	value, _ := strconv.ParseFloat(filters[0], 64)
	return value >= buylist.PriceRatio
}

func entryFilterRatioLessThan(filters []string, entry mtgban.GenericEntry) bool {
	buylist, ok := entry.(mtgban.BuylistEntry)
	if !ok || buylist.PriceRatio == 0 {
		return true
	}
	value, _ := strconv.ParseFloat(filters[0], 64)
	return value <= buylist.PriceRatio
}

// applyEntryFilter dispatches an entry filter by name, mirroring
// applyCardFilter. Unknown names panic, preserving the old registry
// behavior.
func applyEntryFilter(name string, filters []string, entry mtgban.GenericEntry) bool {
	switch name {
	case "condition":
		return entryFilterCondition(filters, entry)
	case "condition_greater_than":
		return entryFilterConditionGreaterThan(filters, entry)
	case "condition_less_than":
		return entryFilterConditionLessThan(filters, entry)
	case "qty_greater_than":
		return entryFilterQtyGreaterThan(filters, entry)
	case "qty_less_than":
		return entryFilterQtyLessThan(filters, entry)
	case "ratio_greater_than":
		return entryFilterRatioGreaterThan(filters, entry)
	case "ratio_less_than":
		return entryFilterRatioLessThan(filters, entry)
	}
	panic(name + " option not found")
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

		res := applyEntryFilter(filters[i].Name, filters[i].Values, entry)
		if filters[i].Negate {
			res = !res
		}
		if res {
			return true
		}
	}

	return false
}

func postFilterEmpty(filters []string, cardID string, foundScraper map[string]map[string][]SearchEntry) bool {
	return len(foundScraper[cardID]) == 0 ||
		(len(foundScraper[cardID]) == 1 && len(foundScraper[cardID]["INDEX"]) != 0)
}

func postFilterAny(filters []string, cardID string, foundScraper map[string]map[string][]SearchEntry) bool {
	for _, cond := range AllConditions {
		for _, entry := range foundScraper[cardID][cond] {
			for _, shorthand := range filters {
				if strings.ToLower(entry.Shorthand) == shorthand {
					return false
				}
			}
		}
	}
	return true
}

// applyPostFilter dispatches a post-search filter by name, mirroring
// applyCardFilter. Unknown names panic, preserving the old registry
// behavior.
func applyPostFilter(name string, filters []string, cardID string, foundScraper map[string]map[string][]SearchEntry) bool {
	switch name {
	case "empty":
		return postFilterEmpty(filters, cardID, foundScraper)
	case "any":
		return postFilterAny(filters, cardID, foundScraper)
	}
	panic(name + " option not found")
}

func shouldSkipPostNG(cardID string, foundSellers, foundVendors map[string]map[string][]SearchEntry, filters []FilterPostElem) bool {
	for i := range filters {
		var foundScrapers map[string]map[string][]SearchEntry
		if filters[i].OnlyForSeller {
			foundScrapers = foundSellers
		} else if filters[i].OnlyForVendor {
			foundScrapers = foundVendors
		} else {
			resS := applyPostFilter(filters[i].Name, filters[i].Values, cardID, foundSellers)
			resV := applyPostFilter(filters[i].Name, filters[i].Values, cardID, foundVendors)
			res := resS && resV
			if res {
				return true
			}
			continue
		}

		res := applyPostFilter(filters[i].Name, filters[i].Values, cardID, foundScrapers)
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

	var keepIDs []string

	for _, cardID := range allKeys {
		if shouldSkipPostNG(cardID, foundSellers, foundVendors, config.PostFilters) {
			continue
		}
		keepIDs = append(keepIDs, cardID)
	}

	return keepIDs
}
