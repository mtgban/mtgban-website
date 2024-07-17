package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/unistyle"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/mtgjson"
	"golang.org/x/exp/slices"
)

const (
	MaxSearchQueryLen = 200
	MaxSearchResults  = 100
	TooLongMessage    = "Your query planeswalked away, try a shorter one"
	TooManyMessage    = "Too many results, try adjusting your filters"
	NoResultsMessage  = "No results found"
	NoCardsMessage    = "No cards found"

	MaxSearchTotalResults = 10000
)

var (
	defaultSellerPriorityOpt = []string{TCG_MARKET, TCG_LOW, "TCGSealed"}
	defaultVendorPriorityOpt = []string{"CK", "SS"}
)

type SearchEntry struct {
	ScraperName string
	Shorthand   string
	Price       float64
	Credit      float64
	Ratio       float64
	Quantity    int
	URL         string
	NoQuantity  bool
	BundleIcon  string

	Country string

	IndexCombined bool
	Secondary     float64

	// Cannot use slices or pointers to remain compatible with Comparable
	Tertiary float64

	// Price does not look correct
	IsSussy  bool
	SusPrice float64
}

var AllConditions = []string{"INDEX", "NM", "SP", "MP", "HP", "PO"}

func Search(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Search", sig)

	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	query := strings.TrimSpace(r.FormValue("q"))

	oembed := strings.HasPrefix(r.URL.Path, "/search/oembed")
	if oembed {
		page := r.FormValue("url")
		u, err := url.Parse(page)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`Internal Server Error`))
			return
		}
		values := u.Query()
		query = values.Get("q")
		if query == "" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`Not Found`))
			return
		}
	}

	pageVars.IsSealed = r.URL.Path == "/sealed"
	pageVars.IsSets = r.URL.Path == "/sets"
	if query == "" {
		pageVars.PromoTags = mtgmatcher.AllPromoTypes()
	}

	pageVars.Nav = insertNavBar("Search", pageVars.Nav, []NavElem{
		NavElem{
			Name:   "Sets",
			Short:  "📦",
			Link:   "/sets",
			Active: pageVars.IsSets,
			Class:  "selected",
		},
	})

	pageVars.Nav = insertNavBar("Sets", pageVars.Nav, []NavElem{
		NavElem{
			Name:   "Sealed",
			Short:  "🧱",
			Link:   "/sealed",
			Active: pageVars.IsSealed,
			Class:  "selected",
		},
	})

	page := r.FormValue("page")
	if page == "options" {
		pageVars.Title = "Options"

		for _, seller := range Sellers {
			if seller == nil ||
				slices.Contains(blocklistRetail, seller.Info().Shorthand) {
				continue
			}

			pageVars.SellerKeys = append(pageVars.SellerKeys, seller.Info().Shorthand)
		}

		for _, vendor := range Vendors {
			if vendor == nil ||
				slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
				continue
			}

			pageVars.VendorKeys = append(pageVars.VendorKeys, vendor.Info().Shorthand)
		}

		render(w, "search.html", pageVars)

		return
	}

	skipSellersOpt := readCookie(r, "SearchSellersList")
	if skipSellersOpt != "" {
		blocklistRetail = append(blocklistRetail, strings.Split(skipSellersOpt, ",")...)
	}
	skipVendorsOpt := readCookie(r, "SearchVendorsList")
	if skipVendorsOpt != "" {
		blocklistBuylist = append(blocklistBuylist, strings.Split(skipVendorsOpt, ",")...)
	}
	// For buylists, if open mode, filter any store except the ones in the AffiliatesBuylistList
	if sig == "" && SigCheck {
		for _, vendor := range Vendors {
			if vendor != nil && !slices.Contains(Config.AffiliatesBuylistList, vendor.Info().Shorthand) {
				blocklistBuylist = append(blocklistBuylist, vendor.Info().Shorthand)
			}
		}
		pageVars.DisableChart = true
		pageVars.InfoMessage = "Join BAN to unlock additional buylists and tools!"
	}

	pageVars.SearchSort = readCookie(r, "SearchDefaultSort")
	defaultSortOpt := r.FormValue("sort")
	if defaultSortOpt != "" {
		pageVars.SearchSort = defaultSortOpt
	}

	pageVars.SearchBest = (readCookie(r, "SearchListingPriority") == "prices")

	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	pageVars.CanDownloadCSV = canDownloadCSV

	if len(query) > MaxSearchQueryLen {
		pageVars.ErrorMessage = TooLongMessage

		render(w, "search.html", pageVars)
		return
	}

	chartId := r.FormValue("chart")
	// Check if query is a valid ID
	co, err := mtgmatcher.GetUUID(chartId)
	if err != nil || pageVars.DisableChart {
		// Stay on the same probable query page
		if query == "" {
			query = chartId
		}
		chartId = ""
	} else {
		// Override the query when chart is requested
		query = chartId
	}

	// If query is empty there is nothing to do
	if query == "" {
		// Hijack sealed list
		if pageVars.IsSealed {
			pageVars.EditionSort = SealedEditionsSorted
			pageVars.EditionList = SealedEditionsList
			render(w, "search.html", pageVars)
			return
		} else if pageVars.IsSets {
			pageVars.EditionSort = TreeEditionsKeys
			pageVars.EditionList = TreeEditionsMap
			pageVars.TotalSets = TotalSets
			pageVars.TotalCards = TotalCards
			pageVars.TotalUnique = TotalUnique

			sortOpt := r.FormValue("sort")

			if sortOpt == "name" {
				namedSort := make([]string, len(TreeEditionsKeys))
				copy(namedSort, TreeEditionsKeys)
				sort.Slice(namedSort, func(i, j int) bool {
					return TreeEditionsMap[namedSort[i]][0].Name < TreeEditionsMap[namedSort[j]][0].Name
				})
				pageVars.EditionSort = namedSort
			} else if sortOpt == "size" {
				sizeSort := make([]string, len(TreeEditionsKeys))
				copy(sizeSort, TreeEditionsKeys)
				sort.Slice(sizeSort, func(i, j int) bool {
					if TreeEditionsMap[sizeSort[i]][0].Size == TreeEditionsMap[sizeSort[j]][0].Size {
						return TreeEditionsMap[sizeSort[i]][0].Name < TreeEditionsMap[sizeSort[j]][0].Name
					}
					return TreeEditionsMap[sizeSort[i]][0].Size > TreeEditionsMap[sizeSort[j]][0].Size
				})
				pageVars.EditionSort = sizeSort
			}

			render(w, "editions.html", pageVars)
			return
		}

		render(w, "search.html", pageVars)
		return
	}

	start := time.Now()

	// Keep track of what was searched
	pageVars.SearchQuery = query
	pageVars.Page = getBaseURL(r) + r.URL.String()
	pageVars.OembedURL = getBaseURL(r) + "/search/oembed?format=json&url=" + url.QueryEscape(getBaseURL(r)+"/search?q="+query)
	pageVars.CondKeys = AllConditions
	pageVars.Metadata = map[string]GenericCard{}

	config := parseSearchOptionsNG(query, blocklistRetail, blocklistBuylist)
	if pageVars.IsSealed {
		config.SearchMode = "sealed"
	}

	if config.SortMode != "" {
		pageVars.SearchSort = config.SortMode
		pageVars.NoSort = true
	}

	if oembed {
		// Skip any store based outside of the US
		config.StoreFilters = append(config.StoreFilters, FilterStoreElem{
			Name:   "region_keep_index",
			Values: []string{"us"},
		})
		// Skip non-NM buylist prices
		config.EntryFilters = append(config.EntryFilters, FilterEntryElem{
			Name:          "condition",
			Values:        []string{"NM"},
			OnlyForVendor: true,
		})
	}

	var hideSus bool
	var hideSyp bool
	miscSearchOpts := readCookie(r, "SearchMiscOpts")
	if miscSearchOpts != "" {
		for _, optName := range strings.Split(miscSearchOpts, ",") {
			switch optName {
			// Skip promotional entries (unless specified)
			case "hidePromos":
				var skipOption bool
				for _, filter := range config.CardFilters {
					if filter.Name == "is" {
						for _, value := range filter.Values {
							if value == "promo" && !filter.Negate {
								skipOption = true
							}
						}
					}
				}
				if !skipOption {
					config.CardFilters = append(config.CardFilters, FilterElem{
						Name:   "is",
						Negate: true,
						Values: []string{"promo"},
					})
				}
			// Skip non-NM buylist prices
			case "hideBLconds":
				config.EntryFilters = append(config.EntryFilters, FilterEntryElem{
					Name:          "condition",
					Values:        []string{"NM"},
					OnlyForVendor: true,
				})
			// Skip results with no prices
			case "skipEmpty":
				config.SkipEmptyRetail = true
				config.SkipEmptyBuylist = true
			case "noSyp":
				hideSyp = true
			case "noUpsell":
				pageVars.ShowPromo = true
			case "noSussy":
				hideSus = true
				config.SkipEmptyRetail = true
				config.PriceFilters = append(config.PriceFilters, FilterPriceElem{
					Name:        "invalid_direct",
					Price4Store: price4seller,
					Stores:      []string{TCG_MARKET},
					ApplyTo:     []string{TCG_DIRECT, "TCGDirectNet"},
				})
			}
		}
	}

	// Hijack for csv download
	downloadCSV := r.FormValue("downloadCSV")
	if canDownloadCSV && (downloadCSV == "retail" || downloadCSV == "buylist") {
		// Perform the search
		selectedUUIDs, err := searchAndFilter(config)
		if err != nil {
			UserNotify("search", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "search.html", pageVars)
			return
		}

		// Limit results to be processed
		if len(selectedUUIDs) > MaxUploadProEntries {
			selectedUUIDs = selectedUUIDs[:MaxUploadProEntries]
		}

		var enabledStores []string
		if downloadCSV == "retail" {
			for _, seller := range Sellers {
				if seller != nil && !slices.Contains(blocklistRetail, seller.Info().Shorthand) {
					enabledStores = append(enabledStores, seller.Info().Shorthand)
				}
			}
		} else if downloadCSV == "buylist" {
			for _, vendor := range Vendors {
				if vendor != nil && !slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
					enabledStores = append(enabledStores, vendor.Info().Shorthand)
				}
			}
		}

		var filename string
		mode := "scryfall"
		if pageVars.IsSealed {
			mode = "mtgjson"
		}
		var results map[string]map[string]*BanPrice
		if downloadCSV == "retail" {
			results = getSellerPrices(mode, enabledStores, "", selectedUUIDs, "", true, true, pageVars.IsSealed)
			filename = "mtgban_retail_prices.csv"
		} else if downloadCSV == "buylist" {
			results = getVendorPrices(mode, enabledStores, "", selectedUUIDs, "", true, true, pageVars.IsSealed)
			filename = "mtgban_buylist_prices.csv"
		} else {
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "search.html", pageVars)
			return
		}

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		csvWriter := csv.NewWriter(w)

		err = BanPrice2CSV(csvWriter, results, true, true, pageVars.IsSealed)
		if err != nil {
			w.Header().Del("Content-Type")
			w.Header().Del("Content-Disposition")
			UserNotify("search", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "search.html", pageVars)
		}
		return
	} else if downloadCSV == "decklist" {
		// Perform the search
		selectedUUIDs, err := searchAndFilter(config)
		if err != nil {
			UserNotify("search", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "search.html", pageVars)
			return
		}

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+config.PrivateData+".csv\"")
		csvWriter := csv.NewWriter(w)

		err = UUID2TCGCSV(csvWriter, selectedUUIDs)
		if err != nil {
			w.Header().Del("Content-Type")
			w.Header().Del("Content-Disposition")
			UserNotify("search", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "search.html", pageVars)
		}
		return
	}

	allKeys, err := searchAndFilter(config)
	if err != nil {
		pageVars.InfoMessage = NoCardsMessage
		render(w, "search.html", pageVars)
		return
	}
	if len(allKeys) > MaxSearchTotalResults {
		pageVars.TotalCards = len(allKeys)
		pageVars.InfoMessage = TooManyMessage
		allKeys = allKeys[:MaxSearchTotalResults]
	}

	foundSellers, foundVendors := searchParallelNG(allKeys, config)

	cleanQuery := config.CleanQuery
	canShowAll := (len(config.CardFilters) != 0 || len(config.UUIDs) != 0)

	// Only used in hashing searches, fill in data with what is available
	if config.FullQuery != "" {
		pageVars.SearchQuery = config.FullQuery
	}

	// If SkipEmptyBuylist or SkipEmptyRetail are set, we need to remove ids from allKeys
	if config.SkipEmptyBuylist {
		var filteredKeys []string

		// Skip if nothing was found in buylist
		for _, cardId := range allKeys {
			if len(foundVendors[cardId]) == 0 {
				continue
			}
			filteredKeys = append(filteredKeys, cardId)
		}
		allKeys = filteredKeys
	}
	if config.SkipEmptyRetail {
		var filteredKeys []string

		// Skip if nothing was found in retail or only INDEX entries were found
		for _, cardId := range allKeys {
			if len(foundSellers[cardId]) == 0 ||
				(len(foundSellers[cardId]) == 1 && len(foundSellers[cardId]["INDEX"]) != 0) {
				continue
			}
			filteredKeys = append(filteredKeys, cardId)
		}
		allKeys = filteredKeys
	}

	// Early exit if there no matches are found
	if len(allKeys) == 0 {
		pageVars.InfoMessage = NoResultsMessage
		render(w, "search.html", pageVars)
		return
	}

	// Allow displaying the "search all" link only when something
	// was searched and no options were specified for it
	pageVars.CanShowAll = cleanQuery != "" && canShowAll
	pageVars.CleanSearchQuery = cleanQuery

	// Update page title
	if cleanQuery != "" {
		pageVars.Title += ": " + cleanQuery
	}

	// Save stats
	pageVars.TotalUnique = len(allKeys)

	// Needed to load search in Upload
	if canDownloadCSV {
		pageVars.CardHashes = allKeys
	}

	// Sort sets as requested, default to chronological
	switch pageVars.SearchSort {
	case "alpha":
		sort.Slice(allKeys, func(i, j int) bool {
			return sortSetsAlphabetical(allKeys[i], allKeys[j])
		})
	case "retail":
		retSellers := defaultSellerPriorityOpt
		retSeller := readCookie(r, "SearchSellersPriority")
		if retSeller != "" {
			retSellers = append([]string{retSeller}, defaultSellerPriorityOpt...)
		}

		sort.Slice(allKeys, func(i, j int) bool {
			return sortSetsByRetail(allKeys[i], allKeys[j], retSellers)
		})
	case "buylist":
		blVendors := defaultVendorPriorityOpt
		blVendor := readCookie(r, "SearchVendorsPriority")
		if blVendor != "" {
			blVendors = append([]string{blVendor}, defaultVendorPriorityOpt...)
		}

		sort.Slice(allKeys, func(i, j int) bool {
			return sortSetsByBuylist(allKeys[i], allKeys[j], blVendors)
		})
	default:
		sort.Slice(allKeys, func(i, j int) bool {
			return sortSets(allKeys[i], allKeys[j])
		})
	}

	// Invert the slice if requested
	reverseSort, _ := strconv.ParseBool(r.FormValue("reverse"))
	if reverseSort {
		for i, j := 0, len(allKeys)-1; i < j; i, j = i+1, j-1 {
			allKeys[i], allKeys[j] = allKeys[j], allKeys[i]
		}
	}
	pageVars.ReverseMode = reverseSort

	// If results can't fit in one page, chunk response and enable pagination
	if len(allKeys) > MaxSearchResults {
		pageIndex, _ := strconv.Atoi(r.FormValue("p"))
		allKeys, pageVars.Pagination = Paginate(allKeys, pageIndex, MaxSearchResults, MaxSearchTotalResults)
	}

	// Load up image links and other metadata
	for _, cardId := range allKeys {
		_, found := pageVars.Metadata[cardId]
		if !found {
			pageVars.Metadata[cardId] = uuid2card(cardId, false, true)
			if hideSyp {
				meta := pageVars.Metadata[cardId]
				meta.SypList = false
				pageVars.Metadata[cardId] = meta
			}
		}
		if pageVars.Metadata[cardId].Reserved {
			pageVars.HasReserved = true
		}
		if pageVars.Metadata[cardId].Stocks {
			pageVars.HasStocks = true
		}
		if pageVars.Metadata[cardId].SypList {
			pageVars.HasSypList = true
		}
	}

	// Optionally sort according to price
	if pageVars.SearchBest || oembed {
		for _, cardId := range allKeys {
			// This skips INDEX and PO conditions
			for _, cond := range mtgban.DefaultGradeTags {
				_, found := foundSellers[cardId][cond]
				if found {
					sort.Slice(foundSellers[cardId][cond], func(i, j int) bool {
						return foundSellers[cardId][cond][i].Price < foundSellers[cardId][cond][j].Price
					})
				}
				_, found = foundVendors[cardId][cond]
				if found {
					sort.Slice(foundVendors[cardId][cond], func(i, j int) bool {
						return foundVendors[cardId][cond][i].Price > foundVendors[cardId][cond][j].Price
					})
				}
			}
		}
	}

	embed, err := generateEmbed(allKeys, foundSellers, foundVendors, pageVars.HasStocks, pageVars.HasSypList)
	if oembed {
		if len(allKeys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`Not Found`))
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`Not Found`))
			return
		}

		payload, err := json.Marshal(embed)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`Internal Server Error`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
		return
	}
	pageVars.OembedTitle = embed.Title
	pageVars.OembedContents = embed.HTML
	pageVars.OembedDesc = embed.HTML
	if len(allKeys) > 0 {
		pageVars.ImageURL = scryfallImageURL(allKeys[0], false)
		co, err := mtgmatcher.GetUUID(allKeys[0])
		if err == nil && len(co.Printings) > 0 {
			pageVars.OembedDesc = fmt.Sprintf("Printed in %s.", printings2line(co.Printings))
		}
		pageVars.RetailPrice = price4seller(allKeys[0], TCG_MARKET)
		pageVars.BuylistPrice = price4seller(allKeys[0], "CK")
	}

	// Readjust array of INDEX entires
	for _, cardId := range allKeys {
		_, found := foundSellers[cardId]
		if !found {
			continue
		}
		indexArray := foundSellers[cardId]["INDEX"]
		tmp := indexArray[:0]
		mkmIndex := -1
		tcgIndex := -1
		sealedEVindexes := map[string]int{}

		// Iterate on array, always passthrough, except for specific entries
		for i := range indexArray {
			// Set index for sealed reuse
			evIndex := 0
			if strings.Contains(indexArray[i].ScraperName, "Median") {
				evIndex = 1
			} else if strings.Contains(indexArray[i].ScraperName, "StdDev") {
				evIndex = 2
			}

			switch indexArray[i].ScraperName {
			case MKM_LOW:
				// Save reference to the array
				tmp = append(tmp, indexArray[i])
				mkmIndex = len(tmp) - 1
			case MKM_TREND:
				// If the reference is found, add a secondary price
				// otherwise just leave it as is
				if mkmIndex >= 0 {
					tmp[mkmIndex].Secondary = indexArray[i].Price
					tmp[mkmIndex].ScraperName = "MKM (Low / Trend)"
					tmp[mkmIndex].IndexCombined = true
				} else {
					tmp = append(tmp, indexArray[i])
				}
			case TCG_LOW:
				// Save reference to the array
				tmp = append(tmp, indexArray[i])
				tcgIndex = len(tmp) - 1
			case TCG_MARKET:
				// If the reference is found, add a secondary price
				// otherwise just leave it as is
				if tcgIndex >= 0 {
					tmp[tcgIndex].Secondary = indexArray[i].Price
					tmp[tcgIndex].ScraperName = "TCG (Low / Market)"
					tmp[tcgIndex].IndexCombined = true
				} else {
					tmp = append(tmp, indexArray[i])
				}
			case TCG_DIRECT_LOW:
				// Skip this one for search results
				continue
			default:
				if slices.Contains(ScraperOptions["sealed_ev"].Keepers, indexArray[i].ScraperName) {
					// Determine an identifiers from the name (the second word)
					fields := strings.Fields(indexArray[i].ScraperName)
					if len(fields) < 2 {
						continue
					}
					id := fields[1]

					// If index is not present add to array and save index
					idx, found := sealedEVindexes[id]
					if !found {
						tmp = append(tmp, indexArray[i])
						idx = len(tmp) - 1
						sealedEVindexes[id] = idx
					}

					// Index is present, add to the existing entry
					switch evIndex {
					case 0:
						tmp[idx].Price = indexArray[i].Price
					case 1:
						tmp[idx].Secondary = indexArray[i].Price
					case 2:
						tmp[idx].Tertiary = indexArray[i].Price
					}
				} else {
					tmp = append(tmp, indexArray[i])
				}
			}
		}

		foundSellers[cardId]["INDEX"] = tmp
	}

	// Mark suspicious prices from TCG Direct
	if !hideSus {
		for _, cardId := range allKeys {
			marketPrice := getTCGMarketPrice(cardId)

			for _, foundScrapers := range []map[string][]SearchEntry{
				foundSellers[cardId], foundVendors[cardId],
			} {
				for cond, entries := range foundScrapers {
					for i, entry := range entries {
						switch entry.Shorthand {
						case TCG_DIRECT, "TCGDirectNet":
						default:
							continue
						}
						if entry.Price/2 > marketPrice {
							foundScrapers[cond][i].IsSussy = true
							foundScrapers[cond][i].SusPrice = marketPrice
						}
					}
				}
			}
		}
	}

	pageVars.FoundSellers = foundSellers
	pageVars.FoundVendors = foundVendors
	pageVars.AllKeys = allKeys

	// CHART ALL THE THINGS
	if chartId != "" {
		// Rebuild the search query by faking a uuid lookup
		cfg := parseSearchOptionsNG(chartId, nil, nil)
		pageVars.SearchQuery = cfg.FullQuery

		// Retrieve data
		labels, err := getDateAxisValues(chartId)
		if err != nil {
			pageVars.InfoMessage = "No chart data available"
		} else {
			pageVars.AxisLabels = labels
			pageVars.ChartID = chartId

			for _, config := range enabledDatasets {
				if co.Sealed && !config.HasSealed {
					continue
				}
				if !co.Sealed && config.OnlySealed {
					continue
				}
				dataset, err := getDataset(chartId, labels, config)
				if err != nil {
					log.Println(err)
					continue
				}
				pageVars.Datasets = append(pageVars.Datasets, dataset)
			}
		}

		altId, err := mtgmatcher.Match(&mtgmatcher.Card{
			Id:   chartId,
			Foil: !co.Foil,
		})
		if err == nil && altId != chartId {
			pageVars.Alternative = altId
		}

		altId, err = mtgmatcher.Match(&mtgmatcher.Card{
			Id:        chartId,
			Variation: "Etched",
		})
		if err == nil && altId != chartId {
			pageVars.AltEtchedId = altId
		}

		pageVars.StocksURL = pageVars.Metadata[chartId].StocksURL
	}

	var source string
	notifyTitle := "search"
	utm := r.FormValue("utm_source")
	if utm == "banbot" {
		id := r.FormValue("utm_affiliate")
		source = fmt.Sprintf("banbot (%s)", id)
	} else if utm == "autocard" {
		source = "autocard anywhere"
	} else if chartId != "" {
		source = "chart page"
		notifyTitle = "chart"
	} else {
		u, err := url.Parse(r.Referer())
		if err != nil {
			log.Println(err)
			source = "n/a"
		} else {
			if strings.Contains(u.Host, "mtgban") {
				source = u.Path
			} else {
				// Avoid automatic URL expansion in Discord
				source = fmt.Sprintf("<%s>", u.String())
			}
		}
	}
	user := GetParamFromSig(sig, "UserEmail")
	if user == "" {
		user = "anonymous"
	}
	msg := fmt.Sprintf("[%s] from %s by %s (took %v)", query, source, user, time.Since(start))
	UserNotify(notifyTitle, msg)
	LogPages["Search"].Println(msg)
	if DevMode {
		log.Println(msg)
	}

	if DevMode {
		start = time.Now()
	}
	render(w, "search.html", pageVars)
	if DevMode {
		log.Println("render took", time.Since(start))
	}
}

func generateEmbed(allKeys []string, foundSellers, foundVendors map[string]map[string][]SearchEntry, hasStocks, hasSyplist bool) (*OEmbed, error) {
	title := "Search Preview"
	img := ""
	htmlBody := ""
	var results []EmbedSearchResult

	for i, cardId := range allKeys {
		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			title = co.Name
			if co.Sealed {
				title += " 📦"
			} else if co.Etched {
				title += " 💫"
			} else if co.Foil {
				title += " ✨"
			}
			if len(co.Printings) > 0 {
				htmlBody += fmt.Sprintf("Printed in %s.\n\n", printings2line(co.Printings))
			}
			img = scryfallImageURL(cardId, true)
		}

		fieldName := fmt.Sprintf("[%s] %s - %s", co.SetCode, co.Name, editionTitle(cardId))

		results = append(results, EmbedSearchResult{
			CardId:        cardId,
			ResultsIndex:  ProcessEmbedSearchResultsSellers(foundSellers, true),
			NamesOverride: []string{fieldName},
		})

		if i > MaxCustomEntries {
			break
		}
	}

	for _, result := range results {
		fields := FormatEmbedSearchResult(&result)

		for _, field := range fields {
			htmlBody += unistyle.BoldSans(field.Name) + "\n"
			if field.Raw != "" {
				htmlBody += field.Raw + "\n"
			}

			for _, value := range field.Values {
				tag := ""
				if value.Tag != "" {
					tag = fmt.Sprintf(" (%s)", value.Tag)
				}
				htmlBody += "• " + value.ScraperName + tag + ": " + value.Price + "\n"
			}
			htmlBody += "\n"
		}
	}

	// Trim any extra space or carriage feed from the final response
	htmlBody = strings.TrimSpace(htmlBody)

	return &OEmbed{
		Version:         "1.0",
		ProviderName:    "MTGBAN Price Search",
		ProviderURL:     "https://mtgban.com",
		Title:           title,
		Type:            "link",
		HTML:            htmlBody,
		ThumbnailURL:    img,
		ThumbnailWidth:  488,
		ThumbnailHeight: 680,
	}, nil
}

func searchSellersNG(cardIds []string, config SearchConfig) (foundSellers map[string]map[string][]SearchEntry) {
	// Allocate memory
	foundSellers = map[string]map[string][]SearchEntry{}

	storeFilters := config.StoreFilters
	priceFilters := config.PriceFilters
	entryFilters := config.EntryFilters

	// Search sellers
	for _, seller := range Sellers {
		if shouldSkipStoreNG(seller, storeFilters) {
			continue
		}

		// Get inventory
		inventory, err := seller.Inventory()
		if err != nil {
			continue
		}

		for _, cardId := range cardIds {
			entries, found := inventory[cardId]
			if !found {
				continue
			}

			// Loop thorugh available conditions
			for _, entry := range entries {
				// Skip cards that have not the desired condition
				if !seller.Info().MetadataOnly && shouldSkipEntryNG(entry, entryFilters) {
					continue
				}

				// Skip cards that don't match desired pricing
				if shouldSkipPriceNG(cardId, entry, priceFilters, seller.Info().Shorthand) {
					continue
				}

				// Check if card already has any entry
				_, found := foundSellers[cardId]
				if !found {
					foundSellers[cardId] = map[string][]SearchEntry{}
				}

				// Set conditions - handle the special TCG one that appears
				// at the top of the results
				conditions := entry.Conditions
				if seller.Info().MetadataOnly {
					conditions = "INDEX"
				}

				// Only add Poor prices if there are no NM and SP entries
				if conditions == "PO" && len(foundSellers[cardId]["NM"]) != 0 && len(foundSellers[cardId]["SP"]) != 0 {
					continue
				}

				icon := ""
				name := seller.Info().Name
				switch name {
				case TCG_MAIN:
					name = "TCGplayer"
				case TCG_DIRECT:
					name = "TCGplayer Direct"
					icon = "/img/misc/direct.png"
				case CT_ZERO:
					icon = "/img/misc/zero.png"
				case CT_STANDARD_SEALED:
					name = CT_STANDARD
				case CT_ZERO_SEALED:
					name = CT_ZERO
					icon = "/img/misc/zero.png"
				}

				// Prepare all the deets
				res := SearchEntry{
					ScraperName: name,
					Shorthand:   seller.Info().Shorthand,
					Price:       entry.Price,
					Quantity:    entry.Quantity,
					URL:         entry.URL,
					NoQuantity:  seller.Info().NoQuantityInventory || seller.Info().MetadataOnly,
					BundleIcon:  icon,
					Country:     Country2flag[seller.Info().CountryFlag],
				}

				// Do not add the same data twice
				if slices.Contains(foundSellers[cardId][conditions], res) {
					continue
				}

				// Touchdown
				foundSellers[cardId][conditions] = append(foundSellers[cardId][conditions], res)
			}
		}
	}

	return
}

func searchVendorsNG(cardIds []string, config SearchConfig) (foundVendors map[string]map[string][]SearchEntry) {
	foundVendors = map[string]map[string][]SearchEntry{}

	storeFilters := config.StoreFilters
	priceFilters := config.PriceFilters
	entryFilters := config.EntryFilters

	for _, vendor := range Vendors {
		if shouldSkipStoreNG(vendor, storeFilters) {
			continue
		}

		buylist, err := vendor.Buylist()
		if err != nil {
			continue
		}

		for _, cardId := range cardIds {
			entries, found := buylist[cardId]
			if !found {
				continue
			}

			for _, entry := range entries {
				if shouldSkipEntryNG(entry, entryFilters) {
					continue
				}

				if shouldSkipPriceNG(cardId, entry, priceFilters, vendor.Info().Shorthand) {
					continue
				}

				_, found = foundVendors[cardId]
				if !found {
					foundVendors[cardId] = map[string][]SearchEntry{}
				}

				conditions := entry.Conditions

				icon := ""
				name := vendor.Info().Name
				switch name {
				case TCG_DIRECT_NET:
					icon = "/img/misc/direct.png"
				case "TCG Player Market":
					name = "TCGplayer Trade-In"
				case "Sealed EV Scraper":
					name = "CK Buylist for Singles"
				}

				res := SearchEntry{
					ScraperName: name,
					Shorthand:   vendor.Info().Shorthand,
					Price:       entry.BuyPrice,
					Credit:      entry.BuyPrice * vendor.Info().CreditMultiplier,
					Ratio:       entry.PriceRatio,
					Quantity:    entry.Quantity,
					URL:         entry.URL,
					BundleIcon:  icon,
					Country:     Country2flag[vendor.Info().CountryFlag],
				}

				if slices.Contains(foundVendors[cardId][conditions], res) {
					continue
				}

				foundVendors[cardId][conditions] = append(foundVendors[cardId][conditions], res)
			}
		}
	}

	return
}

func searchAndFilter(config SearchConfig) ([]string, error) {
	query := config.CleanQuery
	filters := config.CardFilters

	var uuids []string
	var err error
	switch config.SearchMode {
	case "exact":
		uuids, err = mtgmatcher.SearchEquals(query)
	case "any":
		uuids, err = mtgmatcher.SearchContains(query)
	case "prefix":
		uuids, err = mtgmatcher.SearchHasPrefix(query)
	case "hashing":
		uuids = config.UUIDs
	case "regexp":
		uuids, err = mtgmatcher.SearchRegexp(query)
	case "sealed":
		uuids, err = mtgmatcher.SearchSealedEquals(query)
		if err != nil {
			uuids, err = mtgmatcher.SearchSealedContains(query)
		}
	case "mixed":
		uuids, err = mtgmatcher.SearchSealedEquals(query)
		if err != nil {
			uuids, err = mtgmatcher.SearchSealedContains(query)
		}
		moreUUIDs, _ := mtgmatcher.SearchEquals(query)
		uuids = append(uuids, moreUUIDs...)
	default:
		uuids, err = mtgmatcher.SearchEquals(query)
		if err != nil {
			uuids, err = mtgmatcher.SearchHasPrefix(query)
			if err != nil {
				uuids, err = mtgmatcher.SearchRegexp(query)
			}
		}
	}
	if err != nil {
		uuids, err = attemptMatch(query)
		if err != nil {
			return nil, err
		}
	}

	var selectedUUIDs []string
	for _, uuid := range uuids {
		if shouldSkipCardNG(uuid, filters) {
			continue
		}
		selectedUUIDs = append(selectedUUIDs, uuid)
	}
	return selectedUUIDs, nil
}

// Try searching for cards usign the Match algorithm
func attemptMatch(query string) ([]string, error) {
	var uuids []string
	uuid, err := mtgmatcher.Match(&mtgmatcher.Card{
		Name: query,
	})
	if err != nil {
		var alias *mtgmatcher.AliasingError
		if errors.As(err, &alias) {
			uuids = alias.Probe()
		} else {
			// Unsupported case, give up
			return nil, err
		}
	} else {
		uuids = append(uuids, uuid)
	}

	// Repeat for foil and etched (only add if not previously found)
	// Add as needed depending on the previous query result
	for _, tag := range []string{"Foil", "Etched"} {
		uuid, suberr := mtgmatcher.Match(&mtgmatcher.Card{
			Name:      query,
			Variation: tag,
		})
		if err != nil && suberr != nil {
			var alias *mtgmatcher.AliasingError
			if errors.As(suberr, &alias) {
				for _, extra := range alias.Probe() {
					if !slices.Contains(uuids, extra) {
						uuids = append(uuids, extra)
					}
				}
			}
		} else if !slices.Contains(uuids, uuid) {
			uuids = append(uuids, uuid)
		}
	}

	return uuids, nil
}

func searchParallelNG(cardIds []string, config SearchConfig) (foundSellers map[string]map[string][]SearchEntry, foundVendors map[string]map[string][]SearchEntry) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		if !config.SkipRetail {
			foundSellers = searchSellersNG(cardIds, config)
		}
		wg.Done()
	}()
	go func() {
		if !config.SkipBuylist {
			foundVendors = searchVendorsNG(cardIds, config)
		}
		wg.Done()
	}()

	wg.Wait()

	return
}

type SortingData struct {
	co          *mtgmatcher.CardObject
	releaseDate time.Time
	parentCode  string
}

func getSortingData(uuid string) (*SortingData, error) {
	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		return nil, err
	}
	set, err := mtgmatcher.GetSet(co.SetCode)
	if err != nil {
		return nil, err
	}
	releaseDate := set.ReleaseDate
	if co.OriginalReleaseDate != "" {
		releaseDate = co.OriginalReleaseDate
	}
	setDate, err := time.Parse("2006-01-02", releaseDate)
	if err != nil {
		return nil, err
	}
	return &SortingData{
		co:          co,
		releaseDate: setDate,
		parentCode:  set.ParentCode,
	}, nil
}

const charactersToStrip = "abcdefgsp" + mtgjson.SuffixSpecial + mtgjson.SuffixVariant

var reSort = regexp.MustCompile(`\d+`)

func sortByNumberAndFinish(cI, cJ *mtgmatcher.CardObject, strip bool) bool {
	numI := cI.Card.Number
	numJ := cJ.Card.Number
	if strip {
		numI = reSort.FindString(cI.Card.Number)
		numJ = reSort.FindString(cJ.Card.Number)
	}

	// If their number is the same, check for foiling status
	if numI == numJ {
		if len(cI.PromoTypes) > 0 && len(cJ.PromoTypes) > 0 && cI.PromoTypes[0] != cJ.PromoTypes[0] {
			return cI.PromoTypes[0] < cJ.PromoTypes[0]
		}
		if cI.Etched || cJ.Etched {
			if cI.Etched && !cJ.Etched {
				return false
			} else if !cI.Etched && cJ.Etched {
				return true
			}
		} else if cI.Foil || cJ.Foil {
			if cI.Foil && !cJ.Foil {
				return false
			} else if !cI.Foil && cJ.Foil {
				return true
			}
		}
	}

	// If both are foil or both are non-foil, check their number
	cInum, errI := strconv.Atoi(numI)
	cJnum, errJ := strconv.Atoi(numJ)
	if errI == nil && errJ == nil && cInum != cJnum {
		return cInum < cJnum
	}

	// If either one is not a number (due to extra letters) just
	// do a normal string comparison
	return cI.Card.Number < cJ.Card.Number
}

func sortSets(uuidI, uuidJ string) bool {
	sortingI, err := getSortingData(uuidI)
	if err != nil {
		return false
	}
	sortingJ, err := getSortingData(uuidJ)
	if err != nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	// If the two sets have the same release date, let's dig more
	if setDateI.Equal(setDateJ) {
		// If they are part of the same edition, check for their collector number
		// taking their foiling into consideration
		if cI.Edition == cJ.Edition {
			// Special case for sealed products
			if cI.Sealed && cJ.Sealed {
				return cI.Name < cJ.Name
			}

			return sortByNumberAndFinish(cI, cJ, true)
			// For the special case of set promos, always keeps them after
		} else if sortingI.parentCode == "" && sortingJ.parentCode != "" {
			return true
		} else if sortingJ.parentCode == "" && sortingI.parentCode != "" {
			return false
		} else {
			return cI.Edition < cJ.Edition
		}
	}

	return setDateI.After(setDateJ)
}

// Sort card by their names, trying to keep cards grouped by edition, following
// the same rules as sortSets
func sortSetsAlphabetical(uuidI, uuidJ string) bool {
	sortingI, err := getSortingData(uuidI)
	if err != nil {
		return false
	}
	sortingJ, err := getSortingData(uuidJ)
	if err != nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	if cI.Name == cJ.Name {
		if setDateI.Equal(setDateJ) {
			// We need not to strip to keep set ordered wrt Promos etc
			return sortByNumberAndFinish(cI, cJ, false)
		}

		return setDateI.After(setDateJ)
	}

	return cI.Name < cJ.Name
}

// Sort card by their names, keeping cards grouped by edition alphabetically
func sortSetsAlphabeticalSet(uuidI, uuidJ string) bool {
	sortingI, err := getSortingData(uuidI)
	if err != nil {
		return false
	}
	sortingJ, err := getSortingData(uuidJ)
	if err != nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	if setDateI.Equal(setDateJ) {
		return sortSetsAlphabetical(uuidI, uuidJ)
	}

	return cI.Edition < cJ.Edition
}

// Sort cards by their prices according to the passed in sellers,
// If same price is found, sort as normal
func sortSetsByRetail(uuidI, uuidJ string, retSellers []string) bool {
	var priceI, priceJ float64
	for _, retSeller := range retSellers {
		priceI = price4seller(uuidI, retSeller)
		if priceI != 0 {
			break
		}
	}
	for _, retSeller := range retSellers {
		priceJ = price4seller(uuidJ, retSeller)
		if priceJ != 0 {
			break
		}
	}

	if priceI == priceJ {
		return sortSets(uuidI, uuidJ)
	}

	return priceI > priceJ
}

// Sort cards by their prices according to the passed in vendors
// If same price is found, sort by the default retail price
func sortSetsByBuylist(uuidI, uuidJ string, blVendors []string) bool {
	var priceI, priceJ float64
	for _, blVendor := range blVendors {
		priceI = price4vendor(uuidI, blVendor)
		if priceI != 0 {
			break
		}
	}
	for _, blVendor := range blVendors {
		priceJ = price4vendor(uuidJ, blVendor)
		if priceJ != 0 {
			break
		}
	}

	if priceI == priceJ {
		return sortSetsByRetail(uuidI, uuidJ, defaultSellerPriorityOpt)
	}

	return priceI > priceJ
}
