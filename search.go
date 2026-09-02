package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BlueMonday/go-scryfall"

	"github.com/mtgban/go-mtgban/cardmarket"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/mtgban-website/internal/embed"
	"github.com/mtgban/mtgban-website/internal/suggest"
	"github.com/mtgban/mtgban-website/timeseries"
)

const (
	MaxSearchQueryLen = 1000
	MaxSearchResults  = 100
	TooLongMessage    = "Your query planeswalked away, try a shorter one"
	TooManyMessage    = "Too many results, try adjusting your filters"
	NoResultsMessage  = "No products matching your search could be found"
	NoPromosMessage   = "No products matching your search could be found — some promos may be hidden"
	NoCardsMessage    = "No products matching your search could be found"

	MaxSearchTotalResults = 10000
)

var (
	defaultSellerPriorityOpt = []string{"TCGMarket", "TCGLow", "TCGSealed"}
	defaultVendorPriorityOpt = []string{"CK", "SCG", "SS"}
)

type SearchEntry struct {
	ScraperName  string
	Shorthand    string
	Price        float64
	Credit       float64
	MarketCredit float64
	Ratio        float64
	Quantity     int
	URL          string
	NoQuantity   bool
	BundleIcon   string

	// QuantityPriority marks a store whose rows are read as a count of
	// copies wanted rather than as an offer, so the quantity is shown
	// where the price would be and the price is not ranked against the
	// others. The scraper declares it; nothing here names the store.
	QuantityPriority bool

	// Badge renders this entry as the official "Available at Amazon"
	// search-link badge rather than a normal store row. BundleIcon is a
	// generic per-store icon, so it cannot be used to single this out.
	Badge bool

	Country string

	Secondary float64

	// IsEV marks a row produced by the sealed expected-value collapse. The
	// EV/Median/StdDev columns only mean anything for those, so the header
	// naming them follows this rather than the mere presence of index rows.
	IsEV bool

	ExtraValues map[string]float64

	Locked bool
}

var AllConditions = []string{"INDEX", "NM", "SP", "MP", "HP", "PO"}

// searchSuggestions adapts a parsed search that found nothing into the
// suggest package's inputs.
func searchSuggestions(rawQuery string, config SearchConfig, sealed bool) (string, []suggest.AltSearch) {
	return suggest.Build(suggest.Params{
		RawQuery:       rawQuery,
		CleanQuery:     config.CleanQuery,
		SearchMode:     config.SearchMode,
		AppliedFilters: config.AppliedFilters,
		Sealed:         sealed,
	})
}

// searchFallback re-reads a search whose name matched nothing, in the order a
// searcher is likely to have meant it. "metal" names no card, but on the games
// that print treatments as promo types it names a finish, and a storefront
// lists the card under it. Failing that the word is read as a set: someone
// typing "shadows" wants what is in the sets called that.
//
// Every filter the query already carried is kept, so "s:OGN metal" still means
// that set; only the name is read a second way. A hashing search names its own
// cards and is left alone.
func searchFallback(config SearchConfig) []string {
	if config.CleanQuery == "" || config.SearchMode == "hashing" {
		return nil
	}

	query := config.CleanQuery
	config.CleanQuery = ""
	config.FullQuery = ""
	base := slices.Clone(config.CardFilters)

	if promoTypes := promoTypeMatches(query); len(promoTypes) > 0 {
		config.CardFilters = append(slices.Clone(base), FilterElem{
			Name:   "is",
			Values: promoTypes,
		})
		if keys, err := searchAndFilter(config); err == nil && len(keys) > 0 {
			return keys
		}
	}

	// A set the query already narrowed to is not up for reinterpretation:
	// "s:OGN shadows" asked about OGN, and answering with every set named
	// shadows would throw away what the searcher did say.
	if _, narrowed := editionSeedCodes(base); narrowed {
		return nil
	}

	if codes := setCodeMatches(query); len(codes) > 0 {
		config.CardFilters = append(slices.Clone(base), FilterElem{
			Name:   "edition",
			Values: codes,
		})
		if keys, err := searchAndFilter(config); err == nil && len(keys) > 0 {
			return keys
		}
	}

	return nil
}

// isValidChartID reports whether a chart= piece is a plausibly chartable id: a
// mtgmatcher id or a ban:/tcg:/scryfall:/mtgjson: prefixed id (bare numbers are
// TCGplayer ids). Full resolution happens at render time.
func isValidChartID(part string) bool {
	if _, err := mtgmatcher.GetUUID(part); err == nil {
		return true
	}
	switch prefix, _ := splitIDPrefix(part); prefix {
	case "ban", "tcg", "scryfall", "mtgjson":
		return true
	}
	_, err := strconv.Atoi(part)
	return err == nil
}

// magicFinishSearchID re-tags an mtgjson uuid with the finish of the variant it
// came from. The variants table stores the finish beside the base uuid, while
// mtgmatcher gives each finish its own id ("_f", "_e"), so handing the bare uuid
// back to the search always lands on the nonfoil printing. Falls back to the
// uuid when the finish has no id of its own.
func magicFinishSearchID(uuid string, foil, etched bool) string {
	if matched, err := mtgmatcher.MatchID(uuid, foil, etched); err == nil {
		return matched
	}
	return uuid
}

// noteChartIDsDropped tells the reader that part of the roster could not be
// matched to a printing, appending to whatever the page already said.
func noteChartIDsDropped(pageVars *PageVars, dropped, total int) {
	notice := fmt.Sprintf("%d of the %d charted cards could not be matched to a printing and were left out.", dropped, total)
	if dropped == 1 {
		notice = "One of the charted cards could not be matched to a printing and was left out."
	}
	if pageVars.InfoMessage == "" {
		pageVars.InfoMessage = notice
		return
	}
	pageVars.InfoMessage += " " + notice
}

// chartSearchID names the results-table row for a roster id. The resolved
// target already knows it - resolving is what reads the archive, and the chart
// needs that same answer - so the table and the chart cannot disagree about
// which printing a roster id means.
//
// A target is nil when nothing resolved, and on a deployment with no archive at
// all, where the matcher can still map a plain id. ok=false means the id is
// handed back as it came: the results table will find no row for it, so the
// card drops out of the page it was asked for. The caller says so rather than
// letting it vanish.
func chartSearchID(id string, target *chartTarget) (string, bool) {
	if target != nil {
		if target.SearchID != "" {
			return target.SearchID, true
		}
		// The resolver already tried every id space it knows and came back
		// without a row id, so there is no row. Asking the matcher again
		// from the raw string second-guesses that, and the raw string is
		// exactly what cannot be read twice: a ban_id and a TCGplayer
		// product id can be the same number, which is the trap
		// resolveChartTarget's precedence exists to avoid.
		return id, false
	}

	// Nothing resolved, so there is no archive to have resolved against -
	// a deployment without one, where the matcher still places a plain id.
	if _, err := mtgmatcher.GetUUID(id); err == nil {
		return id, true // already a matcher id (bare uuid / variant string)
	}
	prefix, val := splitIDPrefix(id)
	// ban: names our own surrogate. That integer means nothing to the
	// matcher's external map, where the same number belongs to a product.
	if prefix == "ban" {
		return id, false
	}

	// tcg:, scryfall:, mtgjson:, or a bare id mtgmatcher maps through its external
	// id table (a TCGplayer product id, a Scryfall id, or an mtgjson uuid).
	if matched, merr := mtgmatcher.MatchID(val); merr == nil {
		return matched, true
	}
	return id, false
}

// parseChartIDs splits a chart=... param (comma-separated UUIDs) into a
// validated, de-duplicated list. Pieces that don't resolve via mtgmatcher are
// dropped silently, mirroring how single-UUID chart= used to be handled.
//
// The roster is capped at the palette size: the multi-card chart can only
// render that many distinguishable lines, and it bounds the per-UUID DB
// fan-out (GetEarliestDate + timeseries fetch) triggered on this public
// handler by a crafted many-UUID chart= URL. truncated reports whether at
// least one otherwise-valid, distinct card was dropped for exceeding the cap,
// so the caller can tell the user instead of silently swallowing it.
func parseChartIDs(chartParam string) (ids []string, truncated bool) {
	if chartParam == "" {
		return nil, false
	}
	for _, part := range strings.Split(chartParam, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !isValidChartID(part) {
			continue
		}
		if slices.Contains(ids, part) {
			continue
		}
		if len(ids) >= len(multiCardPalette) {
			truncated = true
			break
		}
		ids = append(ids, part)
	}
	return ids, truncated
}

func Search(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Search", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	// Admins get a per-result "Fix" toggle that surfaces a Fix link on every
	// store, deep-linking into the overrides builder.
	canAdmin, _ := strconv.ParseBool(GetParamFromSig(sig, "Admin"))
	pageVars.CanFixSearch = canAdmin || (DevMode && !SigCheck)

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
	isSetsPage := r.URL.Path == "/sets"
	if query == "" {
		pageVars.PromoTags = mtgmatcher.AllPromoTypes()
		if !pageVars.IsSealed && !isSetsPage {
			pageVars.SetKeyrunes = getSetKeyrunes()
		}
	}

	pageVars.HasAvailable = len(mtgmatcher.GetSealedUUIDs()) > 0

	// Image corpus picker: only populate for entitled users.
	if _, ok := offlineModeAllowed(r); ok {
		pageVars.OfflineModeAllowed = true
		editions := GetEditions()
		pageVars.EditionsCategories = editions.AllEditionsCategoriesSorted
		pageVars.EditionsByCategory = editions.AllEditionsByCategory
		pageVars.PickerID = "offline-img-editions-picker"
	}

	// Populate all seller/vendor keys (for settings drawer and options page)
	for _, seller := range GetSellers() {
		pageVars.SellerKeys = append(pageVars.SellerKeys, seller.Info().Shorthand)
	}
	for _, vendor := range GetVendors() {
		pageVars.VendorKeys = append(pageVars.VendorKeys, vendor.Info().Shorthand)
	}
	pageVars.SellerKeys = sortKeysByScraperName(pageVars.SellerKeys)
	pageVars.VendorKeys = sortKeysByScraperName(pageVars.VendorKeys)

	page := r.FormValue("page")
	if page == "options" {
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
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
	// For open mode (Any), disable history charts
	if sig == "" && SigCheck {
		pageVars.DisableChart = true
	}

	// Load sort option from preferences, merge the alpha query parameter if needed
	pageVars.SearchSort = readCookie(r, "SearchDefaultSort")
	defaultSortOpt := r.FormValue("sort")
	if defaultSortOpt != "" {
		preferredSort := pageVars.SearchSort
		pageVars.SearchSort = defaultSortOpt
		// If a user prefers alpha sort grouped by set preserve that option
		if preferredSort == "hybrid" && defaultSortOpt == "alpha" {
			pageVars.SearchSort = "hybrid"
		}
	}

	pageVars.SearchBest = (readCookie(r, "SearchListingPriority") != "stores")
	pageVars.DefaultTab = readCookie(r, "SearchDefaultTab")
	pageVars.DefaultView = readCookie(r, "SearchDefaultView")
	pageVars.MobileSearchLayout = readCookie(r, "MobileSearchLayout")

	// Load whether a user can download CSV and validate the query parameter
	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	pageVars.CanDownloadCSV = canDownloadCSV

	if len(query) > MaxSearchQueryLen {
		pageVars.ErrorMessage = TooLongMessage

		render(w, "search.html", pageVars)
		return
	}

	chartParam := r.FormValue("chart")
	pageVars.ModalMode = r.FormValue("modal") == "1"

	// The front-end enforces the same cap when batching cards, so let the JS
	// disable the affordance at the boundary instead of dropping silently.
	pageVars.MaxChartCards = len(multiCardPalette)

	chartIDs, chartTruncated := parseChartIDs(chartParam)

	chartID := ""
	// Roster id -> resolved search id, computed once per request: a ban:<id>
	// resolution costs a DB round-trip and each id is consulted three times
	// (results query, display query, metadata aliasing).
	chartSearchIDs := map[string]string{}

	// Roster id -> chart target, resolved once per request. The results table
	// and the chart both need this, and it is the archive round-trip that makes
	// it worth doing once: the page used to ask for the same card twice, and a
	// roster did so per card. Owned by this request alone, so a plain map with
	// no locking - a nil entry is a resolution that already failed and is not
	// retried.
	chartTargets := map[string]*chartTarget{}
	chartTargetFor := func(id string) *chartTarget {
		if target, asked := chartTargets[id]; asked {
			return target
		}
		target, err := resolveChartTarget(r.Context(), id)
		if err != nil {
			target = nil
		}
		chartTargets[id] = target
		return target
	}
	if len(chartIDs) > 0 && !pageVars.DisableChart {
		// A crafted or over-long chart= URL that names more cards than the chart
		// can render lands here; say so rather than silently dropping the tail.
		if chartTruncated {
			pageVars.InfoMessage = fmt.Sprintf("Charts show up to %d cards; the extras were left off.", len(multiCardPalette))
		}

		// Always expose the chart roster so the "add to chart" affordance on
		// result rows can target it even when we're rendering a regular search
		// (e.g. the user typed a query while on a chart page).
		pageVars.ChartIDs = chartIDs
		pageVars.ChartIDsCSV = strings.Join(chartIDs, ",")

		// Only enter chart-render mode when chart= is alone (no q=). With both
		// present the user is searching for cards to add to the chart, so we
		// keep the chart roster as context but render the search results page.
		// In modal mode the iframe is the add-to-chart picker, so never render
		// a chart inside it even when no query is set yet.
		if query == "" && !pageVars.ModalMode {
			chartID = chartIDs[0]
			// Drive the results table off the same trimmed/validated IDs the
			// chart plots (not the raw chartParam), so a URL like
			// ?chart=uuidA,%20uuidB doesn't leave card B off the results/remove
			// controls just because fixupIDs won't trim the leading space.
			searchIDs := make([]string, len(chartIDs))
			var unresolved int
			for i, id := range chartIDs {
				searchID, ok := chartSearchID(id, chartTargetFor(id))
				if !ok {
					unresolved++
				}
				searchIDs[i] = searchID
				chartSearchIDs[id] = searchIDs[i]
			}
			// An id that resolved to nothing matches no row, so the card is
			// simply absent from the table below the chart. Say which way it
			// went: a roster the user built by hand, or a link they were sent,
			// otherwise comes back quietly short.
			if unresolved > 0 {
				noteChartIDsDropped(&pageVars, unresolved, len(chartIDs))
			}
			query = strings.Join(searchIDs, ",")
			pageVars.Title = strings.Replace(pageVars.Title, "Search", "Chart", 1)
		}
	} else {
		// Stay on the same probable query page
		if query == "" {
			query = chartParam
		}
		chartIDs = nil
	}

	// If query is empty there is nothing to do
	if query == "" {
		editions := GetEditions()
		// Hijack sealed list
		if pageVars.IsSealed {
			pageVars.Title = strings.Replace(pageVars.Title, "Search", "Sealed Search", 1)

			pageVars.EditionSort = editions.SealedEditionsSorted
			pageVars.EditionList = editions.SealedEditionsList
			render(w, "search.html", pageVars)
			return
		} else if isSetsPage {
			pageVars.Title = strings.Replace(pageVars.Title, "Search", "Editions", 1)

			pageVars.TotalSets = editions.TotalSets
			pageVars.TotalCards = editions.TotalCards
			pageVars.TotalUnique = editions.TotalUnique

			sortOpt := r.FormValue("sort")
			sortedKeys := editions.TreeEditionsKeys

			if sortOpt == "name" {
				namedSort := make([]string, len(editions.TreeEditionsKeys))
				copy(namedSort, editions.TreeEditionsKeys)
				sort.SliceStable(namedSort, func(i, j int) bool {
					return strings.ToLower(editions.TreeEditionsMap[namedSort[i]][0].Name) < strings.ToLower(editions.TreeEditionsMap[namedSort[j]][0].Name)
				})
				sortedKeys = namedSort
			} else if sortOpt == "size" {
				sizeSort := make([]string, len(editions.TreeEditionsKeys))
				copy(sizeSort, editions.TreeEditionsKeys)
				sort.SliceStable(sizeSort, func(i, j int) bool {
					if editions.TreeEditionsMap[sizeSort[i]][0].Size == editions.TreeEditionsMap[sizeSort[j]][0].Size {
						return strings.ToLower(editions.TreeEditionsMap[sizeSort[i]][0].Name) < strings.ToLower(editions.TreeEditionsMap[sizeSort[j]][0].Name)
					}
					return editions.TreeEditionsMap[sizeSort[i]][0].Size > editions.TreeEditionsMap[sizeSort[j]][0].Size
				})
				sortedKeys = sizeSort
			}

			pageVars.FlatEditions = flattenEditions(sortedKeys, editions.TreeEditionsMap)
			pageVars.SortOption = sortOpt

			render(w, "sets.html", pageVars)
			return
		}

		render(w, "search.html", pageVars)
		return
	}

	start := time.Now()

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	hidePromos := slices.Contains(miscSearchOpts, "hidePromos") || slices.Contains(miscSearchOpts, "hidePrelPack")
	if oembed {
		miscSearchOpts = append(miscSearchOpts, "oembed")
	}
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")

	// Keep track of what was searched
	pageVars.SearchQuery = query
	pageVars.Embed.PageURL = ServerURL + r.URL.String()
	pageVars.Embed.OEmbedURL = ServerURL + "/search/oembed?format=json&url=" + url.QueryEscape(ServerURL+"/search?q="+query)
	pageVars.CondKeys = AllConditions
	pageVars.Metadata = map[string]GenericCard{}
	pageVars.ShowUpsell = !slices.Contains(miscSearchOpts, "noUpsell")

	config := parseSearchOptionsNG(query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	if pageVars.IsSealed {
		config.SearchMode = "sealed"
		pageVars.Title = strings.Replace(pageVars.Title, "Search", "Sealed Search", 1)
	}

	if config.SortMode != "" {
		pageVars.SearchSort = config.SortMode
		pageVars.NoSort = true
	}

	// Perform search
	allKeys, err := searchAndFilter(config)
	if err != nil {
		// No card carries the name, so read it another way before giving up.
		// Only here: further down the results are empty because the cards that
		// were found carry no listing, which is a fact about stock rather than
		// an invitation to answer a different question.
		allKeys = searchFallback(config)
		if len(allKeys) == 0 {
			pageVars.InfoMessage = NoCardsMessage
			pageVars.PopularSearches = getPopularSearches()
			pageVars.CleanSearchQuery = config.CleanQuery
			pageVars.DidYouMean, pageVars.AltSearches = searchSuggestions(query, config, pageVars.IsSealed)
			render(w, "search.html", pageVars)
			return
		}
	}

	// Limit results to avoid hogging the website with large queries
	if len(allKeys) > MaxSearchTotalResults {
		pageVars.TotalCards = len(allKeys)
		pageVars.InfoMessage = TooManyMessage
		allKeys = allKeys[:MaxSearchTotalResults]
	}

	foundSellers, foundVendors := searchParallelNG(allKeys, config)

	// Append the virtual custom buylist when enabled in the upload settings
	canUploadCustom, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadCustom"))
	canUploadCustom = canUploadCustom || (DevMode && !SigCheck)
	if canUploadCustom && !config.SkipBuylist {
		searchCustomBuylist(r, allKeys, foundVendors)
	}

	// Filter away any empty result
	allKeys = PostSearchFilter(config, allKeys, foundSellers, foundVendors)

	// Early exit if there no matches are found
	if len(allKeys) == 0 {
		pageVars.InfoMessage = NoResultsMessage
		if hidePromos {
			pageVars.InfoMessage = NoPromosMessage
		}
		pageVars.PopularSearches = getPopularSearches()
		pageVars.CleanSearchQuery = config.CleanQuery
		pageVars.DidYouMean, pageVars.AltSearches = searchSuggestions(query, config, pageVars.IsSealed)
		render(w, "search.html", pageVars)
		return
	}

	// Only used in hashing searches, fill in data with what is available
	if config.FullQuery != "" {
		pageVars.SearchQuery = config.FullQuery
	}

	// Allow displaying the "search all" link only when something
	// was searched and no options were specified for it
	canShowAll := !pageVars.IsSealed && config.CleanQuery != "" && (len(config.CardFilters) != 0 || len(config.UUIDs) != 0)
	pageVars.CanShowAll = canShowAll
	pageVars.CleanSearchQuery = config.CleanQuery

	// CardHashes carries the full result list (with the per-copy repeats that
	// decklist/hashing searches produce) so transferring to the Uploader keeps
	// the quantities. Rendering shows each unique card once, so dedupe the keys
	// used for display — otherwise a 4-of card is drawn (and linked) 4 times.
	// Only multi-result hashing searches can repeat a key (hashing also serves
	// single-uuid lookups), so skip the work for everything else.
	pageVars.CardHashes = allKeys
	if config.SearchMode == "hashing" && len(allKeys) > 1 {
		if uniqueKeys := dedupeKeys(allKeys); len(uniqueKeys) < len(allKeys) {
			if pageVars.TotalCards == 0 {
				pageVars.TotalCards = len(allKeys)
			}
			// Record how many copies each card had so the deduped block can show it.
			quantities := make(map[string]int, len(uniqueKeys))
			for _, k := range allKeys {
				quantities[k]++
			}
			pageVars.CardQuantities = quantities
			allKeys = uniqueKeys
		}
	}

	// Save stats
	pageVars.TotalUnique = len(allKeys)

	if pageVars.IsMobile && !pageVars.IsSealed {
		pageVars.EditionFilterList = editionsForSearch(allKeys)
	}

	// Sort sets as requested, default to chronological
	switch pageVars.SearchSort {
	case "alpha":
		sortData := resolveSortingData(allKeys)
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSetsAlphabetical(sortData[allKeys[i]], sortData[allKeys[j]], preferFlavor)
		})
	case "hybrid":
		sortData := resolveSortingData(allKeys)
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSetsAlphabeticalSet(sortData[allKeys[i]], sortData[allKeys[j]], preferFlavor)
		})
	case "number":
		sortData := resolveSortingData(allKeys)
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpNumberAndFinish(sortData[allKeys[i]], sortData[allKeys[j]], false)
		})
	case "retail":
		retSellers := defaultSellerPriorityOpt
		retSeller := readCookie(r, "SearchSellersPriority")
		if retSeller != "" {
			retSellers = append([]string{retSeller}, defaultSellerPriorityOpt...)
		}

		sortData := resolveSortingData(allKeys)
		prices := resolveBestPrices(allKeys, retSellers, price4seller)
		sort.Slice(allKeys, func(i, j int) bool {
			priceI, priceJ := prices[allKeys[i]], prices[allKeys[j]]
			if priceI == priceJ {
				return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
			}
			return priceI > priceJ
		})
	case "buylist":
		blVendors := defaultVendorPriorityOpt
		blVendor := readCookie(r, "SearchVendorsPriority")
		if blVendor != "" {
			blVendors = append([]string{blVendor}, defaultVendorPriorityOpt...)
		}

		sortData := resolveSortingData(allKeys)
		buyPrices := resolveBestPrices(allKeys, blVendors, price4vendor)
		retPrices := resolveBestPrices(allKeys, defaultSellerPriorityOpt, price4seller)
		sort.Slice(allKeys, func(i, j int) bool {
			priceI, priceJ := buyPrices[allKeys[i]], buyPrices[allKeys[j]]
			if priceI != priceJ {
				return priceI > priceJ
			}
			priceI, priceJ = retPrices[allKeys[i]], retPrices[allKeys[j]]
			if priceI != priceJ {
				return priceI > priceJ
			}
			return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
		})
	default:
		sortData := resolveSortingData(allKeys)
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
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
	for _, cardID := range allKeys {
		_, found := pageVars.Metadata[cardID]
		if found {
			continue
		}
		card := uuid2card(cardID, false, true, preferFlavor)
		// Search results chart cards, so upgrade the chart handle to the cached
		// ban:<id> here rather than inside uuid2card, which also feeds pages
		// that never chart.
		card.ChartID = chartIDForCard(cardID)
		pageVars.Metadata[cardID] = card
	}

	// Optionally sort according to price
	if pageVars.SearchBest || oembed {
		blSortPref := readCookie(r, "SearchListingPriority")

		for _, cardID := range allKeys {
			// This skips INDEX and PO conditions
			for _, cond := range mtgban.DefaultGradeTags {
				_, found := foundSellers[cardID][cond]
				if found {
					sort.Slice(foundSellers[cardID][cond], func(i, j int) bool {
						return foundSellers[cardID][cond][i].Price < foundSellers[cardID][cond][j].Price
					})
				}
				_, found = foundVendors[cardID][cond]
				if found {
					switch blSortPref {
					default:
						sort.Slice(foundVendors[cardID][cond], func(i, j int) bool {
							if foundVendors[cardID][cond][i].Price == foundVendors[cardID][cond][j].Price {
								if foundVendors[cardID][cond][i].Credit == foundVendors[cardID][cond][j].Credit {
									return foundVendors[cardID][cond][i].MarketCredit > foundVendors[cardID][cond][j].MarketCredit
								}
								return foundVendors[cardID][cond][i].Credit > foundVendors[cardID][cond][j].Credit
							}
							return foundVendors[cardID][cond][i].Price > foundVendors[cardID][cond][j].Price
						})
					case "credit":
						sort.Slice(foundVendors[cardID][cond], func(i, j int) bool {
							if foundVendors[cardID][cond][i].Credit == foundVendors[cardID][cond][j].Credit {
								return foundVendors[cardID][cond][i].MarketCredit > foundVendors[cardID][cond][j].MarketCredit
							}
							return foundVendors[cardID][cond][i].Credit > foundVendors[cardID][cond][j].Credit
						})
					case "market":
						sort.Slice(foundVendors[cardID][cond], func(i, j int) bool {
							return foundVendors[cardID][cond][i].MarketCredit > foundVendors[cardID][cond][j].MarketCredit
						})
					}
				}
			}
		}
	}

	preview := embedService.Generate(allKeys, ProcessEmbedSearchResultsSellers(foundSellers, true))
	if oembed {
		if len(allKeys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`Not Found`))
			return
		}

		payload, err := json.Marshal(preview)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`Internal Server Error`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
		return
	}
	pageVars.Embed.Title = preview.Title
	pageVars.Embed.Contents = preview.HTML
	pageVars.Embed.Description = preview.HTML
	if len(allKeys) > 0 {
		pageVars.Embed.ImageURL = pageVars.Metadata[allKeys[0]].ImageURL
		pageVars.Embed.ImageCropURL = pageVars.Embed.ImageURL

		co, err := mtgmatcher.GetUUID(allKeys[0])
		if err == nil && len(co.Printings) > 0 {
			pageVars.Embed.Description = fmt.Sprintf("Printed in %s.", embed.PrintingsLine(co.Printings))
			imgCrop := co.Images["crop"]
			if imgCrop != "" {
				pageVars.Embed.ImageCropURL = imgCrop
			}
		}

		pageVars.Embed.RetailPrice = price4seller(allKeys[0], "TCGMarket")
		pageVars.Embed.BuylistPrice = price4seller(allKeys[0], "CK")
	}

	// When the user asked to drop index data (skip:index), don't synthesize the
	// no-price TCGplayer/CardMarket fallback links below.
	skipIndex := false
	for _, f := range config.StoreFilters {
		if f.Name == "index" && !f.Negate {
			skipIndex = true
			break
		}
	}

	// Rebuild each card's INDEX rows. collapseIndex/collapseSealedEV scan the
	// array themselves, so there's no per-entry dispatch here — just collapse
	// each known source directly and pass the rest through, then sort the
	// resulting reference rows alphabetically by store name.
	for _, cardID := range allKeys {
		indexArray := foundSellers[cardID]["INDEX"]
		evShorts := Config.ScraperConfig.Config["sealed_ev"]["retail"]

		tcgRow, hasTCG := collapseIndex(indexArray, "TCGLow", "TCGMarket", "", "", "TCG (Low / Market)")
		mkmRow, hasMKM := collapseIndex(indexArray, "MKMLow", "MKMTrend", "Cardmarket Low", "Cardmarket Trend", "CM (Low / Trend)")
		evRows, hasEV := collapseSealedEV(indexArray, evShorts)

		var tmp []SearchEntry
		if hasTCG {
			tmp = append(tmp, tcgRow)
		}
		if hasMKM {
			tmp = append(tmp, mkmRow)
		}
		tmp = append(tmp, evRows...)

		// Pass through everything the collapsers didn't consume.
		consumed := append([]string{"TCGLow", "TCGMarket", "MKMLow", "MKMTrend"}, evShorts...)
		tmp = append(tmp, passthroughIndex(indexArray, consumed)...)

		if hasEV && getTCGSimulationIQR(cardID) > IQRThreshold {
			pageVars.InfoMessage = "CAUTION - This search includes products with a high IQR, please check the FAQs to understand how it may impact the computed values"
		}

		// If no TCG reference was present, we manually add one to get the link
		if !hasTCG && !pageVars.Metadata[cardID].Sealed && !skipIndex {
			var link string
			if pageVars.Metadata[cardID].TCGId == "" {
				link = "https://www.tcgplayer.com/search/all/product?q=" + url.QueryEscape(pageVars.Metadata[cardID].Name) + "&utm_medium=" + Config.Affiliate["TCG"] + "&utm_source=" + Config.Affiliate["TCG"]
			} else {
				tcgID, _ := strconv.Atoi(pageVars.Metadata[cardID].TCGId)

				link = tcgplayer.GenerateProductURL(tcgID, "", Config.Affiliate["TCG"], "", "", false)
			}
			tmp = append(tmp, SearchEntry{
				ScraperName: "TCGplayer",
				URL:         link,
				NoQuantity:  true,
			})
		}

		// Same for CM
		if !hasMKM && !pageVars.Metadata[cardID].Sealed && !skipIndex {
			co, err := mtgmatcher.GetUUID(cardID)
			if err == nil {
				var link string

				game := cardmarket.GameFromName(Config.Game)
				id, err := strconv.Atoi(co.Identifiers["mcmId"])
				if err != nil || id == 0 {
					// Cardmarket names the game in every product path, so the
					// name-only fallback has to carry it too.
					link = cardmarket.SearchURL(pageVars.Metadata[cardID].Name, game, Config.Affiliate["MKM"])
				} else {
					link = cardmarket.BuildURL(id, game, Config.Affiliate["MKM"], co.Foil || co.Etched)
				}
				tmp = append(tmp, SearchEntry{
					ScraperName: "CardMarket",
					URL:         link,
					NoQuantity:  true,
				})
			}
		}

		// Show the index reference rows in alphabetical order by store name.
		sort.SliceStable(tmp, func(i, j int) bool {
			return strings.ToLower(tmp[i].ScraperName) < strings.ToLower(tmp[j].ScraperName)
		})

		// Amazon search-by-name link (no price or condition); shown only on
		// sealed products, where marketplace availability is most relevant —
		// singles link to the dedicated card stores instead.
		if !skipIndex && pageVars.Metadata[cardID].Sealed {
			tmp = append([]SearchEntry{{
				ScraperName: "Search on AMAZON",
				URL:         "https://www.amazon.com/s?k=" + url.QueryEscape(pageVars.Metadata[cardID].Name) + "&tag=" + Config.Affiliate["AMZN"],
				BundleIcon:  "/img/misc/available-at-amazon-light.png",
				Badge:       true,
				NoQuantity:  true,
			}}, tmp...)
		}

		// In case there are no results at all
		if foundSellers[cardID] == nil {
			foundSellers[cardID] = map[string][]SearchEntry{}
		}
		foundSellers[cardID]["INDEX"] = tmp

		if sig == "" && SigCheck {
			for j, foundSet := range []map[string]map[string][]SearchEntry{foundSellers, foundVendors} {
				for cond := range foundSet[cardID] {
					// Index/reference prices stay visible to everyone.
					if cond == "INDEX" {
						continue
					}
					entries := foundSet[cardID][cond]
					for i := range entries {
						if j == 0 && !slices.Contains(Config.AffiliatesList, entries[i].Shorthand) {
							entries[i].Locked = true
						} else if j == 1 && !slices.Contains(Config.AffiliatesBuylistList, entries[i].Shorthand) {
							entries[i].Locked = true
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
	if chartID != "" {
		isMultiChart := len(chartIDs) > 1

		chartEditions := GetEditions()
		pageVars.EditionSort = chartEditions.SealedEditionsSorted
		pageVars.EditionList = chartEditions.SealedEditionsList

		// Rebuild a display query from the (first) chart card. Use the resolved
		// mtgmatcher id (a ban:<id> doesn't parse as a query), so SearchQuery is
		// non-empty and the template renders the results+chart layout rather than
		// the empty-query editions browse.
		cfg := parseSearchOptionsNG(chartSearchIDs[chartID], nil, nil, nil)
		pageVars.SearchQuery = cfg.FullQuery

		// Retrieve data
		pageVars.ChartID = chartID
		pageVars.IsMultiChart = isMultiChart

		// The template keys card metadata off ChartID and the roster ids, but the
		// results Metadata map is keyed by the resolved mtgmatcher id. Alias each
		// ban:<id> roster entry to its resolved card so those lookups resolve.
		for _, id := range chartIDs {
			sid := chartSearchIDs[id]
			if sid == "" || sid == id {
				continue
			}
			if card, ok := pageVars.Metadata[sid]; ok {
				pageVars.Metadata[id] = card
			}
		}

		if PricesArchiveDB == nil {
			pageVars.InfoMessage = "No chart data available"
		} else if Config.TimeseriesConfig.LongFormReads {
			lb := chartLookback(sig)
			pageVars.MaxLookbackDays = lb.Days()

			// Generic path: resolve every roster id to a target and chart it by
			// whatever providers have data — one path for every game, keyed on the
			// cached ban_id. The ?chart= url keeps the mtgmatcher id (the search
			// UI's identity for favorites/roster/legend); the ban_id is internal.
			var earliest time.Time
			var ids, names []string
			var series []map[string]timeseries.ProviderPrices
			for _, id := range chartIDs {
				target := chartTargetFor(id)
				if target == nil {
					continue
				}
				// Read each card once and take the axis from what came back: a
				// roster used to cost two archive round-trips per card, and
				// against a hundred-partition prices table a round-trip is
				// mostly planning.
				results := fetchChartPrices(r.Context(), target, lb)
				ids = append(ids, id)
				names = append(names, target.Name)
				series = append(series, results)
				if e := earliestChartedDate(results, lb); !e.IsZero() && (earliest.IsZero() || e.Before(earliest)) {
					earliest = e
				}
			}
			if len(series) == 0 || earliest.IsZero() {
				pageVars.InfoMessage = "No chart data available"
			} else {
				pageVars.AxisLabels = getDateAxisValues(earliest)
				cards := make([]multiCardInput, len(series))
				for i, results := range series {
					cards[i] = multiCardInput{
						CardID:   ids[i],
						Name:     names[i],
						Datasets: chartDatasetsFrom(results, pageVars.AxisLabels),
					}
				}
				if isMultiChart {
					datasets, refs := mergeMultiCardDatasets(cards)
					pageVars.Datasets = datasets
					pageVars.ChartReferences = refs
					pageVars.Checkpoints = multiCardCheckpoints(names, earliest)
				} else {
					pageVars.Datasets = cards[0].Datasets
					pageVars.Checkpoints = relevantCheckpoints(cards[0].Name, earliest)
				}
				if len(pageVars.Datasets) == 0 {
					pageVars.InfoMessage = "No chart data available"
				}
			}
		} else if !isMultiChart {
			co, err := mtgmatcher.GetUUID(chartID)
			if err != nil {
				fmt.Println("Search: Failed to GetUUID: %w", err)
				return
			}
			lb := chartLookback(sig)
			pageVars.MaxLookbackDays = lb.Days()

			earliest, _ := earliestChartDate(r.Context(), co.UUID, co.Foil, co.Etched, lb)

			pageVars.AxisLabels = getDateAxisValues(earliest)
			pageVars.Datasets = getDatasets(r.Context(), chartID, co.Sealed, pageVars.AxisLabels, lb)
			pageVars.Checkpoints = relevantCheckpoints(co.Name, earliest)
			if len(pageVars.Datasets) == 0 {
				pageVars.InfoMessage = "No chart data available"
			}
		} else {
			lb := chartLookback(sig)
			pageVars.MaxLookbackDays = lb.Days()

			// Union of date ranges: pick the oldest earliest so every card's
			// available history shows up, with NaN gaps for dates predating it.
			var earliest time.Time
			var chartNames []string
			for _, id := range chartIDs {
				co, gerr := mtgmatcher.GetUUID(id)
				if gerr != nil {
					continue
				}
				chartNames = append(chartNames, co.Name)
				e, _ := earliestChartDate(r.Context(), co.UUID, co.Foil, co.Etched, lb)
				if e.IsZero() {
					continue
				}
				if earliest.IsZero() || e.Before(earliest) {
					earliest = e
				}
			}
			if earliest.IsZero() {
				pageVars.InfoMessage = "No chart data available"
			} else {
				pageVars.AxisLabels = getDateAxisValues(earliest)
				datasets, refs := getDatasetsForMulti(r.Context(), chartIDs, pageVars.AxisLabels, lb)
				pageVars.Datasets = datasets
				pageVars.ChartReferences = refs
				// Shared timeline across the roster: the union of every card's
				// releases, reprints and bans/unbans, deduped onto one axis.
				pageVars.Checkpoints = multiCardCheckpoints(chartNames, earliest)
				if len(datasets) == 0 {
					pageVars.InfoMessage = "No chart data available"
				}
			}
		}

		// Sidebar foil/etched switch and Stocks link are inherently per-card,
		// and sealed products have no foil/etched variants, so leave them empty
		// and let the sidebar's self-checks hide them. The switches key off the
		// resolved mtgmatcher id, since a ban:<id> roster entry means nothing to
		// the matcher.
		if !isMultiChart {
			searchID := chartSearchIDs[chartID]
			co, gerr := mtgmatcher.GetUUID(searchID)
			if gerr == nil && !co.Sealed {
				altID, err := mtgmatcher.Match(&mtgmatcher.InputCard{
					ID:   searchID,
					Foil: !co.Foil,
				})
				if err == nil && altID != searchID {
					pageVars.Alternative = altID
				}

				altID, err = mtgmatcher.Match(&mtgmatcher.InputCard{
					ID:        searchID,
					Variation: "Etched",
				})
				if err == nil && altID != searchID {
					pageVars.AltEtchedID = altID
				}

				pageVars.StocksURL = pageVars.Metadata[chartID].StocksURL
			}
		}
	}

	var source string
	notifyTitle := "search"
	utm := r.FormValue("utm_source")
	if utm == "banbot" {
		id := r.FormValue("utm_affiliate")
		source = fmt.Sprintf("banbot (%s)", id)
	} else if utm == "autocard" {
		source = "autocard anywhere"
	} else if chartID != "" {
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
		user = fmt.Sprintf("anonymous (%s / %s)", r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
	}
	msg := fmt.Sprintf("[%s] from %s by %s (took %v)", query, source, user, time.Since(start))
	UserNotify(notifyTitle, msg)
	LogPages["Search"].Println(msg)

	if DevMode {
		start = time.Now()
	}
	render(w, "search.html", pageVars)
	if DevMode {
		log.Println("render took", time.Since(start))
	}
}

// collapseIndex folds a paired low/market reference (e.g. TCGLow + TCGMarket)
// from a card's INDEX entries into a single row: the low price as the primary
// and the market price as the secondary, under the merged label. The first of
// each shorthand is used (so repeats are deduped), and the pair merges
// regardless of the order the two entries appear in. When only one side is
// present it's returned on its own, renamed to its solo label (an empty solo
// label keeps the scraper's own name). Returns false when neither is found.
func collapseIndex(entries []SearchEntry, lowShort, marketShort, lowSolo, marketSolo, merged string) (SearchEntry, bool) {
	var low, market *SearchEntry
	for i := range entries {
		switch entries[i].Shorthand {
		case lowShort:
			if low == nil {
				low = &entries[i]
			}
		case marketShort:
			if market == nil {
				market = &entries[i]
			}
		}
	}

	switch {
	case low != nil && market != nil:
		row := *low
		row.Secondary = market.Price
		row.ScraperName = merged
		return row, true
	case low != nil:
		row := *low
		if lowSolo != "" {
			row.ScraperName = lowSolo
		}
		return row, true
	case market != nil:
		row := *market
		if marketSolo != "" {
			row.ScraperName = marketSolo
		}
		return row, true
	default:
		return SearchEntry{}, false
	}
}

// collapseSealedEV folds the sealed expected-value rows from a card's INDEX
// entries into one row per product: a base entry and its " Sim" sibling, paired
// by the product id in the scraper name (its second word), become base price
// primary and simulated price secondary. evShorts is the set of sealed-EV
// scraper shorthands. Returns the collapsed rows and whether any EV entry was
// present (so the caller can flag a high-IQR caution).
func collapseSealedEV(entries []SearchEntry, evShorts []string) (rows []SearchEntry, seen bool) {
	pos := map[string]int{}
	for i := range entries {
		if !slices.Contains(evShorts, entries[i].Shorthand) {
			continue
		}
		seen = true

		// The product id is the second word of the scraper name.
		fields := strings.Fields(entries[i].ScraperName)
		if len(fields) < 2 {
			continue
		}
		id := fields[1]

		idx, found := pos[id]
		if !found {
			rows = append(rows, entries[i])
			idx = len(rows) - 1
			pos[id] = idx
			rows[idx].IsEV = true
		}

		if strings.Contains(entries[i].ScraperName, " Sim") {
			rows[idx].Secondary = entries[i].Price
			rows[idx].ExtraValues = entries[i].ExtraValues
		} else {
			rows[idx].Price = entries[i].Price
		}
	}
	return rows, seen
}

// passthroughIndex returns the INDEX entries whose shorthand isn't in consumed
// — i.e. everything not already folded into a collapsed row — preserving their
// original order.
func passthroughIndex(entries []SearchEntry, consumed []string) []SearchEntry {
	var out []SearchEntry
	for i := range entries {
		if slices.Contains(consumed, entries[i].Shorthand) {
			continue
		}
		out = append(out, entries[i])
	}
	return out
}

func searchSellersNG(cardIDs []string, config SearchConfig) (foundSellers map[string]map[string][]SearchEntry) {
	// Allocate memory
	foundSellers = map[string]map[string][]SearchEntry{}

	// Decklist/hashing searches repeat a key once per copy; the output is
	// keyed by the unique card, so walking a repeated key could only append
	// the same rows once more
	cardIDs = dedupeKeys(cardIDs)

	storeFilters := config.StoreFilters
	priceFilters := config.PriceFilters
	entryFilters := config.EntryFilters

	// Search sellers
	for _, seller := range GetSellers() {
		if shouldSkipStoreNG(seller, storeFilters) {
			continue
		}

		// Get inventory
		inventory := seller.Inventory()

		// Fetch the seller info (a struct copy) and its display name once
		// per store instead of once per entry
		info := seller.Info()
		name := scraperName(info.Shorthand)

		for _, cardID := range cardIDs {
			entries, found := inventory[cardID]
			if !found {
				continue
			}

			// Loop thorugh available conditions
			for _, entry := range entries {
				// Skip cards that have not the desired condition
				if !info.MetadataOnly && shouldSkipEntryNG(entry, entryFilters) {
					continue
				}

				// Skip cards that don't match desired pricing
				if shouldSkipPriceNG(cardID, entry, priceFilters, info.Shorthand) {
					continue
				}

				// Check if card already has any entry
				_, found := foundSellers[cardID]
				if !found {
					foundSellers[cardID] = map[string][]SearchEntry{}
				}

				// Set conditions - handle the special TCG one that appears
				// at the top of the results
				conditions := entry.Conditions
				if info.MetadataOnly {
					conditions = "INDEX"
				}

				icon := Config.ScraperConfig.Icons[info.Shorthand]

				// Prepare all the deets
				res := SearchEntry{
					ScraperName:      name,
					Shorthand:        info.Shorthand,
					Price:            entry.Price,
					Quantity:         entry.Quantity,
					URL:              entry.URL,
					NoQuantity:       info.NoQuantityInventory || info.MetadataOnly,
					BundleIcon:       icon,
					QuantityPriority: info.QuantityPriority,
					Country:          Country2flag[info.CountryFlag],
					ExtraValues:      entry.ExtraValues,
				}
				if info.CreditMultiplier > 0 {
					res.Credit = entry.Price / info.CreditMultiplier
				}

				// Touchdown
				foundSellers[cardID][conditions] = append(foundSellers[cardID][conditions], res)
			}
		}
	}

	return
}

func searchVendorsNG(cardIDs []string, config SearchConfig) (foundVendors map[string]map[string][]SearchEntry) {
	foundVendors = map[string]map[string][]SearchEntry{}

	cardIDs = dedupeKeys(cardIDs)

	storeFilters := config.StoreFilters
	priceFilters := config.PriceFilters
	entryFilters := config.EntryFilters

	for _, vendor := range GetVendors() {
		if shouldSkipStoreNG(vendor, storeFilters) {
			continue
		}

		buylist := vendor.Buylist()

		// Fetch the vendor info and its display name once per store, like
		// in searchSellersNG
		info := vendor.Info()
		name := scraperName(info.Shorthand)

		for _, cardID := range cardIDs {
			entries, found := buylist[cardID]
			if !found {
				continue
			}

			for _, entry := range entries {
				if shouldSkipEntryNG(entry, entryFilters) {
					continue
				}

				if shouldSkipPriceNG(cardID, entry, priceFilters, info.Shorthand) {
					continue
				}

				_, found = foundVendors[cardID]
				if !found {
					foundVendors[cardID] = map[string][]SearchEntry{}
				}

				conditions := entry.Conditions
				if info.MetadataOnly && !info.SealedMode {
					conditions = "INDEX"
				}

				icon := Config.ScraperConfig.Icons[info.Shorthand]

				res := SearchEntry{
					ScraperName:  name,
					Shorthand:    info.Shorthand,
					Price:        entry.BuyPrice,
					Credit:       entry.BuyPrice * info.CreditMultiplier,
					MarketCredit: entry.BuyPrice * info.CreditMultiplier * Config.BuylistMarketCredit[info.Shorthand],
					Ratio:        entry.PriceRatio,
					Quantity:     entry.Quantity,
					URL:          entry.URL,
					BundleIcon:   icon,
					Country:      Country2flag[info.CountryFlag],
				}

				foundVendors[cardID][conditions] = append(foundVendors[cardID][conditions], res)
			}
		}
	}

	return
}

// Append a virtual buylist to search results, priced off the reference
// seller inventories according to the custom buylist rule settings
func searchCustomBuylist(r *http.Request, cardIDs []string, foundVendors map[string]map[string][]SearchEntry) {
	customOpts := strings.Split(readCookie(r, "UploadCustomOpts"), ",")
	if !slices.Contains(customOpts, "enabled") {
		return
	}

	rate, _ := strconv.ParseFloat(readCookie(r, "UploadCustomRate"), 64)
	if rate <= 0 {
		return
	}
	minPrice, _ := strconv.ParseFloat(readCookie(r, "UploadCustomMinPrice"), 64)

	customSeller := readCookie(r, "UploadCustomBuyer")
	customSealedSeller := readCookie(r, "UploadCustomSealedBuyer")
	singles, _ := findSellerInventory(customSeller)
	sealed, _ := findSellerInventory(customSealedSeller)

	// Index price sources have a single meaningful price, while regular
	// retailers list one price per condition
	isIndex := slices.Contains(UploadIndexComparePriceList, customSeller)

	// Decklist/hashing searches repeat a key once per copy; foundVendors is
	// keyed by the unique card, so dedupe to avoid appending an entry per copy.
	for _, cardID := range dedupeKeys(cardIDs) {
		co, err := mtgmatcher.GetUUID(cardID)
		if err != nil {
			continue
		}

		ref := singles
		if co.Sealed {
			ref = sealed
		}
		if ref == nil {
			continue
		}
		entries, found := ref[cardID]
		if !found || len(entries) == 0 {
			continue
		}

		// The rule applies to the best available price
		if entries[0].Price == 0 || entries[0].Price < minPrice {
			continue
		}

		if foundVendors[cardID] == nil {
			foundVendors[cardID] = map[string][]SearchEntry{}
		}

		for _, entry := range entries {
			if entry.Price == 0 {
				continue
			}
			condition := "INDEX"
			if !isIndex {
				condition = entry.Conditions
			}
			foundVendors[cardID][condition] = append(foundVendors[cardID][condition], SearchEntry{
				ScraperName: "Custom Buylist",
				Shorthand:   "CUSTOM",
				Price:       entry.Price * rate,
			})
		}
	}
}

// dedupeKeys returns the keys with duplicates removed, preserving first-seen
// order. It allocates a new slice so the caller's original (e.g. CardHashes)
// keeps its repeats.
func dedupeKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// editionSeedCodes returns the set codes of the first filter that exactly
// bounds the result set: a non-negated edition filter that applies to every
// set. Anything else (negations, ApplyTo-scoped filters) cannot seed.
func editionSeedCodes(filters []FilterElem) ([]string, bool) {
	for i := range filters {
		if filters[i].Name == "edition" && !filters[i].Negate &&
			filters[i].ApplyTo == nil && len(filters[i].Values) > 0 {
			return filters[i].Values, true
		}
	}
	return nil, false
}

func searchAndFilter(config SearchConfig) ([]string, error) {
	query := config.CleanQuery
	filters := config.CardFilters

	var uuids []string
	var err error

	// With no text to search, the mode switch below degrades to seeding
	// from the whole uuid pool. A positive edition filter names its exact
	// result set, so seed from the set index instead: s:EXP,INV becomes
	// the union of two set buckets. Only the modes whose empty-query
	// fallback is the full pool are eligible, and the seeded uuids flow
	// into the same filtering loop as every other search.
	if query == "" {
		if codes, ok := editionSeedCodes(filters); ok {
			for _, code := range codes {
				switch config.SearchMode {
				case "", "prefix", "any":
					uuids = append(uuids, mtgmatcher.GetUUIDsInSet(code)...)
				case "sealed":
					uuids = append(uuids, mtgmatcher.GetSealedUUIDsInSet(code)...)
				}
			}
		}
	}

	if uuids == nil {
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
		case "scryfall":
			uuids, err = searchScryfall(query)
		case "mixed":
			uuids, err = mtgmatcher.SearchSealedEquals(query)
			if err != nil {
				uuids, err = mtgmatcher.SearchSealedContains(query)
			}
			moreUUIDs, _ := mtgmatcher.SearchEquals(query)
			uuids = append(uuids, moreUUIDs...)
		default:
			uuids, err = mtgmatcher.SearchEquals(query)
			// An exact name match can be a red herring: "serra" names a
			// Vanguard card, so "s:leb serra" would stop at it and then
			// filter it out, finding nothing. When the filters reject every
			// exact match, widen to the prefix pool - exactly what the
			// query would have used had the exact name not existed. The
			// surviving exact matches return directly so the filters run
			// once either way.
			if err == nil && len(filters) != 0 {
				selected := filterUUIDs(uuids, filters)
				if len(selected) != 0 {
					return selected, nil
				}
				moreUUIDs, moreErr := mtgmatcher.SearchHasPrefix(query)
				if moreErr == nil {
					uuids = moreUUIDs
				}
			}
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
	}

	return filterUUIDs(uuids, filters), nil
}

// filterUUIDs returns the uuids that pass every card filter.
func filterUUIDs(uuids []string, filters []FilterElem) []string {
	var selected []string
	for _, uuid := range uuids {
		if shouldSkipCardNG(uuid, filters) {
			continue
		}
		selected = append(selected, uuid)
	}
	return selected
}

func editionsForSearch(allKeys []string) []EditionEntry {
	codes := map[string]bool{}
	seenNames := map[string]bool{}
	for _, cardID := range allKeys {
		co, err := mtgmatcher.GetUUID(cardID)
		if err != nil || seenNames[co.Name] {
			continue
		}
		seenNames[co.Name] = true
		printings, err := mtgmatcher.Printings4Card(co.Name)
		if err != nil {
			continue
		}
		for _, code := range printings {
			codes[code] = true
		}
	}
	if len(codes) == 0 {
		return nil
	}

	editions := GetEditions()
	out := make([]EditionEntry, 0, len(codes))
	for code := range codes {
		if entry, ok := editions.AllEditionsMap[code]; ok {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// addFinishVariants appends id's foil and etched finishes to uuids, skipping
// any that don't exist, equal id, or are already present.
func addFinishVariants(uuids []string, id string) []string {
	foilID, _ := mtgmatcher.MatchID(id, true)
	etchedID, _ := mtgmatcher.MatchID(id, false, true)
	for _, otherFinishID := range []string{foilID, etchedID} {
		if otherFinishID != "" && otherFinishID != id && !slices.Contains(uuids, otherFinishID) {
			uuids = append(uuids, otherFinishID)
		}
	}
	return uuids
}

func searchScryfall(query string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*30))
	defer cancel()

	client, err := scryfall.NewClient()
	if err != nil {
		return nil, err
	}

	i := 1
	var out []string
	for {
		sco := scryfall.SearchCardsOptions{
			Unique:        scryfall.UniqueModePrints,
			IncludeExtras: true,
			Page:          i,
		}

		result, err := client.SearchCards(ctx, query, sco)
		if err != nil {
			return nil, err
		}

		// Sort through the results, add the possible foil and etched variants
		for _, card := range result.Cards {
			id := mtgmatcher.ConvertID(mtgmatcher.IDSpaceScryfall, card.ID)
			if id == "" {
				continue
			}
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
			out = addFinishVariants(out, id)
		}

		// Exit the loop when there are no more results
		// or when too many got pulled in
		if !result.HasMore || i > 5 {
			break
		}
		i++
	}

	return out, nil
}

// Try searching for cards usign the Match algorithm
func attemptMatch(query string) ([]string, error) {
	var uuids []string
	uuid, err := mtgmatcher.Match(&mtgmatcher.InputCard{
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
	for _, id := range uuids {
		uuids = addFinishVariants(uuids, id)
	}

	return uuids, nil
}

func searchParallelNG(cardIDs []string, config SearchConfig) (foundSellers map[string]map[string][]SearchEntry, foundVendors map[string]map[string][]SearchEntry) {
	// Initialize up front so callers can always assign into them; when retail or
	// buylist is skipped the corresponding search is never run and the map would
	// otherwise stay nil, panicking on the first write (e.g. the INDEX block).
	foundSellers = map[string]map[string][]SearchEntry{}
	foundVendors = map[string]map[string][]SearchEntry{}

	var wg sync.WaitGroup
	wg.Go(func() {
		if !config.SkipRetail {
			foundSellers = searchSellersNG(cardIDs, config)
		}
	})
	wg.Go(func() {
		if !config.SkipBuylist {
			foundVendors = searchVendorsNG(cardIDs, config)
		}
	})

	wg.Wait()

	return
}

type SortingData struct {
	co          *mtgmatcher.CardObject
	releaseDate time.Time
	parentCode  string

	// Lowercased fields the comparators order by, so the N log N
	// comparisons don't re-lower them every time.
	nameLower    string
	flavorLower  string
	editionLower string
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
	releaseDate, err := mtgmatcher.CardReleaseDate(uuid)
	if err != nil {
		return nil, err
	}
	return &SortingData{
		co:           co,
		releaseDate:  releaseDate,
		parentCode:   set.ParentCode,
		nameLower:    strings.ToLower(co.Name),
		flavorLower:  strings.ToLower(co.FlavorName),
		editionLower: strings.ToLower(co.Edition),
	}, nil
}

// resolveSortingData resolves the sorting data of every given id up
// front, so the N log N comparisons of a sort look each card up instead
// of re-resolving it every time they see it; a sort visits all of its
// elements, so nothing is saved by resolving lazily. Unknown ids get a
// nil entry, which the cmp* comparators order like the lookup error it
// stands for.
func resolveSortingData(cardIDs []string) map[string]*SortingData {
	data := make(map[string]*SortingData, len(cardIDs))
	for _, cardID := range cardIDs {
		_, found := data[cardID]
		if found {
			continue
		}
		sorting, _ := getSortingData(cardID)
		data[cardID] = sorting
	}
	return data
}

// resolveBestPrices records the highest price every given id fetches
// among the listed stores: each price4seller/price4vendor call walks
// the scraper list, so the price sorts must not repeat it per
// comparison, let alone N log N times.
func resolveBestPrices(cardIDs []string, stores []string, price4 func(cardId, shorthand string) float64) map[string]float64 {
	prices := make(map[string]float64, len(cardIDs))
	for _, cardID := range cardIDs {
		_, found := prices[cardID]
		if found {
			continue
		}
		var best float64
		for _, store := range stores {
			price := price4(cardID, store)
			if price > best {
				best = price
			}
		}
		prices[cardID] = best
	}
	return prices
}

// Sort cards by their collector number and finish (nonfoil-foil-etched)
func sortByNumberAndFinish(uuidI, uuidJ string, strip bool) bool {
	sortingI, _ := getSortingData(uuidI)
	sortingJ, _ := getSortingData(uuidJ)
	return cmpNumberAndFinish(sortingI, sortingJ, strip)
}

// cmpNumberAndFinish is sortByNumberAndFinish over already-resolved sorting
// data; nil data (an unknown id) sorts like the lookup error it stands for.
func cmpNumberAndFinish(sortingI, sortingJ *SortingData, strip bool) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI := sortingI.co
	cJ := sortingJ.co

	numI := cI.Card.Number
	numJ := cJ.Card.Number

	// If their number is the same, check for foiling status
	if numI == numJ {
		// Compare promo types first, they are presorted anyway
		if len(cI.PromoTypes) == len(cJ.PromoTypes) {
			for e, promoTypeI := range cI.PromoTypes {
				promoTypeJ := cJ.PromoTypes[e]
				if promoTypeI != promoTypeJ {
					return promoTypeI < promoTypeJ
				}
			}
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
	if errI == nil && errJ == nil {
		return cInum < cJnum
	}

	// If conversion fails for any reson, try again using the numerical value of the card only
	if strip {
		numI = mtgmatcher.ExtractNumberValue(cI.Card.Number)
		numJ = mtgmatcher.ExtractNumberValue(cJ.Card.Number)
		cInum, errI = strconv.Atoi(numI)
		cJnum, errJ = strconv.Atoi(numJ)
		if errI == nil && errJ == nil && cInum != cJnum {
			return cInum < cJnum
		}
	}

	// At this point, numbers look pretty similar, check for languages
	if cI.Card.Language != cJ.Card.Language {
		return cI.Card.Language < cJ.Card.Language
	}

	// If either one is not a number (due to extra letters) just
	// do a normal string comparison
	return cI.Card.Number < cJ.Card.Number
}

// Sort cards grouping them by edition, and then by their collector number
func sortSets(uuidI, uuidJ string) bool {
	sortingI, _ := getSortingData(uuidI)
	sortingJ, _ := getSortingData(uuidJ)
	return cmpSets(sortingI, sortingJ)
}

// cmpSets is sortSets over already-resolved sorting data.
func cmpSets(sortingI, sortingJ *SortingData) bool {
	if sortingI == nil || sortingJ == nil {
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
				// Always keep these products in this order
				for _, prodTag := range []string{"Booster Box", "Booster Pack", "Bundle", "Fat Pack"} {
					bbI := strings.Contains(cI.Name, prodTag) && !strings.Contains(cI.Name, "Case")
					bbJ := strings.Contains(cJ.Name, prodTag) && !strings.Contains(cJ.Name, "Case")
					if bbI && !bbJ {
						return true
					} else if !bbI && bbJ {
						return false
					}
				}

				// Keep Cases and sets last
				bbI := strings.Contains(cI.Name, "Case") || strings.Contains(cI.Name, "Display") || strings.Contains(cI.Name, "Set of")
				bbJ := strings.Contains(cJ.Name, "Case") || strings.Contains(cJ.Name, "Display") || strings.Contains(cJ.Name, "Set of")
				if bbI && !bbJ {
					return false
				} else if !bbI && bbJ {
					return true
				}

				return sortingI.nameLower < sortingJ.nameLower
			}

			return cmpNumberAndFinish(sortingI, sortingJ, true)
			// For the special case of set promos, always keeps them after
		} else if sortingI.parentCode == "" && sortingJ.parentCode != "" {
			return true
		} else if sortingJ.parentCode == "" && sortingI.parentCode != "" {
			return false
		}
		return sortingI.editionLower < sortingJ.editionLower
	}

	return setDateI.After(setDateJ)
}

// Sort card by their names, trying to keep cards grouped by edition, following
// the same rules as sortSets
func sortSetsAlphabetical(uuidI, uuidJ string, preferFlavor bool) bool {
	sortingI, _ := getSortingData(uuidI)
	sortingJ, _ := getSortingData(uuidJ)
	return cmpSetsAlphabetical(sortingI, sortingJ, preferFlavor)
}

// cmpSetsAlphabetical is sortSetsAlphabetical over already-resolved sorting data.
func cmpSetsAlphabetical(sortingI, sortingJ *SortingData, preferFlavor bool) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	cIname, cInameLower := cI.Name, sortingI.nameLower
	cJname, cJnameLower := cJ.Name, sortingJ.nameLower
	if preferFlavor && cI.FlavorName != "" && allLanguageFlags[cI.Language] != "" {
		cIname, cInameLower = cI.FlavorName, sortingI.flavorLower
	}
	if preferFlavor && cJ.FlavorName != "" && allLanguageFlags[cJ.Language] != "" {
		cJname, cJnameLower = cJ.FlavorName, sortingJ.flavorLower
	}

	if cIname == cJname {
		if setDateI.Equal(setDateJ) {
			// We need not to strip to keep set ordered wrt Promos etc
			return cmpNumberAndFinish(sortingI, sortingJ, false)
		}

		return setDateI.After(setDateJ)
	}

	return cInameLower < cJnameLower
}

// Sort card by their names, keeping cards grouped by edition alphabetically
func sortSetsAlphabeticalSet(uuidI, uuidJ string, preferFlavor bool) bool {
	sortingI, _ := getSortingData(uuidI)
	sortingJ, _ := getSortingData(uuidJ)
	return cmpSetsAlphabeticalSet(sortingI, sortingJ, preferFlavor)
}

// cmpSetsAlphabeticalSet is sortSetsAlphabeticalSet over already-resolved sorting data.
func cmpSetsAlphabeticalSet(sortingI, sortingJ *SortingData, preferFlavor bool) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI := sortingI.co
	cJ := sortingJ.co

	if cI.SetCode == cJ.SetCode {
		return cmpSetsAlphabetical(sortingI, sortingJ, preferFlavor)
	}

	return sortingI.editionLower < sortingJ.editionLower
}
