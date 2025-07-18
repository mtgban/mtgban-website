package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	"github.com/extrame/xls"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/xuri/excelize/v2"
	"golang.org/x/exp/slices"
	"gopkg.in/Iwark/spreadsheet.v2"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	MinLowValueSpread  = 60.0
	VisualPercSpread   = 100.0
	MinLowValueAbs     = 1.0
	MaxHighValueSpread = 0.0
	MaxHighValueAbs    = 0.0

	MaxUploadEntries      = 350
	MaxUploadProEntries   = 1000
	MaxUploadTotalEntries = 10000
	MaxUploadFileSize     = 5 << 20

	ProfitabilityConstant = 2

	TooManyEntriesMessage = "Note: you reached the maximum number of entries supported by this tool"
)

// List of ALL index prices to track
var UploadIndexKeys = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "TCGDirectLow",
}

// List of index prices to show by default (must be a subset of UploadIndexKeys)
var UploadIndexKeysPublic = []string{
	"TCGLow", "TCGMarket", "TCGDirect",
}

// List of index prices to use for CSVs
var UploadIndexKeysCSV = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "MKMLow", "MKMTrend",
}

// List of alternative prices sources
var UploadIndexComparePriceList = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "CT", "CT0", "MKMLow", "MKMTrend",
}

var ErrUploadDecklist = errors.New("decklist")
var ErrReloadFirstRow = errors.New("firstrow")

// Data coming from the user upload
type UploadEntry struct {
	// A reference to the parsed card
	Card mtgmatcher.InputCard

	// The UUID of the card
	CardId string

	// Error when mtgmatcher.Match() fails
	MismatchError error

	// Error when multiple results are found
	MismatchAlias bool

	// Price as found in the source data
	OriginalPrice float64

	// Condition as found in the source data
	OriginalCondition string

	// Whether source data had Quantity information
	HasQuantity bool

	// Quantity as found in the source data
	Quantity int

	// Value exported as-is (up to 1024 characters) from the source data
	Notes string
}

// Subset of data used in the optimizer
type OptimizedUploadEntry struct {
	// The UUID of the card
	CardId string

	// Condition as found in the source data
	Condition string

	// Price of the card provided in the source data (or TCGLow)
	Price float64

	// Key of the source of alternative (comparison) pricing
	CompareSource string

	// Percentage of the store price vs uploaded price
	Spread float64

	// Price of the card provided by the Store (condition accounted)
	BestPrice float64

	// Quantity as found in the source data
	Quantity int

	// Price used to display a visual indicator
	VisualPrice float64

	// Profitability index
	Profitability float64
}

func Upload(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Upload", sig)

	// Maximum form size
	r.ParseMultipartForm(MaxUploadFileSize)

	// See if we need to download the ck csv only
	hashTag := r.FormValue("tag")
	switch hashTag {
	case "CK", "SCG", "TCG":
		hashes := r.Form[hashTag+"hashes"]
		hashesQtys := r.Form[hashTag+"hashesQtys"]
		hashesCond := r.Form[hashTag+"hashesCond"]
		if hashes != nil {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=\"mtgban_"+strings.ToLower(hashTag)+".csv\"")
			csvWriter := csv.NewWriter(w)

			var err error
			switch hashTag {
			case "CK":
				err = UUID2CKCSV(csvWriter, hashes, hashesQtys)
			case "SCG":
				err = UUID2SCGCSV(csvWriter, hashes, hashesQtys)
			case "TCG":
				err = UUID2TCGCSV(csvWriter, hashes, hashesQtys, hashesCond)
			}
			if err != nil {
				w.Header().Del("Content-Type")
				UserNotify("upload", err.Error())
				pageVars.InfoMessage = "Unable to download CSV right now"
				render(w, "upload.html", pageVars)
			}
			return
		}
		pageVars.ErrorMessage = "Invalid tag option: " + hashTag
		render(w, "upload.html", pageVars)
		return
	}

	// Check cookies to set preferences
	blMode := readSetFlag(w, r, "mode", "uploadMode")

	// Disable buylist if not permitted
	canBuylist, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadBuylistEnabled"))
	if DevMode && !SigCheck {
		canBuylist = true
	}
	if !canBuylist {
		blMode = false
	}

	// Disable changing stores if not permitted
	canChangeStores, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadChangeStoresEnabled"))
	if DevMode && !SigCheck {
		canChangeStores = true
	}

	// Enable optimizer customization
	var skipLowValue, skipLowValueAbs, skipHighValue, skipHighValueAbs bool
	var skipConds, skipPrices bool
	var useMargin bool
	var visualIndicator bool
	if blMode {
		skipLowValue = r.FormValue("lowval") != ""
		skipLowValueAbs = r.FormValue("lowvalabs") != ""
		skipHighValue = r.FormValue("highval") != ""
		skipHighValueAbs = r.FormValue("highvalabs") != ""
		useMargin = r.FormValue("minmargin") != ""
		skipConds = r.FormValue("nocond") != ""
		skipPrices = r.FormValue("noprice") != ""
		visualIndicator = r.FormValue("customperc") != ""
	}
	sorting := r.FormValue("sorting")

	percSpread := MinLowValueSpread
	customSpread, err := strconv.ParseFloat(r.FormValue("percspread"), 64)
	if err == nil && customSpread > 0 {
		percSpread = customSpread
	}

	percSpreadMax := MaxHighValueSpread
	customSpreadMax, err := strconv.ParseFloat(r.FormValue("percspreadmax"), 64)
	if err == nil && customSpreadMax > percSpread {
		percSpreadMax = customSpreadMax
	}

	minLowVal := MinLowValueAbs
	customMin, err := strconv.ParseFloat(r.FormValue("minval"), 64)
	if err == nil && customMin > 0 {
		minLowVal = customMin
	}

	maxHighVal := MaxHighValueAbs
	customMax, err := strconv.ParseFloat(r.FormValue("maxval"), 64)
	if err == nil && customMax > minLowVal {
		maxHighVal = customMax
	}

	percMargin := 1.0
	if useMargin {
		customMargin, err := strconv.ParseFloat(r.FormValue("margin"), 64)
		if err == nil && customMargin >= 0 {
			percMargin = 1 - customMargin/100.0
		}
	}

	visualPerc := VisualPercSpread
	customVisual, err := strconv.ParseFloat(r.FormValue("custompercmax"), 64)
	if err == nil && customMin > 0 {
		visualPerc = customVisual
	}
	pageVars.CanFilterByPrice = visualIndicator

	multiplier := 1
	customMultiplier, err := strconv.Atoi(r.FormValue("multiplier"))
	if err == nil && customMultiplier > 1 {
		multiplier = customMultiplier
	}

	// Set flags needed to show elements on the page ui
	pageVars.IsBuylist = blMode
	pageVars.CanBuylist = canBuylist
	pageVars.CanChangeStores = canChangeStores

	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)
	var enabledStores []string
	var allSellers []string
	var allVendors []string

	// Load all possible sellers, and vendors according to user permissions
	for _, seller := range Sellers {
		if seller != nil && !slices.Contains(blocklistRetail, seller.Info().Shorthand) && !seller.Info().SealedMode && !seller.Info().MetadataOnly {
			allSellers = append(allSellers, seller.Info().Shorthand)
		}
	}
	for _, vendor := range Vendors {
		if vendor != nil && !slices.Contains(blocklistBuylist, vendor.Info().Shorthand) && !vendor.Info().SealedMode {
			allVendors = append(allVendors, vendor.Info().Shorthand)
		}
	}

	// Set the store names for the <select> box
	pageVars.SellerKeys = allSellers
	pageVars.VendorKeys = allVendors
	pageVars.AltKeys = UploadIndexComparePriceList

	// Load the preferred list of enabled stores for the <select> box
	// The first check is for when the cookie is not yet set
	// Force stores if not allowed to change them
	enabledSellers := readCookie(r, "enabledSellers")
	if len(enabledSellers) == 0 || !canChangeStores {
		pageVars.EnabledSellers = Config.AffiliatesList
	} else {
		pageVars.EnabledSellers = strings.Split(enabledSellers, "|")
	}

	enabledVendors := readCookie(r, "enabledVendors")
	if len(enabledVendors) == 0 {
		pageVars.EnabledVendors = allVendors
	} else {
		pageVars.EnabledVendors = strings.Split(enabledVendors, "|")
	}

	cachedGdocURL := readCookie(r, "gdocURL")
	pageVars.RemoteLinkURL = cachedGdocURL

	// Filter out any unselected store from the full list
	stores := r.Form["stores"]
	if blMode {
		for _, store := range stores {
			if slices.Contains(allVendors, store) {
				enabledStores = append(enabledStores, store)
			}
		}
	} else {
		// Override in case not allowed to change list
		if !canChangeStores {
			stores = Config.AffiliatesList
		}
		for _, store := range stores {
			if slices.Contains(allSellers, store) {
				enabledStores = append(enabledStores, store)
			}
		}
	}

	// Private call from newspaper
	hashes := r.Form["hashes"]
	if len(hashes) != 0 && len(stores) == 0 {
		if blMode {
			enabledStores = pageVars.EnabledVendors
		} else {
			enabledStores = pageVars.EnabledSellers
		}
	}

	// Load spreadsheet cloud url if present
	gdocURL := r.FormValue("gdocURL")

	// Load from the freeform text area
	textArea := r.FormValue("textArea")

	// FormFile returns the first file for the given key `cardListFile`
	// it also returns the FileHeader so we can get the Filename,
	// the Header and the size of the file
	file, handler, err := r.FormFile("cardListFile")
	if err != nil && gdocURL == "" && textArea == "" && len(hashes) == 0 {
		render(w, "upload.html", pageVars)
		return
	} else if err == nil {
		defer file.Close()
	}

	if len(hashes) != 0 {
		log.Printf("Loading from POST %d cards", len(hashes))
		pageVars.CardHashes = hashes
	} else if gdocURL != "" {
		log.Printf("Loading spreadsheet: %+v", gdocURL)
	} else if textArea != "" {
		log.Printf("Loading freeform text area (%d bytes)", len(textArea))
	} else {
		log.Printf("Uploaded File: %+v", handler.Filename)
		log.Printf("File Size: %+v bytes", handler.Size)
		log.Printf("MIME Header: %+v", handler.Header)
	}
	log.Printf("Buylist mode: %+v", blMode)
	log.Printf("Enabled stores: %+v", enabledStores)

	// Reset the cookie for this preference
	if len(hashes) == 0 && cachedGdocURL != gdocURL {
		setCookie(w, r, "gdocURL", gdocURL)
		pageVars.RemoteLinkURL = gdocURL
	}

	// Save user preferred stores in cookies and make sure the page is updated with those
	if blMode {
		setCookie(w, r, "enabledVendors", strings.Join(enabledStores, "|"))
		pageVars.EnabledVendors = enabledStores
	} else {
		setCookie(w, r, "enabledSellers", strings.Join(enabledStores, "|"))
		pageVars.EnabledSellers = enabledStores
	}

	estimate, _ := strconv.ParseBool(r.FormValue("estimate"))
	deckbox, _ := strconv.ParseBool(r.FormValue("deckbox"))

	start := time.Now()

	// Set upload limit
	maxRows := MaxUploadEntries
	download, _ := strconv.ParseBool(r.FormValue("download"))

	// Increase upload limit if allowed
	optimizerOpt, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadOptimizer"))
	increaseMaxRows := optimizerOpt || (DevMode && !SigCheck)
	if increaseMaxRows {
		maxRows = MaxUploadProEntries
	}
	// Allow a larger upload limit if set, if dev, or if it's an external call
	limitOpt, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadNoLimit"))
	uploadNoLimit := limitOpt || (DevMode && !SigCheck) || estimate || deckbox || (download && canBuylist)
	if uploadNoLimit {
		maxRows = MaxUploadTotalEntries
	}

	// Load data
	var uploadedData []UploadEntry
	if len(hashes) != 0 {
		uploadedData, err = loadHashes(hashes)
	} else if textArea != "" {
		uploadedData, err = loadCsv(strings.NewReader(textArea), ',', maxRows)
	} else if handler != nil {
		if strings.HasSuffix(handler.Filename, ".xls") {
			uploadedData, err = loadOldXls(file, maxRows)
		} else if strings.HasSuffix(handler.Filename, ".xlsx") {
			uploadedData, err = loadXlsx(file, maxRows)
		} else {
			uploadedData, err = loadCsv(file, ',', maxRows)
		}
	} else if gdocURL != "" {
		var u *url.URL
		u, err = url.Parse(gdocURL)
		if err == nil {
			switch u.Host {
			case "store.tcgplayer.com":
				uploadedData, err = loadCollection(gdocURL, maxRows)
			case "www.moxfield.com", "moxfield.com":
				uploadedData, err = loadMoxfieldDeck(u.Path, maxRows)
			case "docs.google.com":
				uploadedData, err = loadSpreadsheet(u.Path, maxRows)
			default:
				err = errors.New("unsupported URL")
			}
		}
	}
	if err != nil {
		pageVars.WarningMessage = err.Error()
		render(w, "upload.html", pageVars)
		return
	}

	uploadedData = mergeIdenticalEntries(uploadedData)

	// Allow estimating on a separate page
	if estimate {
		var items []CCItem
		for i := range uploadedData {
			if uploadedData[i].CardId == "" {
				continue
			}
			co, err := mtgmatcher.GetUUID(uploadedData[i].CardId)
			if err != nil {
				continue
			}
			scryfallId, found := co.Identifiers["scryfallId"]
			if !found {
				continue
			}

			var cond string
			if uploadedData[i].OriginalCondition != "" {
				cond = map[string]string{
					"NM": "nm",
					"SP": "lp",
					"MP": "mp",
					"HP": "hp",
					"PO": "dmg",
				}[uploadedData[i].OriginalCondition]
			}
			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			qty *= multiplier

			items = append(items, CCItem{
				ScryfallID: scryfallId,
				Condition:  cond,
				Quantity:   qty,
				IsFoil:     co.Foil,
				IsEtched:   co.Etched,
			})
		}

		link, err := sendCardConduitEstimate(items)
		if err != nil {
			UserNotify("upload", err.Error())
			pageVars.InfoMessage = "Unable to process your list to CardConduit right now"
			render(w, "upload.html", pageVars)
			return
		}

		http.Redirect(w, r, link, http.StatusFound)
		return
	}
	if deckbox && canBuylist {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"mtgban_deckbox.csv\"")
		csvWriter := csv.NewWriter(w)

		err = deckboxIdConvert(csvWriter, uploadedData)
		if err != nil {
			w.Header().Del("Content-Type")
			UserNotify("upload", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "upload.html", pageVars)
		}
		return
	}

	var shouldCheckForConditions bool

	// Extract card Ids
	cardIds := make([]string, 0, len(uploadedData))
	for i := range uploadedData {
		// Filter out empty ids
		if uploadedData[i].CardId == "" {
			continue
		}
		cardIds = append(cardIds, uploadedData[i].CardId)

		// Check if conditions should be retrieved
		if uploadedData[i].OriginalCondition != "" {
			if skipConds {
				uploadedData[i].OriginalCondition = ""
			} else {
				shouldCheckForConditions = true
			}
		}
	}

	// Check not too many entries got uploaded
	if len(cardIds) >= maxRows {
		pageVars.InfoMessage = TooManyEntriesMessage
	}

	tagPref := "tags"
	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")

	// Search
	var results map[string]map[string]*BanPrice
	if blMode {
		results = getVendorPrices("", enabledStores, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
	} else {
		results = getSellerPrices("", enabledStores, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
	}

	// Allow downloading data as CSV
	if download && canBuylist {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"mtgban_prices.csv\"")
		csvWriter := csv.NewWriter(w)

		// Search for all csv-specific indexes
		indexResults := getSellerPrices("", UploadIndexKeysCSV, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)

		// Copy these index prices in the final results
		for _, cardId := range cardIds {
			for _, index := range UploadIndexKeysCSV {
				if results[cardId] == nil {
					results[cardId] = map[string]*BanPrice{}
				}
				results[cardId][index] = indexResults[cardId][index]
			}
		}

		err = SimplePrice2CSV(csvWriter, results, uploadedData, preferFlavor)
		if err != nil {
			w.Header().Del("Content-Type")
			UserNotify("upload", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "upload.html", pageVars)
		}
		return
	}

	indexKeys := UploadIndexKeys

	// Choose the alternative reference pricing source when one is not loaded in
	altPriceSource := r.FormValue("altPrice")
	if !slices.Contains(UploadIndexComparePriceList, altPriceSource) {
		altPriceSource = UploadIndexKeys[0]
	}
	if !slices.Contains(indexKeys, altPriceSource) {
		indexKeys = append(indexKeys, altPriceSource)
	}

	indexResults := getSellerPrices("", indexKeys, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
	pageVars.IndexKeys = UploadIndexKeysPublic

	// Orders implies priority of argument search
	pageVars.Metadata = map[string]GenericCard{}
	if len(hashes) != 0 {
		pageVars.SearchQuery = "hashes"
	} else if textArea != "" {
		pageVars.SearchQuery = "pasted text"
	} else if gdocURL != "" {
		pageVars.SearchQuery = gdocURL
	} else {
		pageVars.SearchQuery = handler.Filename
	}
	pageVars.ScraperKeys = enabledStores
	pageVars.TotalEntries = map[string]float64{}

	skipResults := r.FormValue("noresults") != ""
	if !(blMode && skipResults) {
		pageVars.UploadEntries = uploadedData
	}

	// Load up image links
	for _, data := range uploadedData {
		if data.MismatchError != nil {
			continue
		}

		_, found := pageVars.Metadata[data.CardId]
		if found {
			continue
		}
		pageVars.Metadata[data.CardId] = uuid2card(data.CardId, true, false, preferFlavor)
		if pageVars.Metadata[data.CardId].Reserved {
			pageVars.HasReserved = true
		}
		if pageVars.Metadata[data.CardId].Stocks {
			pageVars.HasStocks = true
		}
		if pageVars.Metadata[data.CardId].SypList {
			pageVars.HasSypList = true
		}
	}

	var highestTotal float64

	optimizedResults := map[string][]OptimizedUploadEntry{}
	optimizedTotals := map[string]float64{}

	missingCounts := map[string]int{}
	missingPrices := map[string]float64{}
	resultPrices := map[string]map[string]float64{}

	for i := range uploadedData {
		// Skip unmatched cards
		if uploadedData[i].MismatchError != nil {
			continue
		}

		var bestPrices []float64
		var bestStores []string

		cardId := uploadedData[i].CardId

		// Search for any missing entries (ie cards not sold or bought by a vendor)
		for _, shorthand := range enabledStores {
			_, found := results[cardId][shorthand]
			if !found {
				missingCounts[shorthand]++
				missingPrices[shorthand] += getPrice(indexResults[cardId]["TCGLow"], "")
			}
		}

		// Summary of the index entries
		for indexKey, indexResult := range indexResults[cardId] {
			var conds string
			// TCG Direct is the only index price that varies by condition
			if indexKey == "TCGDirect" {
				conds = uploadedData[i].OriginalCondition
			}
			if skipConds {
				conds = ""
			}
			indexPrice := getPrice(indexResult, conds)

			if resultPrices[cardId+conds] == nil {
				resultPrices[cardId+conds] = map[string]float64{}
			}
			resultPrices[cardId+conds][indexKey] = indexPrice

			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			indexPrice *= float64(qty * multiplier)
			pageVars.TotalEntries[indexKey] += indexPrice
		}

		// Quantity summary
		qty := 1
		if uploadedData[i].HasQuantity {
			qty = uploadedData[i].Quantity
		}
		pageVars.TotalQuantity += qty * multiplier

		// Run summaries for each vendor
		for shorthand, banPrice := range results[cardId] {
			conds := uploadedData[i].OriginalCondition
			if skipConds {
				conds = ""
			}
			price := getPrice(banPrice, conds)

			// Store computed price
			if resultPrices[cardId+conds] == nil {
				resultPrices[cardId+conds] = map[string]float64{}
			}
			resultPrices[cardId+conds][shorthand] = price

			// Skip empty results
			if price == 0 {
				continue
			}

			// Adjust for quantity
			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			price *= float64(qty * multiplier)

			// Add to totals (unless it was an index, since it was already added)
			_, found := indexResults[cardId][shorthand]
			if !found {
				pageVars.TotalEntries[shorthand] += price
			}

			// Save the lowest or highest price depending on mode
			// If price is tied, or within a set % difference, save them all
			if len(bestPrices) == 0 || (blMode && price*percMargin > bestPrices[0]) || (!blMode && price*percMargin < bestPrices[0]) {
				bestPrices = []float64{price}
				bestStores = []string{shorthand}
			} else if (blMode && price > bestPrices[0]*percMargin) || (!blMode && price < bestPrices[0]*percMargin) {
				bestPrices = append(bestPrices, price)
				bestStores = append(bestStores, shorthand)
			}
		}

		for j, bestPrice := range bestPrices {
			bestStore := bestStores[j]

			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			qty *= multiplier

			conds := uploadedData[i].OriginalCondition
			if skipConds {
				conds = ""
			}
			cardId := uploadedData[i].CardId

			// Load comparison price, either the loaded one or one of the alternatives
			comparePrice := uploadedData[i].OriginalPrice
			if comparePrice == 0 || skipPrices {
				compareConds := ""
				prices := indexResults[cardId][altPriceSource]
				if slices.Index(indexKeys, altPriceSource) > len(UploadIndexKeys) {
					compareConds = conds
				}

				// Normally index has no conditions to check, but the price might be coming
				// from a regular store (in which case we attempt to match it)
				comparePrice = getPrice(prices, compareConds)
			}

			// Load the single item priceprice
			price := resultPrices[cardId+conds][bestStore]

			// Skip if needed
			if skipLowValueAbs && price < minLowVal {
				continue
			}
			if skipHighValueAbs && maxHighVal != 0 && price >= maxHighVal {
				continue
			}

			var factor float64
			var profitability float64
			// Compute spread (and skip if needed)
			if comparePrice != 0 {
				factor = price / comparePrice * 100

				if skipLowValue && factor < percSpread {
					continue
				}
				if skipHighValue && percSpreadMax != 0 && factor >= percSpreadMax {
					continue
				}

				if factor > 0 {
					profitability = ((comparePrice - price) / (price + ProfitabilityConstant)) * math.Log(1+factor)
					if qty > 1 {
						profitability *= math.Pow(float64(qty), 0.25)
					}
				}
			}

			// Break down by store
			optimizedResults[bestStore] = append(optimizedResults[bestStore], OptimizedUploadEntry{
				CardId:        cardId,
				Condition:     conds,
				Price:         comparePrice,
				CompareSource: altPriceSource,
				Spread:        factor,
				BestPrice:     price,
				Quantity:      qty,
				VisualPrice:   comparePrice * visualPerc / 100.0,
				Profitability: profitability,
			})

			// Save totals
			optimizedTotals[bestStore] += bestPrice
			if j == 0 {
				highestTotal += bestPrice
			}
		}

		// Keep cards sorted by edition, following the same rules of search
		for store := range optimizedResults {
			switch sorting {
			case "highprice":
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					return optimizedResults[store][i].BestPrice > optimizedResults[store][j].BestPrice
				})
			case "highspread":
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					return optimizedResults[store][i].Spread > optimizedResults[store][j].Spread
				})
			case "setalpha":
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					return sortSetsAlphabeticalSet(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId, preferFlavor)
				})
			case "alphabetical":
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					return sortSetsAlphabetical(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId, preferFlavor)
				})
			case "profitability":
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					if optimizedResults[store][i].Spread < 0 || optimizedResults[store][j].Spread < 0 {
						return optimizedResults[store][i].Spread > optimizedResults[store][j].Spread
					}
					// Remember profitability here is computed over the factor to the base price
					// not from the actual traditional spread, so they are reversed
					return optimizedResults[store][i].Profitability < optimizedResults[store][j].Profitability
				})
			default:
				sort.Slice(optimizedResults[store], func(i, j int) bool {
					return sortSets(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId)
				})
			}
		}

		pageVars.Optimized = optimizedResults
		pageVars.OptimizedTotals = optimizedTotals
		pageVars.HighestTotal = highestTotal
		pageVars.Editions = AllEditionsKeys
		pageVars.EditionsMap = AllEditionsMap
	}

	switch sorting {
	case "highprice":
		sort.Slice(uploadedData, func(i, j int) bool {
			return uploadedData[i].OriginalPrice > uploadedData[j].OriginalPrice
		})
	case "alphabetical":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSetsAlphabetical(uploadedData[i].CardId, uploadedData[j].CardId, preferFlavor)
		})
	case "setalpha":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSetsAlphabeticalSet(uploadedData[i].CardId, uploadedData[j].CardId, preferFlavor)
		})
	case "setchrono":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSets(uploadedData[i].CardId, uploadedData[j].CardId)
		})
	default:
		// Leave input order
	}

	pageVars.MissingCounts = missingCounts
	pageVars.MissingPrices = missingPrices
	pageVars.ResultPrices = resultPrices

	// Logs
	user := GetParamFromSig(sig, "UserEmail")
	msgMode := "retail"
	if blMode {
		msgMode = "buylist"
	}
	msg := fmt.Sprintf("%s uploaded %d %s entries from %s, took %v", user, len(cardIds), msgMode, pageVars.SearchQuery, time.Since(start))
	UserNotify("upload", msg)
	LogPages["Upload"].Println(msg)

	// Touchdown!
	render(w, "upload.html", pageVars)
}

func getPrice(banPrice *BanPrice, conds string) float64 {
	if banPrice == nil {
		return 0
	}

	var price float64

	// Grab the correct Price
	if conds == "" {
		price = banPrice.Regular
		if price == 0 {
			price = banPrice.Foil
			if price == 0 {
				price = banPrice.Etched
			}
		}
	} else {
		price = banPrice.Conditions[conds]
		if price == 0 {
			price = banPrice.Conditions[conds+"_foil"]
			if price == 0 {
				price = banPrice.Conditions[conds+"_etched"]
			}
		}
	}

	return price
}

func getQuantity(qty string) (int, error) {
	qty = strings.TrimSuffix(qty, "x")
	qty = strings.TrimSpace(qty)
	return strconv.Atoi(qty)
}

func mergeIdenticalEntries(uploadedData []UploadEntry) []UploadEntry {
	var uploadedDataClean []UploadEntry
	duplicatedHashes := map[string]bool{}

	for i := range uploadedData {
		// Preserve empty results (for errors and whatnot)
		if uploadedData[i].CardId == "" {
			uploadedDataClean = append(uploadedDataClean, uploadedData[i])
			continue
		}

		// Use id + condition to mimic a "sku"
		sku := uploadedData[i].CardId + uploadedData[i].OriginalCondition

		if duplicatedHashes[sku] {
			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}

			// Iterate on the already added cards to update the quantity
			for j := range uploadedDataClean {
				if uploadedData[i].CardId == uploadedDataClean[j].CardId &&
					uploadedData[i].OriginalCondition == uploadedDataClean[j].OriginalCondition {
					if uploadedDataClean[j].Quantity == 0 {
						uploadedDataClean[j].Quantity++
					}
					uploadedDataClean[j].Quantity += qty
					uploadedDataClean[j].HasQuantity = true
					break
				}
			}
			continue
		}

		duplicatedHashes[sku] = true
		uploadedDataClean = append(uploadedDataClean, uploadedData[i])
	}

	return uploadedDataClean
}

func parseHeader(first []string) (map[string]int, error) {
	if len(first) < 1 {
		return nil, errors.New("too few fields")
	}

	indexMap := map[string]int{}

	// If there is a single element, try using a different mode
	if len(first) == 1 {
		indexMap["cardName"] = 0
		log.Println("No Header map, decklist mode (single element)")
		return indexMap, ErrUploadDecklist
	}

	// Parse the header to understand where these fields are
	for i, field := range first {
		field = strings.ToLower(field)
		switch {
		// Skip "tcgplayer id" because it could mean SKU or Product, and the two systems often overlap
		case field == "id" || strings.Contains(field, "uuid") || (strings.Contains(field, "id") && field != "tcgplayer id" && (strings.Contains(field, "tcg") || strings.Contains(field, "scryfall"))):
			_, found := indexMap["id"]
			if !found {
				indexMap["id"] = i
			}
		case (strings.Contains(field, "name") && !strings.Contains(field, "edition") && !strings.Contains(field, "set") || strings.Contains(field, "expansion")) || field == "card":
			_, found := indexMap["cardName"]
			if !found {
				indexMap["cardName"] = i
			}
		case strings.Contains(field, "edition") || strings.Contains(field, "set") || strings.Contains(field, "expansion"):
			_, found := indexMap["edition"]
			if !found {
				indexMap["edition"] = i
			}
		case strings.Contains(field, "comment") ||
			strings.Contains(field, "number") ||
			strings.Contains(field, "variant") ||
			strings.Contains(field, "variation") ||
			strings.Contains(field, "version"):
			_, found := indexMap["variant"]
			if !found {
				indexMap["variant"] = i
			}
		case strings.Contains(field, "foil") || strings.Contains(field, "printing") || strings.Contains(field, "finish") || strings.Contains(field, "extra") || field == "f/nf" || field == "nf/f":
			_, found := indexMap["printing"]
			if !found {
				indexMap["printing"] = i
			}
		case strings.Contains(field, "sku"):
			_, found := indexMap["sku"]
			if !found {
				indexMap["sku"] = i
			}
		case strings.Contains(field, "condition"):
			_, found := indexMap["conditions"]
			if !found {
				indexMap["conditions"] = i
			}
		case strings.Contains(field, "price") || strings.Contains(field, "low"):
			_, found := indexMap["price"]
			if !found {
				indexMap["price"] = i
			}
		case (strings.Contains(field, "quantity") ||
			strings.Contains(field, "qty") ||
			strings.Contains(field, "stock") ||
			strings.Contains(field, "count") ||
			strings.Contains(field, "trade") ||
			strings.Contains(field, "have")) &&
			!strings.HasPrefix(field, "set") && !strings.Contains(field, "pending"):
			// Keep headers like "Add To Quantity" as backup if nothing is found later
			_, found := indexMap["quantity"]
			if !found && !strings.HasPrefix(field, "add") {
				indexMap["quantity"] = i
			} else {
				_, found := indexMap["quantity_backup"]
				if !found {
					indexMap["quantity_backup"] = i
				}
			}
		case strings.Contains(field, "title") && !strings.Contains(field, "variant"):
			_, found := indexMap["title"]
			if !found {
				indexMap["title"] = i
			}
		case strings.Contains(field, "notes") || strings.Contains(field, "data"):
			_, found := indexMap["notes"]
			if !found {
				indexMap["notes"] = i
			}
		}
	}

	// In case there was actually a single element, but the comma appears in the card name
	// Performing this after processing the map in case of a weird header with spaces
	// after the names
	if len(indexMap) < 2 && strings.Contains(strings.Join(first, ","), ", ") {
		indexMap["cardName"] = 0
		log.Println("No Header map, decklist mode (comma in card name)")
		return indexMap, ErrUploadDecklist
	}

	// If a clean quantity header was not found see if there is a backup option
	_, foundQty := indexMap["quantity"]
	if !foundQty {
		i, found := indexMap["quantity_backup"]
		if found {
			indexMap["quantity"] = i
		}
	}

	// If this field is present we don't need safe defaults
	_, foundId := indexMap["id"]

	// Set some default values for the mandatory fields
	_, foundName := indexMap["cardName"]
	if !foundName && !foundId {
		indexMap["cardName"] = 0
		// Used by some formats that do not set a card name
		i, found := indexMap["title"]
		if found {
			indexMap["cardName"] = i
			foundName = true
		}
	}
	_, foundEdition := indexMap["edition"]
	if !foundEdition && !foundId {
		indexMap["edition"] = 1
	}

	// If nothing at all was found, send an error to reprocess the first line
	if !foundName && !foundEdition && !foundId {
		log.Println("Fake Header map:", indexMap)
		return indexMap, ErrReloadFirstRow
	}

	log.Println("Header map:", indexMap)
	return indexMap, nil
}

func parseRow(indexMap map[string]int, record []string) (UploadEntry, error) {
	var res UploadEntry

	// Skip empty lines
	hasContent := false
	for _, field := range record {
		if field != "" {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return res, errors.New("empty line")
	}

	// Ensure fields can be parsed correctly
	for i := range record {
		record[i] = strings.TrimSpace(record[i])
	}

	// Decklist mode
	if len(record) == 1 {
		line := record[indexMap["cardName"]]

		// Support setting a card foil
		if strings.HasSuffix(line, "*F*") {
			res.Card.Foil = true
			line = strings.TrimSuffix(line, "*F*")
			line = strings.TrimSpace(line)
		}

		if line != "" && unicode.IsDigit(rune(line[0])) {
			// Parse both "4 x <name>" and "4x <name>"
			fields := strings.Split(line, " ")
			field := strings.TrimSuffix(fields[0], "x")
			num, err := strconv.Atoi(field)
			if err == nil {
				// Cleanup and append
				line = strings.TrimPrefix(line, field)
				line = strings.TrimSpace(line)
				line = strings.TrimPrefix(line, "x")
				res.HasQuantity = true
				res.Quantity = num
			}
		}

		// Parse "Rift Bolt (TSP)"
		vars := mtgmatcher.SplitVariants(line)
		if len(vars) > 1 {
			maybeEdition := vars[1]
			// Only assign edition if it's a known set code
			set, err := mtgmatcher.GetSetByName(maybeEdition)
			if err == nil {
				// Remove the parsed part, leaving any other detail available downstream
				line = strings.Replace(line, "("+maybeEdition+")", "", 1)
				line = strings.Replace(line, "  ", "", -1)
				res.Card.Edition = set.Name
			}

			// Parse the number from "Flagstones of Trokair (tsr) 278"
			if strings.HasPrefix(line, vars[0]) && unicode.IsDigit(rune(line[len(line)-1])) {
				res.Card.Variation = strings.TrimPrefix(line, vars[0])
				line = vars[0]
			}
		}

		// Parse "10 Swamp <462> [CLB]"
		line = strings.Replace(line, "<", "(", 1)
		line = strings.Replace(line, ">", ")", 1)

		record[indexMap["cardName"]] = line
	}

	// Load quantity, and skip it if it's present and zero
	idx, found := indexMap["quantity"]
	if found && idx < len(record) {
		num, err := getQuantity(record[idx])
		if err != nil || num == 0 {
			// Retry in the second quantity data if present
			idx, found = indexMap["quantity_backup"]
			if found && idx < len(record) {
				num, err = getQuantity(record[idx])
			}
		}
		if err == nil {
			res.HasQuantity = true
			res.Quantity = num
		}
	}
	if res.HasQuantity && res.Quantity == 0 {
		return res, errors.New("no stock")
	}

	idx, found = indexMap["id"]
	if found && idx < len(record) {
		res.Card.Id = record[idx]
	}

	res.Card.Name = record[indexMap["cardName"]]
	idx, found = indexMap["edition"]
	if found && idx < len(record) {
		res.Card.Edition = record[idx]
	}

	idx, found = indexMap["variant"]
	if found && idx < len(record) {
		res.Card.Variation = record[idx]
	}

	var sku string
	idx, found = indexMap["sku"]
	if found && idx < len(record) {
		sku = strings.ToLower(record[idx])
	}
	var conditions string
	idx, found = indexMap["conditions"]
	if found && idx < len(record) {
		conditions = strings.ToLower(record[idx])
	}
	var printing string
	idx, found = indexMap["printing"]
	if found && idx < len(record) {
		printing = strings.ToLower(record[idx])
	}
	switch printing {
	case "y", "yes", "true", "t", "1", "x":
		res.Card.Foil = true
	default:
		variation := strings.ToLower(res.Card.Variation)
		if (strings.Contains(printing, "foil") && !strings.Contains(printing, "non")) ||
			(strings.Contains(conditions, "foil") && !strings.Contains(conditions, "non")) ||
			(strings.Contains(variation, "foil") && !strings.Contains(variation, "non")) ||
			strings.HasSuffix(conditions, "f") || // MPF
			strings.Contains(sku, "-f-") || strings.Contains(sku, "-fo-") {
			res.Card.Foil = true
		}
	}

	idx, found = indexMap["price"]
	if found && idx < len(record) {
		res.OriginalPrice, _ = mtgmatcher.ParsePrice(record[idx])
	}

	switch {
	case strings.Contains(conditions, "mint"), strings.Contains(conditions, "nm"):
		res.OriginalCondition = "NM"
	case strings.Contains(conditions, "light"), strings.Contains(conditions, "lp"),
		strings.Contains(conditions, "sp"), strings.Contains(conditions, "ex"):
		res.OriginalCondition = "SP"
	case strings.Contains(conditions, "moderately"), strings.Contains(conditions, "mp"), strings.Contains(conditions, "vg"):
		res.OriginalCondition = "MP"
	case strings.Contains(conditions, "heav"), strings.Contains(conditions, "hp"), strings.Contains(conditions, "good"):
		res.OriginalCondition = "HP"
	case strings.Contains(conditions, "poor"), strings.Contains(conditions, "damage"),
		strings.Contains(conditions, "po"), strings.Contains(conditions, "dmg"):
		res.OriginalCondition = "PO"
	}

	idx, found = indexMap["notes"]
	if found && idx < len(record) {
		notes := record[idx]
		if len(notes) > 1024 {
			notes = notes[:1024]
		}
		res.Notes = notes
	}

	cardId, err := mtgmatcher.Match(&res.Card)

	var alias *mtgmatcher.AliasingError
	if errors.As(err, &alias) {
		// Keep the most recent printing available in case of aliasing
		aliases := alias.Probe()
		sort.Slice(aliases, func(i, j int) bool {
			return sortSets(aliases[i], aliases[j])
		})
		cardId = aliases[0]
		res.MismatchAlias = true
	} else {
		res.MismatchError = err
	}
	res.CardId = cardId

	return res, nil
}

func loadHashes(hashes []string) ([]UploadEntry, error) {
	var uploadEntries []UploadEntry

	for i := range hashes {
		uploadEntries = append(uploadEntries, UploadEntry{
			CardId: hashes[i],
		})
	}

	return uploadEntries, nil
}

func loadCollection(link string, maxRows int) ([]UploadEntry, error) {
	if !strings.Contains(link, "/collection/view/") {
		return nil, errors.New("unsupported URL")
	}

	resp, err := cleanhttp.DefaultClient().Get(link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	var header []string
	doc.Find(`div[id="collectionContainer"] table thead`).Find("th").Each(func(i int, s *goquery.Selection) {
		header = append(header, s.Text())
	})

	indexMap, err := parseHeader(header)
	if err != nil {
		return nil, err
	}

	var uploadEntries []UploadEntry
	doc.Find(`div[id="collectionContainer"] table tbody`).Find("tr").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= maxRows {
			return false
		}

		var record []string
		s.Find("td").Each(func(i int, se *goquery.Selection) {
			record = append(record, se.Text())
		})

		res, err := parseRow(indexMap, record)
		if err != nil {
			return true
		}

		uploadEntries = append(uploadEntries, res)
		return true
	})

	return uploadEntries, nil
}

func loadSpreadsheet(urlPath string, maxRows int) ([]UploadEntry, error) {
	service := spreadsheet.NewServiceWithClient(GoogleDocsClient)

	hash := path.Base(strings.TrimSuffix(urlPath, "/edit"))
	spreadsheet, err := service.FetchSpreadsheet(hash)
	if err != nil {
		return nil, err
	}

	sheetIndex := 0
	for i := 0; i < len(spreadsheet.Sheets); i++ {
		if strings.Contains(strings.ToLower(spreadsheet.Sheets[i].Properties.Title), "mtgban") {
			sheetIndex = i
			break
		}
	}

	sheet, err := spreadsheet.SheetByIndex(uint(sheetIndex))
	if err != nil {
		return nil, err
	}

	if len(sheet.Rows) == 0 {
		return nil, errors.New("empty xls file")
	}

	record := make([]string, len(sheet.Rows[0]))
	for i := range record {
		record[i] = sheet.Rows[0][i].Value
	}

	var i int
	indexMap, err := parseHeader(record)
	if errors.Is(err, ErrUploadDecklist) || errors.Is(err, ErrReloadFirstRow) {
		i-- // Parse the first line again
	} else if err != nil {
		return nil, err
	}

	var uploadEntries []UploadEntry
	for {
		i++
		if i > maxRows || i >= len(sheet.Rows) {
			break
		} else if len(record) > len(sheet.Rows[i]) {
			var res UploadEntry
			res.MismatchError = errors.New("wrong number of fields")
			uploadEntries = append(uploadEntries, res)
			continue
		}

		for j := range record {
			record[j] = sheet.Rows[i][j].Value
		}

		res, err := parseRow(indexMap, record)
		if err != nil {
			continue
		}

		uploadEntries = append(uploadEntries, res)
	}

	return uploadEntries, nil
}

func loadOldXls(reader io.ReadSeeker, maxRows int) ([]UploadEntry, error) {
	f, err := xls.OpenReader(reader, "")
	if err != nil {
		return nil, err
	}

	// Search for the possible main sheet
	sheetIndex := 0
	for i := 0; i < f.NumSheets(); i++ {
		sheet := f.GetSheet(i)
		if sheet != nil && strings.Contains(strings.ToLower(sheet.Name), "mtgban") {
			sheetIndex = i
			break
		}
	}

	sheet := f.GetSheet(sheetIndex)
	if sheet == nil || sheet.MaxRow == 0 {
		return nil, errors.New("empty xls file")
	}

	record := make([]string, sheet.Row(0).LastCol())
	for i := range record {
		record[i] = sheet.Row(0).Col(i)
	}

	var i int
	indexMap, err := parseHeader(record)
	if errors.Is(err, ErrUploadDecklist) || errors.Is(err, ErrReloadFirstRow) {
		i-- // Parse the first line again
	} else if err != nil {
		return nil, err
	}

	var uploadEntries []UploadEntry
	for {
		i++
		if i > maxRows || i >= int(sheet.MaxRow) {
			break
		} else if len(record) > sheet.Row(i).LastCol() {
			var res UploadEntry
			res.MismatchError = errors.New("wrong number of fields")
			uploadEntries = append(uploadEntries, res)
			continue
		}

		for j := range record {
			record[j] = sheet.Row(i).Col(j)
		}

		res, err := parseRow(indexMap, record)
		if err != nil {
			continue
		}

		uploadEntries = append(uploadEntries, res)
	}

	return uploadEntries, nil
}

func loadXlsx(reader io.Reader, maxRows int) ([]UploadEntry, error) {
	f, err := excelize.OpenReader(reader)
	if err != nil {
		return nil, err
	}

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, errors.New("empty xlsx file")
	}

	// Search for the possible main sheet
	sheetIndex := 0
	for i, sheet := range sheets {
		if strings.Contains(strings.ToLower(sheet), "mtgban") {
			sheetIndex = i
			break
		}
	}

	// Get all the rows in the Sheet1.
	rows, err := f.GetRows(sheets[sheetIndex])
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errors.New("empty sheet")
	}

	var i int
	indexMap, err := parseHeader(rows[0])
	if errors.Is(err, ErrUploadDecklist) || errors.Is(err, ErrReloadFirstRow) {
		i-- // Parse the first line again
	} else if err != nil {
		return nil, err
	}

	var uploadEntries []UploadEntry
	for {
		i++
		if i > maxRows || i >= len(rows) {
			break
		} else if len(rows[i]) > len(rows[0]) {
			var res UploadEntry
			res.MismatchError = errors.New("wrong number of fields")
			uploadEntries = append(uploadEntries, res)
			continue
		}

		res, err := parseRow(indexMap, rows[i])
		if err != nil {
			continue
		}

		uploadEntries = append(uploadEntries, res)
	}

	return uploadEntries, nil
}

func loadCsv(reader io.ReadSeeker, comma rune, maxRows int) ([]UploadEntry, error) {
	csvReader := csv.NewReader(reader)
	csvReader.ReuseRecord = true
	csvReader.Comma = comma

	// In case we are not using a sane csv
	if comma != ',' {
		csvReader.LazyQuotes = true
	}

	// Load header
	first, err := csvReader.Read()
	if err == io.EOF {
		return nil, errors.New("empty input file")
	}
	if err != nil {
		log.Println("Error reading header:", err)
		return nil, errors.New("error reading file header")
	}
	log.Println("Found", len(first), "headers")

	// If there is a single element, parsing didn't work
	// try again with a different delimiter
	if len(first) == 1 && (comma == ',' || comma == '\t') {
		log.Println("Using a different delimiter for csv")
		_, err = reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		if comma == ',' {
			comma = '\t'
		} else if comma == '\t' {
			comma = ';'
		}
		return loadCsv(reader, comma, maxRows)
	}

	indexMap, err := parseHeader(first)
	if errors.Is(err, ErrUploadDecklist) || errors.Is(err, ErrReloadFirstRow) {
		// Reload reader to catch the first name too
		_, suberr := reader.Seek(0, io.SeekStart)
		if suberr != nil {
			return nil, suberr
		}

		// Rebuild the reader as previously used
		csvReader = csv.NewReader(reader)
		csvReader.ReuseRecord = true
		csvReader.Comma = comma
		if comma != ',' {
			csvReader.LazyQuotes = true
		}

		if errors.Is(err, ErrUploadDecklist) {
			csvReader.Comma = '§' // fake comma to parse the whole line
			csvReader.LazyQuotes = true
			csvReader.FieldsPerRecord = 1
		}
	} else if err != nil {
		return nil, err
	}

	var i int
	var uploadEntries []UploadEntry
	for {
		i++
		if i > maxRows {
			break
		}

		record, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			var res UploadEntry
			res.MismatchError = err
			uploadEntries = append(uploadEntries, res)
			continue
		}

		res, err := parseRow(indexMap, record)
		if err != nil {
			continue
		}

		// Tweak the message to the format from csv errors
		if res.MismatchError != nil {
			res.MismatchError = fmt.Errorf("record on line %d: %s", i+1, res.MismatchError.Error())
		}

		uploadEntries = append(uploadEntries, res)
	}

	return uploadEntries, nil
}
