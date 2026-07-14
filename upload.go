package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/extrame/xls"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/xuri/excelize/v2"
	"gopkg.in/Iwark/spreadsheet.v2"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/cardconduit"
	"github.com/mtgban/mtgban-website/internal/docparse"
	"github.com/mtgban/mtgban-website/moxfield"
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
	"TCGLow", "TCGMarket", "TCGDirect", "TCGDirectLow", "MKMLow", "MKMTrend",
}

// List of index prices to show by default (must be a subset of UploadIndexKeys)
var UploadIndexKeysPublic = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "MKMLow", "MKMTrend",
}

// List of index prices to use for CSVs
var UploadIndexKeysCSV = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "MKMLow", "MKMTrend",
}

// List of alternative prices sources
var UploadIndexComparePriceList = []string{
	"TCGLow", "TCGMarket", "TCGDirect", "CT", "CT0", "MKMLow", "MKMTrend",
}

// List of sealed index prices to show by default
var UploadSealedIndexKeysPublic = []string{
	"TCGLowEV", "TCGDirectNetEV", "TCGLowSim", "TCGDirectNetSim",
}

var ErrUploadDecklist = docparse.ErrDecklist
var ErrReloadFirstRow = docparse.ErrReloadFirstRow

// Data coming from the user upload
type UploadEntry = docparse.Entry

// uploadParser matches uploaded rows, wired to the site's logger, the
// TCGplayer SKU index, and the set-recency ordering for alias candidates.
var uploadParser = &docparse.Parser{
	Logf: func(format string, v ...any) {
		if logger := LogPages["Upload"]; logger != nil {
			logger.Printf(format, v...)
		}
	},
	TCGSkuToUUID:      tcgSKU2UUID,
	TCGSkuToCondition: tcgSKU2Condition,
	PreferredPrinting: sortSets,
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

// Checkbox options enabled by default in the settings UI when the
// preference cookie was never saved
var defaultUploadOpts = []string{"lowval", "lowvalabs", "minmargin", "customperc"}

// getUploadSetting returns the form value for field when it was submitted,
// otherwise the value of the cookie the upload settings are saved to, so
// that requests bypassing the upload form entirely (search transfers,
// shared remote links) behave the same way
func getUploadSetting(r *http.Request, field, cookieName string) string {
	if r.Form.Has(field) {
		return r.FormValue(field)
	}
	return readCookie(r, cookieName)
}

// uploadFloatSetting returns the form field (or cookie fallback) parsed as
// float64; 0 if missing or unparseable. Callers apply their own threshold
// guards (e.g. `if v := uploadFloatSetting(...); v > 0 { ... }`).
func uploadFloatSetting(r *http.Request, field, cookieName string) float64 {
	v, _ := strconv.ParseFloat(getUploadSetting(r, field, cookieName), 64)
	return v
}

// uploadIntSetting returns the form field (or cookie fallback) parsed as
// int; 0 if missing or unparseable.
func uploadIntSetting(r *http.Request, field, cookieName string) int {
	v, _ := strconv.Atoi(getUploadSetting(r, field, cookieName))
	return v
}

// hasUploadOpt reports whether a checkbox option was submitted with the
// form or, when absent, whether it is enabled in the preference cookie
func hasUploadOpt(r *http.Request, field string) bool {
	if r.Form.Has(field) {
		return r.FormValue(field) != ""
	}
	uploadOpts := defaultUploadOpts
	if optsRaw := readCookie(r, "UploadOptimizerOpts"); optsRaw != "" {
		uploadOpts = strings.Split(optsRaw, ",")
	}
	return slices.Contains(uploadOpts, field)
}

func Upload(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Upload", sig)

	// Maximum form size
	r.ParseMultipartForm(MaxUploadFileSize)

	// See if we need to download the ck csv only
	hashTag := r.FormValue("tag")
	switch hashTag {
	case "CK", "SCG", "SCGRetail", "TCG":
		hashes := r.Form[hashTag+"hashes"]
		hashesQtys := r.Form[hashTag+"hashesQtys"]
		hashesCond := r.Form[hashTag+"hashesCond"]

		if hashes != nil && hashTag == "SCGRetail" {
			log.Println("Preparing a mass-entry call to SCG")
			dataId, err := SCGRetailRedirect(r.Context(), hashes, hashesQtys, hashesCond)
			if err != nil {
				log.Println(err)
				pageVars.ErrorMessage = "Unable to forward data to SCG: " + err.Error()
				render(w, "upload.html", pageVars)
				return
			}
			log.Println("SCG dataId:", dataId)

			url := "https://goto.starcitygames.com/c/" + Config.Affiliate["SCG"] + `/3052179/37198/?u=https%3A%2F%2Fstarcitygames.com%2Fshop%2Fdeck-builder%2F%3Fdata%3D` + dataId
			http.Redirect(w, r, url, http.StatusFound)
			return
		}

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

	// Allow setting up a custom buylist
	canUploadCustom, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadCustom"))
	canUploadCustom = canUploadCustom || (DevMode && !SigCheck)

	// Enable optimizer customization
	var skipLowValue, skipLowValueAbs, skipHighValue, skipHighValueAbs bool
	var skipConds, skipPrices bool
	var useMargin bool
	var visualIndicator bool
	if blMode {
		skipLowValue = hasUploadOpt(r, "lowval")
		skipLowValueAbs = hasUploadOpt(r, "lowvalabs")
		skipHighValue = hasUploadOpt(r, "highval")
		skipHighValueAbs = hasUploadOpt(r, "highvalabs")
		useMargin = hasUploadOpt(r, "minmargin")
		skipConds = hasUploadOpt(r, "nocond")
		skipPrices = hasUploadOpt(r, "noprice")
		visualIndicator = hasUploadOpt(r, "customperc")
	}
	sorting := getUploadSetting(r, "sorting", "UploadSorting")

	percSpread := MinLowValueSpread
	if v := uploadFloatSetting(r, "percspread", "UploadPercSpread"); v > 0 {
		percSpread = v
	}

	percSpreadMax := MaxHighValueSpread
	if v := uploadFloatSetting(r, "percspreadmax", "UploadPercSpreadMax"); v > percSpread {
		percSpreadMax = v
	}

	minLowVal := MinLowValueAbs
	if v := uploadFloatSetting(r, "minval", "UploadMinVal"); v > 0 {
		minLowVal = v
	}

	maxHighVal := MaxHighValueAbs
	if v := uploadFloatSetting(r, "maxval", "UploadMaxVal"); v > minLowVal {
		maxHighVal = v
	}

	percMargin := 1.0
	if useMargin {
		if v := uploadFloatSetting(r, "margin", "UploadMargin"); v >= 0 {
			percMargin = 1 - v/100.0
		}
	}

	visualPerc := VisualPercSpread
	if v := uploadFloatSetting(r, "custompercmax", "UploadCustomPercMax"); v > 0 {
		visualPerc = v
	}
	pageVars.CanFilterByPrice = visualIndicator

	multiplier := 1
	if v := uploadIntSetting(r, "multiplier", "UploadMultiplier"); v > 1 {
		multiplier = v
	}

	// Cap each card's quantity to this maximum (0 = no cap)
	maxQty := 0
	if v := uploadIntSetting(r, "maxqty", "UploadMaxQty"); v > 0 {
		maxQty = v
	}

	// Set flags needed to show elements on the page ui
	pageVars.IsBuylist = blMode
	pageVars.CanBuylist = canBuylist
	pageVars.CanChangeStores = canChangeStores
	pageVars.CanUploadCustom = canUploadCustom

	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)
	var enabledStores []string
	var enabledSealedStores []string

	// Load all possible sellers and vendors according to user permissions.
	// Sellers skip MetadataOnly entries (no quantity/condition data to
	// optimize against); vendors don't apply that filter.
	singlesSellers := filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && !info.SealedMode &&
			!slices.Contains(blocklistRetail, info.Shorthand)
	})
	sealedSellers := filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && info.SealedMode &&
			!slices.Contains(Config.UploadSealedBlockList, info.Shorthand)
	})
	singlesVendors := filterVendors(func(info mtgban.ScraperInfo) bool {
		return !info.SealedMode &&
			!slices.Contains(blocklistBuylist, info.Shorthand)
	})
	sealedVendors := filterVendors(func(info mtgban.ScraperInfo) bool {
		return info.SealedMode &&
			!slices.Contains(Config.UploadSealedBlockList, info.Shorthand)
	})

	// Set the store names for the <select> box
	pageVars.SellerKeys = singlesSellers
	pageVars.VendorKeys = singlesVendors
	pageVars.SealedSellerKeys = sealedSellers
	pageVars.SealedVendorKeys = sealedVendors
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
	if len(enabledVendors) == 0 || !canChangeStores {
		pageVars.EnabledVendors = singlesVendors
	} else {
		pageVars.EnabledVendors = strings.Split(enabledVendors, "|")
	}

	enabledSealedSellers := readCookie(r, "enabledSealedSellers")
	if len(enabledSealedSellers) == 0 || !canChangeStores {
		pageVars.EnabledSealedSellers = sealedSellers
	} else {
		pageVars.EnabledSealedSellers = strings.Split(enabledSealedSellers, "|")
	}

	enabledSealedVendors := readCookie(r, "enabledSealedVendors")
	if len(enabledSealedVendors) == 0 || !canChangeStores {
		pageVars.EnabledSealedVendors = sealedVendors
	} else {
		pageVars.EnabledSealedVendors = strings.Split(enabledSealedVendors, "|")
	}

	cachedGdocURL := readCookie(r, "gdocURL")
	pageVars.RemoteLinkURL = cachedGdocURL

	// Filter out any unselected store from the full list
	stores := r.Form["stores"]
	sealedStores := r.Form["sealed_stores"]
	if blMode {
		// Override in case not allowed to change list
		if !canChangeStores {
			stores = singlesVendors
			sealedStores = sealedVendors
		}
		for _, store := range stores {
			if slices.Contains(singlesVendors, store) {
				enabledStores = append(enabledStores, store)
			}
		}
		for _, store := range sealedStores {
			if slices.Contains(sealedVendors, store) {
				enabledSealedStores = append(enabledSealedStores, store)
			}
		}

	} else {
		// Override in case not allowed to change list
		if !canChangeStores {
			stores = Config.AffiliatesList
			sealedStores = sealedSellers
		}
		for _, store := range stores {
			if slices.Contains(singlesSellers, store) {
				enabledStores = append(enabledStores, store)
			}
		}
		for _, store := range sealedStores {
			if slices.Contains(sealedSellers, store) {
				enabledSealedStores = append(enabledSealedStores, store)
			}
		}
	}

	// Make sure there are some enabled stores for direct access
	if len(stores) == 0 && len(enabledStores) == 0 {
		if blMode {
			enabledStores = pageVars.EnabledVendors
		} else {
			enabledStores = pageVars.EnabledSellers
		}
	}
	// Same as above, covering requests that carry no sealed_stores field
	// at all (hash transfers from search, gdocURL links)
	if len(sealedStores) == 0 && len(enabledSealedStores) == 0 {
		if blMode {
			enabledSealedStores = pageVars.EnabledSealedVendors
		} else {
			enabledSealedStores = pageVars.EnabledSealedSellers
		}
	}

	// Load a list of uuids from newspaper or search
	hashes := r.Form["hashes"]

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
	} else if textArea != "" {
		log.Printf("Loading freeform text area (%d bytes)", len(textArea))
	} else if gdocURL != "" {
		log.Printf("Loading spreadsheet: %+v", gdocURL)
	} else {
		log.Printf("Uploaded File: %+v", handler.Filename)
		log.Printf("File Size: %+v bytes", handler.Size)
		log.Printf("MIME Header: %+v", handler.Header)
	}
	log.Printf("Buylist mode: %+v", blMode)
	log.Printf("Enabled stores: %+v", enabledStores)
	if blMode {
		log.Printf("Sealed vendors: %+v", sealedVendors)
	} else {
		log.Printf("Sealed sellers: %+v", sealedSellers)
	}

	// Reset the cookie for this preference
	if len(hashes) == 0 && cachedGdocURL != gdocURL {
		setForeverCookie(w, "gdocURL", gdocURL)
		pageVars.RemoteLinkURL = gdocURL
	}

	// Save user preferred stores in cookies and make sure the page is updated with those
	if blMode {
		setForeverCookie(w, "enabledVendors", strings.Join(enabledStores, "|"))
		setForeverCookie(w, "enabledSealedVendors", strings.Join(enabledSealedStores, "|"))
		pageVars.EnabledVendors = enabledStores
		pageVars.EnabledSealedVendors = enabledSealedStores
	} else {
		setForeverCookie(w, "enabledSellers", strings.Join(enabledStores, "|"))
		setForeverCookie(w, "enabledSealedSellers", strings.Join(enabledSealedStores, "|"))
		pageVars.EnabledSellers = enabledStores
		pageVars.EnabledSealedSellers = enabledSealedStores
	}

	// Set upload limit
	maxRows := MaxUploadEntries

	// Load optional modes
	download, _ := strconv.ParseBool(r.FormValue("download"))
	estimate, _ := strconv.ParseBool(r.FormValue("estimate"))
	deckbox, _ := strconv.ParseBool(r.FormValue("deckbox"))
	tcgpCSV, _ := strconv.ParseBool(r.FormValue("tcgplayer_csv"))

	// Increase upload limit if allowed
	optimizerOpt, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadOptimizer"))
	increaseMaxRows := optimizerOpt || (DevMode && !SigCheck)
	if increaseMaxRows {
		maxRows = MaxUploadProEntries
	}
	// Allow a larger upload limit if set, if dev, or if it's an external call
	limitOpt, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadNoLimit"))
	uploadNoLimit := limitOpt || (DevMode && !SigCheck) || estimate || deckbox || tcgpCSV || (download && canBuylist)
	if uploadNoLimit {
		maxRows = MaxUploadTotalEntries
	}
	start := time.Now()

	// Load data
	var uploadedData []UploadEntry
	var uploadName string
	if len(hashes) != 0 {
		uploadedData, err = loadHashes(hashes, r.Form["hashesQtys"], r.Form["hashesCond"], r.Form["hashesPrice"])
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
				uploadedData, uploadName, err = loadCollection(r.Context(), gdocURL, maxRows)
			case "www.moxfield.com", "moxfield.com":
				uploadedData, uploadName, err = loadMoxfield(r.Context(), u.Path, maxRows)
			case "docs.google.com":
				uploadedData, uploadName, err = loadSpreadsheet(u.Path, maxRows)
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

	uploadedData = docparse.MergeIdenticalEntries(uploadedData)

	// Allow estimating on a separate page
	if estimate {
		var items []cardconduit.Item
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
			qty = adjustQty(qty, multiplier, maxQty)

			items = append(items, cardconduit.Item{
				ScryfallID: scryfallId,
				Condition:  cond,
				Quantity:   qty,
				IsFoil:     co.Foil,
				IsEtched:   co.Etched,
			})
		}

		link, err := cardconduit.SendEstimate(r.Context(), Config.Api["cardconduit"], items)
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
	if tcgpCSV && canBuylist {
		w.Header().Set("content-type", "text/csv")
		w.Header().Set("content-disposition", "attachment; filename=\"mtgban_tcgplayer.csv\"")
		csvWriter := csv.NewWriter(w)

		var ids, qtys, conds []string
		for i := range uploadedData {
			if uploadedData[i].CardId == "" {
				continue
			}

			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			qty = adjustQty(qty, multiplier, maxQty)

			ids = append(ids, uploadedData[i].CardId)
			qtys = append(qtys, fmt.Sprintf("%d", qty))
			conds = append(conds, uploadedData[i].OriginalCondition)
		}

		err = UUID2TCGCSV(csvWriter, ids, qtys, conds)
		if err != nil {
			w.Header().Del("Content-Type")
			UserNotify("upload", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "upload.html", pageVars)
		}
		return
	}

	var shouldCheckForConditions bool

	// Extract card Ids, separating sealed from singles
	var cardIds, sealedProductIds []string
	for i := range uploadedData {
		// Filter out empty ids
		if uploadedData[i].CardId == "" {
			continue
		}

		co, err := mtgmatcher.GetUUID(uploadedData[i].CardId)
		if err == nil && co.Sealed {
			sealedProductIds = append(sealedProductIds, uploadedData[i].CardId)
		} else {
			cardIds = append(cardIds, uploadedData[i].CardId)
		}

		// Check if conditions should be retrieved
		if uploadedData[i].OriginalCondition != "" {
			if skipConds {
				uploadedData[i].OriginalCondition = ""
			} else {
				shouldCheckForConditions = true
			}
		}
	}
	log.Printf("Card IDs: %d, Sealed product IDs: %d", len(cardIds), len(sealedProductIds))

	// Check not too many entries got uploaded
	if len(cardIds) >= maxRows {
		pageVars.InfoMessage = TooManyEntriesMessage
	}

	tagPref := "tags"
	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")
	priceSource := getUploadSetting(r, "pricesource", "UploadPriceSource")

	// Search — fetch card and sealed prices separately then merge
	var results map[string]map[string]*BanPrice
	var credits map[string]float64

	if blMode {
		// Only fetch singles prices when the upload actually has singles. A nil
		// or empty hash list is the "dump the whole inventory" signal to
		// getSellerPrices/getVendorPrices, so a sealed-only upload would
		// otherwise pull every enabled singles store's full catalog — spurious
		// empty singles columns plus a GetUUID-per-card dump. Guard it the same
		// way the sealed and index fetches below already do.
		results = map[string]map[string]*BanPrice{}
		if len(cardIds) > 0 {
			results = getVendorPrices("", enabledStores, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
		}

		// Build the custom buylist if requested
		customBuylist, _ := strconv.ParseBool(r.FormValue("custombuylist"))
		if !r.Form.Has("custombuylist") {
			customOpts := strings.Split(readCookie(r, "UploadCustomOpts"), ",")
			customBuylist = slices.Contains(customOpts, "enabled")
		}
		if canUploadCustom && customBuylist {
			var rule EntryRule
			if v := uploadFloatSetting(r, "customminprice", "UploadCustomMinPrice"); v > 0 {
				rule.MinPrice = v
			}
			if v := uploadFloatSetting(r, "customrate", "UploadCustomRate"); v > 0 {
				rule.Rate = v
			}

			customSeller := getUploadSetting(r, "customseller", "UploadCustomBuyer")
			if customSeller != "" {
				ref, _ := findSellerInventory(customSeller)
				for _, cardId := range cardIds {
					processEntry(results, ref[cardId], "", cardId, "CUSTOM", false, shouldCheckForConditions, false, rule)
				}
				enabledStores = append(enabledStores, "CUSTOM")
			}

			customSealedSeller := getUploadSetting(r, "customsealedseller", "UploadCustomSealedBuyer")
			if customSealedSeller != "" && len(sealedProductIds) > 0 && len(enabledSealedStores) > 0 {
				ref, _ := findSellerInventory(customSealedSeller)
				for _, productId := range sealedProductIds {
					processEntry(results, ref[productId], "", productId, "CUSTOM_SEALED", false, false, false, rule)
				}
				enabledSealedStores = append(enabledSealedStores, "CUSTOM_SEALED")
			}
		}

		// Fetch sealed vendor prices and merge
		if len(sealedProductIds) > 0 && len(enabledSealedStores) > 0 {
			sealedResults := getVendorPrices("", enabledSealedStores, "", sealedProductIds, "", false, false, true, tagPref)
			for cardId, stores := range sealedResults {
				if results[cardId] == nil {
					results[cardId] = map[string]*BanPrice{}
				}
				for store, price := range stores {
					results[cardId][store] = price
				}
			}
		}

		if priceSource != "" {
			credits = map[string]float64{}
			allStores := append(enabledStores, enabledSealedStores...)
			for _, store := range allStores {
				credits[store] = findCredit(store)
			}
		}
	} else {
		// Same guard as the buylist branch: skip the singles dump when the
		// upload has no singles (see the comment above).
		results = map[string]map[string]*BanPrice{}
		if len(cardIds) > 0 {
			results = getSellerPrices("", enabledStores, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
		}

		// Fetch sealed seller prices and merge
		if len(sealedProductIds) > 0 && len(enabledSealedStores) > 0 {
			sealedResults := getSellerPrices("", enabledSealedStores, "", sealedProductIds, "", false, false, true, tagPref)
			for cardId, stores := range sealedResults {
				if results[cardId] == nil {
					results[cardId] = map[string]*BanPrice{}
				}
				for store, price := range stores {
					results[cardId][store] = price
				}
			}
		}
	}

	// Allow downloading data as CSV
	if download && canBuylist {
		csvName := "mtgban_prices"
		if scope := r.FormValue("csvscope"); scope == "singles" || scope == "sealed" {
			csvName += "_" + scope
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+csvName+".csv\"")
		csvWriter := csv.NewWriter(w)

		// Search for all csv-specific indexes (skip the dump when there are no singles)
		indexResults := map[string]map[string]*BanPrice{}
		if len(cardIds) > 0 {
			indexResults = getSellerPrices("", UploadIndexKeysCSV, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
		}

		// Copy these index prices in the final results
		for _, cardId := range cardIds {
			for _, index := range UploadIndexKeysCSV {
				if results[cardId] == nil {
					results[cardId] = map[string]*BanPrice{}
				}
				results[cardId][index] = indexResults[cardId][index]
			}
		}

		err = SimplePrice2CSV(csvWriter, results, uploadedData, nil, preferFlavor)
		if err != nil {
			w.Header().Del("Content-Type")
			UserNotify("upload", err.Error())
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "upload.html", pageVars)
		}
		return
	}

	var indexKeys []string
	indexResults := map[string]map[string]*BanPrice{}

	// Choose the alternative reference pricing source when one is not loaded in
	altPriceSource := getUploadSetting(r, "altPrice", "UploadAltPrice")
	if !slices.Contains(UploadIndexComparePriceList, altPriceSource) {
		altPriceSource = UploadIndexKeys[0]
	}

	if len(cardIds) > 0 {
		indexKeys = UploadIndexKeys
		if !slices.Contains(indexKeys, altPriceSource) {
			indexKeys = append(indexKeys, altPriceSource)
		}
		indexResults = getSellerPrices("", indexKeys, "", cardIds, "", false, shouldCheckForConditions, false, tagPref)
	}

	// Build sealed index keys from MetadataOnly sealed sellers
	var sealedIndexKeys []string
	for _, seller := range GetSellers() {
		if seller == nil || !seller.Info().SealedMode || !seller.Info().MetadataOnly {
			continue
		}
		short := seller.Info().Shorthand
		if !slices.Contains(UploadSealedIndexKeysPublic, short) {
			continue
		}
		sealedIndexKeys = append(sealedIndexKeys, short)
	}

	// Fetch sealed index prices
	if len(sealedProductIds) > 0 && len(sealedIndexKeys) > 0 {
		sealedIndexResults := getSellerPrices("", sealedIndexKeys, "", sealedProductIds, "", false, false, true, tagPref)
		for cardId, stores := range sealedIndexResults {
			if indexResults[cardId] == nil {
				indexResults[cardId] = map[string]*BanPrice{}
			}
			for store, price := range stores {
				indexResults[cardId][store] = price
			}
		}
	}

	// Set card and sealed keys separately — the template picks per entry
	pageVars.IndexKeys = UploadIndexKeysPublic
	pageVars.ScraperKeys = enabledStores
	pageVars.AllScraperKeys = enabledStores
	if len(sealedProductIds) > 0 {
		pageVars.SealedIndexKeys = sealedIndexKeys
		pageVars.SealedScraperKeys = enabledSealedStores
		pageVars.AllScraperKeys = append(append([]string{}, enabledStores...), enabledSealedStores...)
	}

	// Orders implies priority of argument search
	pageVars.Metadata = map[string]GenericCard{}
	if len(hashes) != 0 {
		pageVars.UploadQuery = "hashes"
	} else if textArea != "" {
		pageVars.UploadQuery = "pasted text"
	} else if gdocURL != "" {
		// Show the source's own name when the loader could retrieve one,
		// and let the results header link back to it
		pageVars.UploadQuery = "remote URL"
		if uploadName != "" {
			pageVars.UploadQuery = uploadName
		}
		pageVars.UploadSourceURL = gdocURL
	} else {
		pageVars.UploadQuery = handler.Filename
	}
	pageVars.TotalEntries = map[string]float64{}

	pageVars.UploadEntries = uploadedData

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

		// Load metadata for alternative printings (used by pick-printing picker)
		for _, alias := range data.PossibleAliases {
			if _, exists := pageVars.Metadata[alias]; !exists {
				pageVars.Metadata[alias] = uuid2card(alias, true, false, preferFlavor)
			}
		}
	}

	var highestTotal float64
	var singlesHighest, sealedHighest float64

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

		// Pick the right store list for this entry
		isSealed := slices.Contains(sealedProductIds, cardId)
		entryStores := enabledStores
		if isSealed {
			entryStores = enabledSealedStores
		}

		// Search for any missing entries (ie cards not sold or bought by a vendor)
		for _, shorthand := range entryStores {
			_, found := results[cardId][shorthand]
			if !found {
				missingCounts[shorthand]++
				missingPrices[shorthand] += getPrice(indexResults[cardId]["TCGLow"], "")
			}
		}

		// Summary of the index entries. We pass the row's condition to
		// every index; getPrice handles the MetadataOnly sources
		// (TCGLow/TCGMarket/MKM*) by falling back to their flat price
		// while still using TCGDirect's per-condition listing.
		conds := uploadedData[i].OriginalCondition
		if skipConds {
			conds = ""
		}
		for indexKey, indexResult := range indexResults[cardId] {
			indexPrice := getPrice(indexResult, conds)

			if resultPrices[cardId+conds] == nil {
				resultPrices[cardId+conds] = map[string]float64{}
			}
			resultPrices[cardId+conds][indexKey] = indexPrice

			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}
			indexPrice *= float64(adjustQty(qty, multiplier, maxQty))
			pageVars.TotalEntries[indexKey] += indexPrice
		}

		// Quantity summary
		qty := 1
		if uploadedData[i].HasQuantity {
			qty = uploadedData[i].Quantity
		}
		adjusted := adjustQty(qty, multiplier, maxQty)
		pageVars.TotalQuantity += adjusted
		if isSealed {
			pageVars.SealedQuantity += adjusted
		} else {
			pageVars.SinglesQuantity += adjusted
		}

		// Run summaries for each vendor
		for shorthand, banPrice := range results[cardId] {
			conds := uploadedData[i].OriginalCondition
			if skipConds {
				conds = ""
			}
			price := getPrice(banPrice, conds)

			// Adjust for preferred price source
			if blMode {
				if priceSource == "credit" {
					price *= credits[shorthand]
				} else if priceSource == "marketCredit" {
					price *= credits[shorthand] * Config.BuylistMarketCredit[shorthand]
				}
			}

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
			price *= float64(adjustQty(qty, multiplier, maxQty))

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
			qty = adjustQty(qty, multiplier, maxQty)

			conds := uploadedData[i].OriginalCondition
			if skipConds {
				conds = ""
			}
			cardId := uploadedData[i].CardId

			// Load comparison price, either the loaded one or one of the alternatives
			comparePrice := 0.0
			if skipPrices {
				compareConds := ""
				prices := indexResults[cardId][altPriceSource]
				if slices.Index(indexKeys, altPriceSource) >= len(UploadIndexKeys) {
					compareConds = conds
				}

				// Normally index has no conditions to check, but the price might be coming
				// from a regular store (in which case we attempt to match it)
				comparePrice = getPrice(prices, compareConds)
			} else {
				comparePrice = uploadedData[i].OriginalPrice
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
					profitability = ((comparePrice - price) / (price + ProfitabilityConstant)) * math.Log10(1+factor)
					if qty > 1 {
						profitability *= math.Sqrt(float64(qty))
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
				if isSealed {
					sealedHighest += bestPrice
				} else {
					singlesHighest += bestPrice
				}
			}
		}

		// Avoid printing the credit conversion if the price source is already in store credit
		pageVars.CanFilterByPrice = priceSource == ""
	}

	sortResults(uploadedData, optimizedResults, sorting, preferFlavor)

	// Split sorted entries into singles, sealed, and not-found for the tabbed view
	singlesEntries, sealedEntries, notFoundEntries := docparse.PartitionEntries(uploadedData, sealedProductIds)
	pageVars.SinglesEntries = singlesEntries
	pageVars.SealedEntries = sealedEntries
	pageVars.NotFoundEntries = notFoundEntries
	pageVars.SinglesHighest = singlesHighest
	pageVars.SealedHighest = sealedHighest

	// Decide which result sub-tabs to show. The All tab appears only when both
	// actionable categories are present; the bar appears when more than one
	// section (singles, sealed, not-found) exists.
	hasSingles := len(singlesEntries) > 0
	hasSealed := len(sealedEntries) > 0
	hasNotFound := len(notFoundEntries) > 0
	sections := 0
	for _, present := range []bool{hasSingles, hasSealed, hasNotFound} {
		if present {
			sections++
		}
	}
	pageVars.ShowResultTabs = sections > 1
	pageVars.ShowAllTab = hasSingles && hasSealed
	switch {
	case pageVars.ShowAllTab:
		pageVars.DefaultResultView = "all"
	case hasSingles:
		pageVars.DefaultResultView = "singles"
	case hasSealed:
		pageVars.DefaultResultView = "sealed"
	default:
		pageVars.DefaultResultView = "notfound"
	}

	pageVars.MissingCounts = missingCounts
	pageVars.MissingPrices = missingPrices
	pageVars.ResultPrices = resultPrices

	// For the totals row: show all enabled card stores (even with "-"),
	// but only include sealed stores that actually returned prices.
	activeTotalStores := append([]string{}, enabledStores...)
	for _, key := range enabledSealedStores {
		if pageVars.TotalEntries[key] != 0 {
			activeTotalStores = append(activeTotalStores, key)
		}
	}
	pageVars.AllScraperKeys = activeTotalStores

	// Assign the resulting optimized data to the page variables
	if len(optimizedResults) > 0 {
		// When prices are ignored, the loaded price IS the alternate source, so
		// it can be linked directly; otherwise it's the user's uploaded price
		// and only a separate symbol should link out to the alternate source.
		pageVars.IgnorePrices = skipPrices
		pageVars.Optimized = optimizedResults
		// Only the stores that render a results section, in display order,
		// so that the template can link each section to the previous/next one
		for _, key := range activeTotalStores {
			if len(optimizedResults[key]) > 0 {
				pageVars.OptimizedKeys = append(pageVars.OptimizedKeys, key)
			}
		}
		pageVars.OptimizedTotals = optimizedTotals
		pageVars.HighestTotal = highestTotal
		uploadEditions := GetEditions()
		pageVars.Editions = uploadEditions.AllEditionsKeys
		pageVars.EditionsMap = uploadEditions.AllEditionsMap
	}

	// Logs
	user := GetParamFromSig(sig, "UserEmail")
	msgMode := "retail"
	if blMode {
		msgMode = "buylist"
	}
	msg := fmt.Sprintf("%s uploaded %d %s entries from %s, took %v", user, len(cardIds), msgMode, pageVars.UploadQuery, time.Since(start))
	UserNotify("upload", msg)
	LogPages["Upload"].Println(msg)

	// Touchdown!
	render(w, "upload.html", pageVars)
}

func sortResults(uploadedData []UploadEntry, optimizedResults map[string][]OptimizedUploadEntry, sorting string, preferFlavor bool) {
	switch sorting {
	case "highprice":
		sort.Slice(uploadedData, func(i, j int) bool {
			return uploadedData[i].OriginalPrice > uploadedData[j].OriginalPrice
		})

		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				return optimizedResults[store][i].BestPrice > optimizedResults[store][j].BestPrice
			})
		}
	case "alphabetical":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSetsAlphabetical(uploadedData[i].CardId, uploadedData[j].CardId, preferFlavor)
		})

		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				return sortSetsAlphabetical(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId, preferFlavor)
			})
		}
	case "setalpha":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSetsAlphabeticalSet(uploadedData[i].CardId, uploadedData[j].CardId, preferFlavor)
		})

		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				return sortSetsAlphabeticalSet(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId, preferFlavor)
			})
		}
	case "setchrono":
		sort.Slice(uploadedData, func(i, j int) bool {
			return sortSets(uploadedData[i].CardId, uploadedData[j].CardId)
		})

		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				return sortSets(optimizedResults[store][i].CardId, optimizedResults[store][j].CardId)
			})
		}
	case "highspread":
		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				return optimizedResults[store][i].Spread > optimizedResults[store][j].Spread
			})
		}
	case "profitability":
		for store := range optimizedResults {
			sort.Slice(optimizedResults[store], func(i, j int) bool {
				if optimizedResults[store][i].Spread < 0 || optimizedResults[store][j].Spread < 0 {
					return optimizedResults[store][i].Spread > optimizedResults[store][j].Spread
				}
				// Profitability is computed over the factor to the base price,
				// not the traditional spread, so the comparison is reversed.
				return optimizedResults[store][i].Profitability < optimizedResults[store][j].Profitability
			})
		}
	}
}

func getPrice(banPrice *BanPrice, conds string) float64 {
	if banPrice == nil {
		return 0
	}

	var price float64

	// Check sealed price first
	if banPrice.Sealed > 0 {
		return banPrice.Sealed
	}

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
		price = banPrice.Conditions.Get(conds)
		if price == 0 {
			price = banPrice.Conditions.Get(conds + "_foil")
			if price == 0 {
				price = banPrice.Conditions.Get(conds + "_etched")
			}
		}
		// MetadataOnly sources (TCGLow / TCGMarket / MKM*) never
		// populate Conditions — they carry a single flat price in
		// Regular/Foil/Etched. Fall back so a caller passing the
		// row's condition still gets that flat price instead of 0.
		// Sources that DO have per-condition data (real sellers and
		// vendors) keep the original "return 0 if this specific
		// condition isn't listed" semantic.
		if price == 0 && banPrice.Conditions == nil {
			price = banPrice.Regular
			if price == 0 {
				price = banPrice.Foil
				if price == 0 {
					price = banPrice.Etched
				}
			}
		}
	}

	return price
}

// Apply multiplier and max cap to a quantity
func adjustQty(qty, multiplier, maxQty int) int {
	qty *= multiplier
	if maxQty > 0 && qty > maxQty {
		qty = maxQty
	}
	return qty
}

func loadHashes(hashes, qtys, cond, prices []string) ([]UploadEntry, error) {
	var uploadEntries []UploadEntry

	for i := range hashes {
		entry := UploadEntry{
			CardId: hashes[i],
		}

		if len(qtys) > i {
			qty, err := strconv.Atoi(qtys[i])
			entry.HasQuantity = (err == nil)
			entry.Quantity = qty
		}

		if len(cond) > i {
			entry.OriginalCondition = cond[i]
		}

		if len(prices) > i {
			entry.OriginalPrice, _ = strconv.ParseFloat(prices[i], 64)
		}

		// Force a quantity to be set to avoid empty values in the UI
		if !entry.HasQuantity {
			entry.HasQuantity = true
			entry.Quantity = 1
		}

		uploadEntries = append(uploadEntries, entry)
	}

	return uploadEntries, nil
}

func loadMoxfield(ctx context.Context, link string, maxRows int) ([]UploadEntry, string, error) {
	var uploadEntries []UploadEntry

	deckID := path.Base(link)
	if deckID == "" {
		return nil, "", errors.New("invalid Moxfield deck URL")
	}

	// Build the request URL from the configured proxy base so the host
	// is provably the trusted config host, never user-influenced.
	// `link` is the path component of the user-submitted Moxfield URL;
	// require a clean absolute path so it can't inject a scheme or host
	// (e.g. via a leading "//" or an embedded "://").
	if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.Contains(link, "://") {
		return nil, "", errors.New("invalid Moxfield deck URL")
	}
	base, err := url.Parse(Config.Uploader["moxfield"])
	if err != nil {
		return nil, "", errors.New("invalid Moxfield uploader configuration")
	}
	base.Path = path.Join(base.Path, link)
	moxURL := base.String()

	items, deckName, err := moxfield.Load(ctx, moxURL, maxRows)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch Moxfield deck: %w", err)
	}

	for _, item := range items {
		cardId, err := resolveMoxItem(item)
		entry := UploadEntry{
			HasQuantity:       true,
			Quantity:          item.Quantity,
			CardId:            cardId,
			MismatchError:     err,
			OriginalPrice:     item.Price,
			OriginalCondition: item.Condition,
		}
		uploadEntries = append(uploadEntries, entry)
	}

	return uploadEntries, deckName, nil
}

// resolveMoxItem resolves a Moxfield item to a uuid. Most items carry a
// scryfall id; deck per-copy printings carry name plus set and collector
// number instead, resolved through the set catalog with the finish applied
// on top.
func resolveMoxItem(item moxfield.Item) (string, error) {
	if item.ScryfallID != "" {
		return mtgmatcher.MatchId(item.ScryfallID, item.IsFoil, item.IsEtched)
	}

	printings := mtgmatcher.MatchWithNumber(item.Name, strings.ToUpper(item.SetCode), item.Number)
	if len(printings) == 0 {
		return "", fmt.Errorf("unknown printing %s (%s) %s", item.Name, item.SetCode, item.Number)
	}
	return mtgmatcher.MatchId(printings[0].UUID, item.IsFoil, item.IsEtched)
}

func loadCollection(ctx context.Context, link string, maxRows int) ([]UploadEntry, string, error) {
	// Re-validate the URL locally rather than trusting the caller's host
	// switch: parse it here and require the exact TCGplayer store host so
	// the request target can't be pointed at an arbitrary (e.g. internal)
	// address. This also gives the static analyzer a sanitizer it can see.
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", errors.New("unsupported URL")
	}
	if u.Scheme != "https" || u.Host != "store.tcgplayer.com" {
		return nil, "", errors.New("unsupported URL")
	}
	if !strings.Contains(u.Path, "/collection/view/") {
		return nil, "", errors.New("unsupported URL")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, "", err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, "", err
	}

	// The page title names the collection ("<owner>'s Collection")
	collectionName := strings.TrimSpace(doc.Find("title").First().Text())
	if idx := strings.Index(collectionName, "|"); idx > 0 {
		collectionName = strings.TrimSpace(collectionName[:idx])
	}

	var header []string
	doc.Find(`div[id="collectionContainer"] table thead`).Find("th").Each(func(i int, s *goquery.Selection) {
		header = append(header, s.Text())
	})

	indexMap, err := uploadParser.ParseHeader(header)
	if err != nil {
		return nil, "", err
	}

	var uploadEntries []UploadEntry
	doc.Find(`div[id="collectionContainer"] table tbody`).Find("tr").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= maxRows {
			return false
		}

		record := make([]string, len(header))
		s.Find("td").Each(func(i int, se *goquery.Selection) {
			record[i] = se.Text()
		})

		// Look for the tcgplayer Id
		var tcgId string
		trId, _ := s.Attr("id")
		fields := strings.Split(trId, "_")
		if len(fields) > 1 {
			tcgId = fields[1]
		}

		// Override header map and save relevant fields
		if mtgmatcher.ExternalUUID(tcgId) != "" {
			record[5] = tcgId

			record[2] = "Normal"
			if strings.Contains(s.Find("td").Text(), "[Foil]") {
				record[2] = "Foil"
			}

			// Update map header
			indexMap["id"] = 5
			indexMap["printing"] = 2
		}

		res, err := uploadParser.ParseRow(indexMap, record)
		if err != nil {
			return true
		}

		uploadEntries = append(uploadEntries, res)
		return true
	})

	return uploadEntries, collectionName, nil
}

func loadSpreadsheet(urlPath string, maxRows int) ([]UploadEntry, string, error) {
	service := spreadsheet.NewServiceWithClient(GoogleDocsClient)

	hash := path.Base(strings.TrimSuffix(urlPath, "/edit"))
	spreadsheet, err := service.FetchSpreadsheet(hash)
	if err != nil {
		return nil, "", err
	}

	docName := spreadsheet.Properties.Title

	sheetIndex := 0
	for i := 0; i < len(spreadsheet.Sheets); i++ {
		if strings.Contains(strings.ToLower(spreadsheet.Sheets[i].Properties.Title), "mtgban") {
			sheetIndex = i
			break
		}
	}

	sheet, err := spreadsheet.SheetByIndex(uint(sheetIndex))
	if err != nil {
		return nil, "", err
	}

	if len(sheet.Rows) == 0 {
		return nil, "", errors.New("empty xls file")
	}

	record := make([]string, len(sheet.Rows[0]))
	for i := range record {
		record[i] = sheet.Rows[0][i].Value
	}

	var i int
	indexMap, err := uploadParser.ParseHeader(record)
	if errors.Is(err, ErrUploadDecklist) || errors.Is(err, ErrReloadFirstRow) {
		i-- // Parse the first line again
	} else if err != nil {
		return nil, "", err
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

		res, err := uploadParser.ParseRow(indexMap, record)
		if err != nil {
			continue
		}

		uploadEntries = append(uploadEntries, res)
	}

	return uploadEntries, docName, nil
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
	indexMap, err := uploadParser.ParseHeader(record)
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

		res, err := uploadParser.ParseRow(indexMap, record)
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
	indexMap, err := uploadParser.ParseHeader(rows[0])
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

		res, err := uploadParser.ParseRow(indexMap, rows[i])
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

	// Enabled for maximum compatibility
	csvReader.LazyQuotes = true
	csvReader.FieldsPerRecord = -1 // allow variable number of fields per row

	// Load header
	first, err := csvReader.Read()
	if err == io.EOF {
		return nil, errors.New("empty input file")
	}
	// Support non-standard separator metadata IN the file
	if len(first) == 1 && strings.Contains(first[0], "sep") {
		fields := strings.Split(first[0], "=")
		if len(fields) > 1 {
			csvReader.Comma = rune(fields[1][0])
		}
		// Re-read the header
		first, err = csvReader.Read()
	}
	if err != nil {
		LogPages["Upload"].Println("Error reading header:", err)
		return nil, errors.New("error reading file header")
	}
	LogPages["Upload"].Println("Found", len(first), "headers")

	// If there is a single element, parsing didn't work
	// try again with a different delimiter
	if len(first) == 1 && (comma == ',' || comma == '\t') {
		LogPages["Upload"].Println("Using a different delimiter for csv")
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

	indexMap, err := uploadParser.ParseHeader(first)
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

		res, err := uploadParser.ParseRow(indexMap, record)
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

// Redirect external URLs to the uploader (e.g. /https://store.tcgplayer.com/...)
// Go's ServeMux cleans // to / before the handler runs, so
// /https://host/path arrives as /https:/host/path
func UploadURLRedirect(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.RequestURI(), "/")
	log.Println(raw)
	// Restore the double slash that ServeMux cleaned
	raw = strings.Replace(raw, "https:/", "https://", 1)
	raw = strings.Replace(raw, "http:/", "http://", 1)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		http.Redirect(w, r, "/upload", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/upload?gdocURL="+url.QueryEscape(u.String()), http.StatusFound)
}
