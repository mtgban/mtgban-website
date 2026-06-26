package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

var ErrMissingTCGId = errors.New("tcg id not found")

func getLastSold(ctx context.Context, cardId string, anyLang bool) ([]tcgplayer.LatestSalesData, error) {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return nil, err
	}

	tcgId := findTCGproductId(cardId)
	if tcgId == "" {
		return nil, ErrMissingTCGId
	}

	latestSales, err := tcgplayer.LatestSales(ctx, tcgId, co.Foil || co.Etched, anyLang)
	if err != nil {
		return nil, err
	}

	// If we got an empty response, try again with all the possible languages
	if len(latestSales.Data) == 0 && !anyLang {
		return getLastSold(ctx, cardId, true)
	}

	return latestSales.Data, nil
}

func getDirectQty(ctx context.Context, cardId string) ([]tcgplayer.ListingData, error) {
	tcgProductId := findTCGproductId(cardId)
	if tcgProductId == "" {
		return nil, ErrMissingTCGId
	}

	tcgId, err := strconv.Atoi(tcgProductId)
	if err != nil {
		return nil, err
	}

	return tcgplayer.GetDirectQtysForProductId(ctx, tcgId, true), nil
}

func getDecklist(uuid string) ([]string, error) {
	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		return nil, err
	}

	return mtgmatcher.GetDecklist(co.SetCode, co.UUID)
}

func TCGHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	isLastSold := strings.Contains(r.URL.Path, "lastsold")
	isDirectQty := strings.Contains(r.URL.Path, "directqty")
	isDecklist := strings.Contains(r.URL.Path, "decklist")

	cardId := r.URL.Path
	cardId = strings.TrimPrefix(cardId, "/api/tcgplayer/lastsold/")
	cardId = strings.TrimPrefix(cardId, "/api/tcgplayer/directqty/")
	cardId = strings.TrimPrefix(cardId, "/api/tcgplayer/decklist/")

	var data any
	var err error
	var useCSV bool
	if isLastSold {
		UserNotify("tcgLastSold", cardId)
		data, err = getLastSold(r.Context(), cardId, false)
	} else if isDirectQty {
		UserNotify("tcgDirectQty", cardId)
		data, err = getDirectQty(r.Context(), cardId)
	} else if isDecklist {
		UserNotify("tcgDecklist", cardId)
		data, err = getDecklist(cardId)
		useCSV = true
	} else {
		err = errors.New("invalid endpoint")
	}
	if err != nil {
		log.Println(err)
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	if useCSV {
		co, _ := mtgmatcher.GetUUID(cardId)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+co.Name+".csv\"")

		csvWriter := csv.NewWriter(w)
		err = UUID2TCGCSV(csvWriter, data.([]string), nil, nil, true)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		return
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println(err)
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func UUID2CKCSV(w *csv.Writer, ids, qtys []string) error {
	buylist, err := findVendorBuylist("CK")
	if err != nil {
		return err
	}

	header := []string{"Title", "Edition", "Foil", "Quantity"}
	err = w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		name, found := blEntries[0].CustomFields["CKTitle"]
		if !found {
			continue
		}
		edition := blEntries[0].CustomFields["CKEdition"]
		finish := blEntries[0].CustomFields["CKFoil"]
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}

		err = w.Write([]string{name, edition, finish, quantity})
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

func UUID2SCGCSV(w *csv.Writer, ids, qtys []string) error {
	buylist, err := findVendorBuylist("SCG")
	if err != nil {
		return err
	}

	header := []string{"quantity", "productid", "name", "set_name", "language", "finish"}
	err = w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		productId := blEntries[0].CustomFields["scgSKU"]
		name := blEntries[0].CustomFields["SCGName"]
		edition := blEntries[0].CustomFields["SCGEdition"]
		language := blEntries[0].CustomFields["SCGLanguage"]
		finish := blEntries[0].CustomFields["SCGFinish"]
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}

		err = w.Write([]string{quantity, productId, name, edition, language, finish})
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

func SCGRetailRedirect(ctx context.Context, ids, qtys, conds []string) (string, error) {
	var data strings.Builder
	for i, hash := range ids {
		co, err := mtgmatcher.GetUUID(hash)
		if err != nil {
			continue
		}
		sku := findInstanceId("SCG", hash, conds[i])

		data.WriteString(qtys[i])
		data.WriteString(" ")
		data.WriteString(co.Name)
		data.WriteString(" [sku: '")
		data.WriteString(sku)
		data.WriteString("']||")
	}

	var requestPayload struct {
		Redirect bool   `json:"redirect"`
		Data     string `json:"data"`
	}
	requestPayload.Data = data.String()

	payload, err := json.Marshal(requestPayload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.starcitygames.com/ajax/affiliate", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-KEY", Config.Api["scg_mass_entry"])

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var responsePayload struct {
		AffiliateDataId string `json:"affiliateDataId"`
	}
	err = json.NewDecoder(resp.Body).Decode(&responsePayload)
	if err != nil {
		return "", err
	}

	return responsePayload.AffiliateDataId, nil
}

var tcgcsvHeader = []string{
	"TCGplayer Id",
	"Product Line",
	"Set Name",
	"Product Name",
	"Title",
	"Number",
	"Rarity",
	"Condition",
	"TCG Market Price",
	"TCG Direct Low",
	"TCG Low Price With Shipping",
	"TCG Low Price",
	"Total Quantity",
	"Add to Quantity",
	"TCG Marketplace Price",
	"Photo URL",
}

var tcgConditionMap = map[string]string{
	"NM": "Near Mint",
	"SP": "Lightly Played",
	"MP": "Moderately Played",
	"HP": "Heavily Played",
	"PO": "Damaged",
}

// Convert a slice of ids (BAN uuids) to a list of TCG product SKUs on a CSV
//
// If present, qtys and conds need to be the same size of ids.
// If absent, quantity will be computed on the fly and entries will be merged
// in a single entry (tcgplayer does not support csv operations with identical
// items) and conditions will be set to NM.
// UUID2TCGCSV writes a TCGplayer-importable CSV. The edition and display-name
// columns are normally left blank: TCGplayer skips its name-match check when
// they're empty, and our names don't always match theirs exactly (see commit
// 1e39d5d). Pass withNames=true to restore them — used by the decklist
// endpoint, where the human-readable name/edition is wanted in the output.
func UUID2TCGCSV(w *csv.Writer, ids, qtys, conds []string, withNames bool) error {
	market, err := findSellerInventory("TCGPlayer")
	if err != nil {
		return err
	}
	direct, _ := findSellerInventory("TCGDirectLow")
	low, _ := findSellerInventory("TCGLow")
	sealed, _ := findSellerInventory("TCGSealed")

	err = w.Write(tcgcsvHeader)
	if err != nil {
		return err
	}

	// Track total quantity, and skip repeats
	qty := map[string]int{}
	var cleanedIds []string
	for i, id := range ids {
		quantity := 1
		if qtys != nil {
			q, err := strconv.Atoi(qtys[i])
			if err == nil {
				quantity = q
			}
		}
		cond := "NM"
		if conds != nil && conds[i] != "" {
			cond = conds[i]
		}
		qty[id+cond] += quantity

		if slices.Contains(cleanedIds, id) {
			continue
		}
		cleanedIds = append(cleanedIds, id)
	}

	for i, id := range cleanedIds {
		var prices [3]float64

		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			continue
		}

		cond := "NM"
		if conds != nil && conds[i] != "" && !co.Sealed {
			cond = conds[i]
		}

		var tcgSkuId string
		if co.Sealed {
			tcgSkuId = findInstanceId("TCGSealed", id, cond)
			for _, entry := range sealed[id] {
				prices[0] = entry.Price
				break
			}
		} else {
			tcgSkuId = findInstanceId("TCGPlayer", id, cond)
			for j, inv := range []mtgban.InventoryRecord{market, direct, low} {
				for _, entry := range inv[id] {
					if entry.Conditions == cond {
						prices[j] = entry.Price
						break
					}
				}
			}
		}

		condLong := tcgConditionMap[cond]
		if co.Foil || co.Etched {
			condLong += " Foil"
		}

		record := make([]string, 0, len(tcgcsvHeader))

		record = append(record, tcgSkuId)
		switch Config.Game {
		case "magic":
			record = append(record, "Magic")
		case "lorcana":
			record = append(record, "Lorcana")
		default:
			panic("not implemented")
		}
		if withNames {
			record = append(record, co.Edition)
			record = append(record, co.Name)
		} else {
			record = append(record, "")
			record = append(record, "")
		}
		record = append(record, "")
		record = append(record, co.Number)
		record = append(record, strings.ToUpper(co.Rarity[:1]))
		record = append(record, condLong)
		record = append(record, fmt.Sprintf("%0.2f", prices[0]))
		record = append(record, fmt.Sprintf("%0.2f", prices[1]))
		record = append(record, "")
		record = append(record, fmt.Sprintf("%0.2f", prices[2]))
		record = append(record, "")
		record = append(record, fmt.Sprint(qty[id+cond]))
		record = append(record, fmt.Sprintf("%0.2f", prices[0]))
		record = append(record, "")

		err = w.Write(record)
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

func MKMHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	isDecklist := strings.Contains(r.URL.Path, "decklist")

	cardId := r.URL.Path
	cardId = strings.TrimPrefix(cardId, "/api/cardmarket/decklist/")

	var data any
	var err error
	var useCSV bool
	if isDecklist {
		UserNotify("mkmDecklist", cardId)
		data, err = getDecklist(cardId)
		useCSV = true
	} else {
		err = errors.New("invalid endpoint")
	}
	if err != nil {
		log.Println(err)
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	if useCSV {
		co, _ := mtgmatcher.GetUUID(cardId)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+co.Name+".csv\"")

		csvWriter := csv.NewWriter(w)
		err = UUID2MKMCSV(csvWriter, data.([]string), nil, nil)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		return
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println(err)
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
}

var mkmcsvHeader = []string{
	"cardmarketId",
	"quantity",
	"name",
	"set",
	"setCode",
	"cn",
	"condition",
	"language",
	"isFoil",
	"isPlayset",
	"isSigned",
	"price",
	"comment",
	"nameDE",
	"nameES",
	"nameFR",
	"nameIT",
	"rarity",
	"listedAt",
}

var mkmConditionMap = map[string]string{
	"NM": "NM",
	"SP": "EX",
	"MP": "GD",
	"HP": "HP",
	"PO": "PO",
}

// Convert a slice of ids (BAN uuids) to a list of TCG product SKUs on a CSV
//
// If present, qtys and conds need to be the same size of ids.
// If absent, quantity will be computed on the fly and entries will be merged
// in a single entry (tcgplayer does not support csv operations with identical
// items) and conditions will be set to NM.
func UUID2MKMCSV(w *csv.Writer, ids, qtys, conds []string) error {
	trend, _ := findSellerInventory("MKMTrend")
	low, _ := findSellerInventory("MKMLow")

	err := w.Write(mkmcsvHeader)
	if err != nil {
		return err
	}

	// Track total quantity, and skip repeats
	qty := map[string]int{}
	var cleanedIds []string
	for i, id := range ids {
		quantity := 1
		if qtys != nil {
			q, err := strconv.Atoi(qtys[i])
			if err == nil {
				quantity = q
			}
		}
		cond := "NM"
		if conds != nil && conds[i] != "" {
			cond = conds[i]
		}
		qty[id+cond] += quantity

		if slices.Contains(cleanedIds, id) {
			continue
		}
		cleanedIds = append(cleanedIds, id)
	}

	for i, id := range cleanedIds {
		cond := "NM"
		if conds != nil && conds[i] != "" {
			cond = conds[i]
		}

		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			continue
		}

		mkmId := findOriginalId("MKMTrend", id)
		if mkmId == "" {
			mkmId = findOriginalId("MKMLow", id)
		}

		var price float64
		entries, found := trend[id]
		if !found {
			entries, found = low[id]
		}
		if found {
			price = entries[0].Price
		}

		foil := ""
		if co.Foil || co.Etched {
			foil = "Y"
		}

		record := make([]string, 0, len(mkmcsvHeader))

		record = append(record, mkmId)
		record = append(record, fmt.Sprint(qty[id+cond]))
		record = append(record, co.Name)
		record = append(record, co.Edition)
		record = append(record, co.SetCode)
		record = append(record, co.Number)
		record = append(record, mkmConditionMap[cond])
		record = append(record, co.Language)
		record = append(record, foil)
		record = append(record, "") //isPlayset
		record = append(record, "") //isSigned
		record = append(record, fmt.Sprintf("%0.2f", price))
		record = append(record, "") //comment
		record = append(record, "")
		record = append(record, "")
		record = append(record, "")
		record = append(record, "")
		record = append(record, mtgmatcher.Title(co.Rarity))
		record = append(record, "") //listedAt

		err = w.Write(record)
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

type OpenSearchDescriptionType struct {
	XMLName       xml.Name          `xml:"OpenSearchDescription"`
	Text          string            `xml:",chardata"`
	Xmlns         string            `xml:"xmlns,attr"`
	ShortName     string            `xml:"ShortName"`
	Description   string            `xml:"Description"`
	Language      string            `xml:"Language"`
	InputEncoding string            `xml:"InputEncoding"`
	Tags          string            `xml:"Tags"`
	Image         []OpenSearchImage `xml:"Image"`
	URL           []OpenSearchURL   `xml:"Url"`
}

type OpenSearchImage struct {
	Text   string `xml:",chardata"`
	Width  string `xml:"width,attr"`
	Height string `xml:"height,attr"`
	Type   string `xml:"type,attr"`
}
type OpenSearchURL struct {
	Text     string `xml:",chardata"`
	Method   string `xml:"method,attr,omitempty"`
	Rel      string `xml:"rel,attr"`
	Type     string `xml:"type,attr"`
	Template string `xml:"template,attr"`
}

func OpenSearchDesc(w http.ResponseWriter, r *http.Request) {
	host := Config.Game
	gameName := mtgmatcher.Title(Config.Game)

	images := []OpenSearchImage{
		{
			Text:   "https://mtgban.com/img/favicon/favicon.ico",
			Width:  "32",
			Height: "32",
			Type:   "image/x-icon",
		},
		{
			Text:   "https://mtgban.com/img/favicon/apple-touch-icon.png",
			Width:  "120",
			Height: "120",
			Type:   "image/png",
		},
	}

	urls := []OpenSearchURL{
		{
			Method:   "get",
			Rel:      "results",
			Type:     "text/html",
			Template: "https://" + host + ".mtgban.com/search?q={searchTerms}",
		},
		{
			Rel:      "self",
			Type:     "application/opensearchdescription+xml",
			Template: "https://" + host + ".mtgban.com/api/opensearch.xml",
		},
		{
			Rel:      "suggestions",
			Type:     "application/json",
			Template: "http://" + host + ".mtgban.com/api/suggest?q={searchTerms}",
		},
	}

	openSearchDescription := OpenSearchDescriptionType{
		Xmlns:         "http://a9.com/-/spec/opensearch/1.1/",
		ShortName:     "MTGBAN Price Search",
		Description:   "Search MTGBAN for " + gameName + " prices",
		Language:      "en",
		InputEncoding: "UTF-8",
		Tags:          "MTGBAN " + gameName + " Price Search",
		Image:         images,
		URL:           urls,
	}

	xml.NewEncoder(w).Encode(&openSearchDescription)
}

func SearchAPI(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	if sig == "" {
		sig = r.FormValue("sig")
	}

	out := PriceAPIOutput{}
	out.Meta.Date = time.Now()
	out.Meta.Version = APIVersion
	out.Meta.BaseURL = ServerURL + "/go/"

	isJSON := strings.HasSuffix(r.URL.Path, ".json")
	isCSV := strings.HasSuffix(r.URL.Path, ".csv")

	// Only allow JSON from a different (protected) endpoint
	if isJSON && !strings.HasPrefix(r.URL.Path, "/api/mtgban/search/") {
		pageVars := genPageNav("Error", sig)
		pageVars.Title = "Unauthorized"
		pageVars.ErrorMessage = "Invalid endpoint for JSON"
		render(w, "home.html", pageVars)
		return
	}

	// Load whether a user can download CSV and validate the query parameter
	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	if isCSV && !canDownloadCSV {
		pageVars := genPageNav("Error", sig)
		pageVars.Title = "Unauthorized"
		pageVars.ErrorMessage = "Unable to download CSV"
		render(w, "home.html", pageVars)
		return
	}

	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	// Expand blocklist as needed
	skipSellersOpt := readCookie(r, "SearchSellersList")
	if skipSellersOpt != "" {
		blocklistRetail = append(blocklistRetail, strings.Split(skipSellersOpt, ",")...)
	}
	skipVendorsOpt := readCookie(r, "SearchVendorsList")
	if skipVendorsOpt != "" {
		blocklistBuylist = append(blocklistBuylist, strings.Split(skipVendorsOpt, ",")...)
	}

	isRetail := strings.Contains(r.URL.Path, "/retail/")
	isBuylist := strings.Contains(r.URL.Path, "/buylist/")
	isSealed := strings.Contains(r.URL.Path, "/sealed/")

	query := path.Base(r.URL.Path)
	query = strings.TrimSuffix(query, ".json")
	query = strings.TrimSuffix(query, ".csv")

	// Load some defaults
	enabledModes := strings.Split(GetParamFromSig(sig, "APImode"), ",")
	if enabledModes[0] == "" {
		enabledModes[0] = "all"
	}
	idOpt := r.FormValue("id")
	if idOpt == "" {
		idOpt = "scryfall"
	}
	tagName := r.FormValue("tag")
	if tagName == "" {
		tagName = "names"
	}

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	config := parseSearchOptionsNG(query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	if isSealed {
		config.SearchMode = "sealed"
		idOpt = "mtgjson"
	}

	// Perform search
	allKeys, _ := searchAndFilter(config)

	// Sort results to match the search page order
	sortOpt := r.FormValue("sort")
	switch sortOpt {
	case "alpha":
		sort.Slice(allKeys, func(i, j int) bool {
			return sortSetsAlphabetical(allKeys[i], allKeys[j], false)
		})
	case "number":
		sort.Slice(allKeys, func(i, j int) bool {
			return sortByNumberAndFinish(allKeys[i], allKeys[j], false)
		})
	default:
		sort.Slice(allKeys, func(i, j int) bool {
			return sortSets(allKeys[i], allKeys[j])
		})
	}
	reverseSort, _ := strconv.ParseBool(r.FormValue("reverse"))
	if reverseSort {
		for i, j := 0, len(allKeys)-1; i < j; i, j = i+1, j-1 {
			allKeys[i], allKeys[j] = allKeys[j], allKeys[i]
		}
	}

	// Limit results to be processed
	if len(allKeys) > MaxSearchTotalResults {
		allKeys = allKeys[:MaxSearchTotalResults]
	}

	canRetail := canAccessMode(enabledModes, "retail")
	canBuylist := canAccessMode(enabledModes, "buylist")

	// Build store lists
	var enabledRetailStores []string
	for _, seller := range GetSellers() {
		if seller != nil && !slices.Contains(blocklistRetail, seller.Info().Shorthand) {
			enabledRetailStores = append(enabledRetailStores, seller.Info().Shorthand)
		}
	}
	var enabledBuylistStores []string
	for _, vendor := range GetVendors() {
		if vendor != nil && !slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
			enabledBuylistStores = append(enabledBuylistStores, vendor.Info().Shorthand)
		}
	}

	// Retrieve prices
	if isRetail && canRetail {
		stores := enabledRetailStores
		if sig == "" && isJSON {
			stores = Config.ApiDemoStores
		}
		out.Retail = getSellerPrices(idOpt, stores, "", allKeys, "", true, true, isSealed, tagName)
	}
	if isBuylist && canBuylist {
		stores := enabledBuylistStores
		if sig == "" && isJSON {
			stores = Config.ApiDemoStores
		}
		out.Buylist = getVendorPrices(idOpt, stores, "", allKeys, "", true, true, isSealed, tagName)
	}

	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&out)
		return
	}

	if isCSV {
		w.Header().Set("Content-Type", "text/csv")

		// Re-fetch prices keyed by BAN UUID so foil/nonfoil stay separate
		var results map[string]map[string]*BanPrice
		if isRetail && canRetail {
			results = getSellerPrices("", enabledRetailStores, "", allKeys, "", true, true, isSealed, tagName)
		} else if isBuylist && canBuylist {
			results = getVendorPrices("", enabledBuylistStores, "", allKeys, "", true, true, isSealed, tagName)
		}

		err := BanPrice2CSV(w, results, allKeys)
		if err != nil {
			w.Header().Del("Content-Type")
			w.Header().Del("Content-Disposition")
			UserNotify("search", err.Error())
			pageVars := genPageNav("Error", sig)
			pageVars.Title = "Error"
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "home.html", pageVars)
			return
		}
		return
	}
}

func LoadFromCloud(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path
	name = strings.TrimPrefix(name, "/api/load/")

	if GetParamFromSig(r.FormValue("sig"), "API") != name {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}

	config := Config.ScraperConfig
	scrapersConfig, found := config.Config[name]
	if !found {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}

	for kind, list := range scrapersConfig {
		for _, shorthand := range list {
			err := loadScraper(DataBucket, config.BucketPath, Config.Game, name, kind, shorthand, config.BucketFileFormat)
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}

	ServerNotify("reload", "Server reloaded "+name)
	w.Write([]byte(`{"status": "ok"}`))
}

func LoadDatastoreFromCloud(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := verify(r)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = loadDatastore(Config.DatastorePath)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to reload datastore: "+err.Error())
		return
	}

	ServerNotify("reload", "Datastore reloaded from "+Config.DatastorePath)
	w.Write([]byte(`{"status": "ok"}`))
}

// Simple function to check a simple signature, the body is just the timestamp
func verify(r *http.Request) error {
	defer r.Body.Close()

	sig := r.Header.Get("X-Signature")
	ts := r.Header.Get("X-Timestamp")
	if sig == "" || ts == "" {
		return errors.New("bad headers")
	}

	// Reject old requests (e.g., > 1 minute)
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(t, 0)) > 1*time.Minute {
		return errors.New("expired")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(os.Getenv("BAN_SECRET")))
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return errors.New("unauthorized")
	}

	return nil
}
