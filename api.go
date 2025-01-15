package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/cardkingdom"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"golang.org/x/exp/slices"
)

type ckMeta struct {
	Id  int    `json:"id,omitempty"`
	URL string `json:"url,omitempty"`
}

type ck2id struct {
	Normal *ckMeta `json:"normal,omitempty"`
	Foil   *ckMeta `json:"foil,omitempty"`
	Etched *ckMeta `json:"etched,omitempty"`
}

var CKAPIMutex sync.RWMutex
var CKAPIOutput map[string]*ck2id
var CKAPIData []cardkingdom.CKCard

func CKMirrorAPI(w http.ResponseWriter, r *http.Request) {
	var pricelist struct {
		Data []cardkingdom.CKCard `json:"list"`
	}
	pricelist.Data = CKAPIData

	err := json.NewEncoder(w).Encode(&pricelist)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}
}

func prepareCKAPI() error {
	ServerNotify("api", "CK APIrefresh started")

	list, err := cardkingdom.NewCKClient().GetPriceList()
	if err != nil {
		log.Println(err)
		return err
	}
	CKAPIData = list

	// Backup option for stashing CK data
	rdbRT := ScraperOptions["cardkingdom"].RDBs["retail"]
	rdbBL := ScraperOptions["cardkingdom"].RDBs["buylist"]
	key := time.Now().Format("2006-01-02")

	output := map[string]*ck2id{}

	var skipRedis bool
	for _, card := range list {
		theCard, err := cardkingdom.Preprocess(card)
		if err != nil {
			continue
		}

		cardId, err := mtgmatcher.Match(theCard)
		if err != nil {
			continue
		}

		if card.SellQuantity > 0 && !skipRedis {
			// We use Set for retail because prices are more accurate
			err = rdbRT.HSet(context.Background(), cardId, key, card.SellPrice).Err()
			if err != nil {
				log.Printf("redis error for %s: %s", cardId, err)
				skipRedis = true
			}
		}
		if card.BuyQuantity > 0 && !skipRedis {
			err = rdbBL.HSetNX(context.Background(), cardId, key, card.BuyPrice).Err()
			if err != nil {
				log.Printf("redis error for %s: %s", cardId, err)
				skipRedis = true
			}
		}

		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			continue
		}

		id, found := co.Identifiers["mtgjsonId"]
		if !found {
			continue
		}

		// Allocate memory
		_, found = output[id]
		if !found {
			output[id] = &ck2id{}
		}

		// Set data as needed
		data := &ckMeta{
			Id:  card.Id,
			URL: "https://www.cardkingdom.com/" + card.URL,
		}
		if co.Etched {
			output[id].Etched = data
		} else if co.Foil {
			output[id].Foil = data
		} else {
			output[id].Normal = data
		}
	}

	CKAPIMutex.Lock()
	CKAPIOutput = output
	CKAPIMutex.Unlock()

	ServerNotify("api", "CK API refresh completed")

	return nil
}

func API(w http.ResponseWriter, r *http.Request) {
	sig := r.FormValue("sig")

	param := GetParamFromSig(sig, "API")
	canAPI := strings.Contains(param, "CK")
	if SigCheck && !canAPI {
		w.Write([]byte(`{"error": "invalid signature"}`))
		return
	}

	CKAPIMutex.RLock()
	defer CKAPIMutex.RUnlock()
	if CKAPIOutput == nil {
		log.Println("CK API called when list was empty")
		w.Write([]byte(`{"error": "empty list"}`))
		return
	}
	outputMap := CKAPIOutput

	// Only scryfall and mtgjson ids are supported due to the unification of finishes
	// mtgjson is the default, perform a key conversion if scryfall is requested
	idMode := r.FormValue("id")
	if idMode == "scryfall" {
		altMap := map[string]*ck2id{}
		for uuid, meta := range CKAPIOutput {
			co, err := mtgmatcher.GetUUID(uuid)
			if err != nil {
				continue
			}
			id := getIdFunc(idMode)(co)
			altMap[id] = meta
		}
		outputMap = altMap
	}

	err := json.NewEncoder(w).Encode(outputMap)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}
}

var ErrMissingTCGId = errors.New("tcg id not found")

func getLastSold(cardId string) ([]tcgplayer.LatestSalesData, error) {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return nil, err
	}

	tcgId := findTCGproductId(cardId)
	if tcgId == "" {
		return nil, ErrMissingTCGId
	}

	latestSales, err := tcgplayer.LatestSales(tcgId, co.Foil || co.Etched)
	if err != nil {
		return nil, err
	}

	// If we got an empty response, try again with all the possible languages
	if len(latestSales.Data) == 0 {
		latestSales, err = tcgplayer.LatestSales(tcgId, co.Foil || co.Etched, true)
		if err != nil {
			return nil, err
		}
	}

	return latestSales.Data, nil
}

func getDrirectQty(cardId string) ([]tcgplayer.ListingData, error) {
	tcgProductId := findTCGproductId(cardId)
	if tcgProductId == "" {
		return nil, ErrMissingTCGId
	}

	tcgId, err := strconv.Atoi(tcgProductId)
	if err != nil {
		return nil, err
	}

	return tcgplayer.GetDirectQtysForProductId(tcgId, true), nil
}

func tcgDecklist(uuid string) ([]string, error) {
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
		data, err = getLastSold(cardId)
	} else if isDirectQty {
		UserNotify("tcgDirectQty", cardId)
		data, err = getDrirectQty(cardId)
	} else if isDecklist {
		UserNotify("tcgDecklist", cardId)
		data, err = tcgDecklist(cardId)
		useCSV = true
	} else {
		err = errors.New("invalid endpoint")
	}
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	if useCSV {
		co, _ := mtgmatcher.GetUUID(cardId)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+co.Name+".csv\"")

		csvWriter := csv.NewWriter(w)
		err = UUID2TCGCSV(csvWriter, data.([]string), nil, nil)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error": "` + err.Error() + `"}`))
			return
		}
		return
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
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

	header := []string{"name", "set_name", "language", "finish", "quantity"}
	err = w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		name, found := blEntries[0].CustomFields["SCGName"]
		if !found {
			continue
		}
		edition := blEntries[0].CustomFields["SCGEdition"]
		language := blEntries[0].CustomFields["SCGLanguage"]
		finish := blEntries[0].CustomFields["SCGFinish"]
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}

		err = w.Write([]string{name, edition, language, finish, quantity})
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
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
func UUID2TCGCSV(w *csv.Writer, ids, qtys, conds []string) error {
	market, err := findSellerInventory("TCGPlayer")
	if err != nil {
		return err
	}
	direct, _ := findSellerInventory("TCGDirectLow")
	low, _ := findSellerInventory("TCGLow")

	err = w.Write(tcgcsvHeader)
	if err != nil {
		return err
	}

	// Track total quantity, and skip repeats
	qty := map[string]int{}
	for i, id := range ids {
		quantity := 1
		if qtys != nil {
			q, err := strconv.Atoi(qtys[i])
			if err == nil {
				quantity = q
			}
		}
		cond := "NM"
		if conds != nil {
			cond = conds[i]
		}
		qty[id+cond] += quantity
	}

	for i, id := range ids {
		var prices [3]float64

		cond := "NM"
		if conds != nil {
			cond = conds[i]
		}

		for j, inv := range []mtgban.InventoryRecord{market, direct, low} {
			for _, entry := range inv[id] {
				if entry.Conditions == cond {
					prices[j] = entry.Price
					break
				}
			}
		}

		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			continue
		}

		tcgSkuId := findTCGproductSKU(id, cond)

		condLong := tcgConditionMap[cond]
		if co.Foil || co.Etched {
			condLong += " Foil"
		}

		record := make([]string, 0, len(tcgcsvHeader))

		record = append(record, tcgSkuId)
		record = append(record, "")
		record = append(record, co.Edition)
		record = append(record, co.Name)
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
		record = append(record, "")
		record = append(record, "")

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
	host := ""
	gameName := "Magic: the Gathering"
	if Config.Game == "Lorcana" {
		host = "lorcana."
		gameName = "Lorcana"
	}

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
			Template: "https://" + host + "mtgban.com/search?q={searchTerms}",
		},
		{
			Rel:      "self",
			Type:     "application/opensearchdescription+xml",
			Template: "https://" + host + "mtgban.com/api/opensearch.xml",
		},
		{
			Rel:      "suggestions",
			Type:     "application/json",
			Template: "http://" + host + "mtgban.com/api/suggest?q={searchTerms}",
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

	// Load whether a user can download CSV and validate the query parameter
	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	if !canDownloadCSV {
		pageVars := genPageNav("Error", sig)
		pageVars.Title = "Unauthorized"
		pageVars.ErrorMessage = "Unable to download CSV"
		render(w, "home.html", pageVars)
		return
	}

	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	isRetail := strings.Contains(r.URL.Path, "/retail/")
	isBuylist := strings.Contains(r.URL.Path, "/buylist/")
	isSealed := strings.Contains(r.URL.Path, "/sealed/")

	query := r.URL.Path
	query = strings.TrimPrefix(query, "/api/search/retail/")
	query = strings.TrimPrefix(query, "/api/search/buylist/")
	query = strings.TrimPrefix(query, "sealed/")

	mode := "scryfall"
	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	config := parseSearchOptionsNG(query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	if isSealed {
		config.SearchMode = "sealed"
		mode = "mtgjson"
	}

	// Perform search
	allKeys, _ := searchAndFilter(config)

	// Limit results to be processed
	if len(allKeys) > MaxUploadProEntries {
		allKeys = allKeys[:MaxUploadProEntries]
	}

	// Retrieve prices
	var results map[string]map[string]*BanPrice
	var filename string
	if isRetail {
		filename = "mtgban_retail_prices"

		var enabledStores []string
		for _, seller := range Sellers {
			if seller != nil && !slices.Contains(blocklistRetail, seller.Info().Shorthand) {
				enabledStores = append(enabledStores, seller.Info().Shorthand)
			}
		}

		results = getSellerPrices(mode, enabledStores, "", allKeys, "", true, true, isSealed, "names")
	} else if isBuylist {
		filename = "mtgban_buylist_prices"

		var enabledStores []string
		for _, vendor := range Vendors {
			if vendor != nil && !slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
				enabledStores = append(enabledStores, vendor.Info().Shorthand)
			}
		}

		results = getVendorPrices(mode, enabledStores, "", allKeys, "", true, true, isSealed, "names")
	}
	if isSealed {
		filename += "_sealed"
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+".csv\"")
	csvWriter := csv.NewWriter(w)
	err := BanPrice2CSV(csvWriter, results, true, true, isSealed)
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
}
