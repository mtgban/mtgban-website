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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

var ErrMissingTCGId = errors.New("tcg id not found")

func getLastSold(ctx context.Context, b *mtgmatcher.Backend, cardID string, anyLang bool) ([]tcgplayer.LatestSalesData, error) {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return nil, err
	}

	tcgID := findTCGproductID(b, cardID)
	if tcgID == "" {
		return nil, ErrMissingTCGId
	}

	latestSales, err := tcgplayer.LatestSales(ctx, tcgID, co.Foil || co.Etched, anyLang)
	if err != nil {
		return nil, err
	}

	// If we got an empty response, try again with all the possible languages
	if len(latestSales) == 0 && !anyLang {
		return getLastSold(ctx, b, cardID, true)
	}

	return latestSales, nil
}

func getDirectQty(ctx context.Context, b *mtgmatcher.Backend, cardID string) ([]tcgplayer.ListingData, error) {
	tcgProductID := findTCGproductID(b, cardID)
	if tcgProductID == "" {
		return nil, ErrMissingTCGId
	}

	tcgID, err := strconv.Atoi(tcgProductID)
	if err != nil {
		return nil, err
	}

	return tcgplayer.GetDirectQtysForProductID(ctx, tcgID, true), nil
}

func getDecklist(b *mtgmatcher.Backend, uuid string) ([]string, error) {
	co, err := b.GetUUID(uuid)
	if err != nil {
		return nil, err
	}

	return b.GetDecklist(co.SetCode, co.UUID)
}

func (s *site) TCGHandler(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	w.Header().Set("Content-Type", "application/json")

	isLastSold := strings.Contains(r.URL.Path, "lastsold")
	isDirectQty := strings.Contains(r.URL.Path, "directqty")
	isDecklist := strings.Contains(r.URL.Path, "decklist")

	cardID := r.URL.Path
	cardID = strings.TrimPrefix(cardID, "/api/tcgplayer/lastsold/")
	cardID = strings.TrimPrefix(cardID, "/api/tcgplayer/directqty/")
	cardID = strings.TrimPrefix(cardID, "/api/tcgplayer/decklist/")

	var data any
	var err error
	var useCSV bool
	if isLastSold {
		UserNotify("tcgLastSold", cardID)
		data, err = getLastSold(r.Context(), b, cardID, false)
	} else if isDirectQty {
		UserNotify("tcgDirectQty", cardID)
		data, err = getDirectQty(r.Context(), b, cardID)
	} else if isDecklist {
		UserNotify("tcgDecklist", cardID)
		data, err = getDecklist(b, cardID)
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
		co, _ := b.GetUUID(cardID)
		setCSVDownloadHeaders(w, co.Name+".csv")

		csvWriter := csv.NewWriter(w)
		err = UUID2TCGCSV(b, csvWriter, data.([]string), nil, nil)
		if err != nil {
			dropDownloadHeaders(w)
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
	header := []string{"Title", "Edition", "Foil", "Quantity"}
	return uuid2BuylistCSV(w, ids, qtys, "CK", header, func(entry mtgban.BuylistEntry, quantity string) []string {
		name, found := entry.CustomFields["CKTitle"]
		if !found {
			return nil
		}
		return []string{name, entry.CustomFields["CKEdition"], entry.CustomFields["CKFoil"], quantity}
	})
}

func UUID2SCGCSV(w *csv.Writer, ids, qtys []string) error {
	header := []string{"quantity", "productid", "name", "set_name", "language", "finish"}
	return uuid2BuylistCSV(w, ids, qtys, "SCG", header, func(entry mtgban.BuylistEntry, quantity string) []string {
		fields := entry.CustomFields
		return []string{quantity, entry.InstanceID, fields["SCGName"], fields["SCGEdition"], fields["SCGLanguage"], fields["SCGFinish"]}
	})
}

// uuid2BuylistCSV writes a row for each id the vendor buys, as row renders
// its first buylist entry and quantity; a nil row skips the card. Quantities
// default to 1, for a "0" or when qtys is not the size of ids.
func uuid2BuylistCSV(w *csv.Writer, ids, qtys []string, vendor string, header []string, row func(mtgban.BuylistEntry, string) []string) error {
	buylist, err := findVendorBuylist(vendor)
	if err != nil {
		return err
	}

	err = w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}
		record := row(blEntries[0], quantity)
		if record == nil {
			continue
		}

		err = w.Write(record)
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

func SCGRetailRedirect(ctx context.Context, b *mtgmatcher.Backend, ids, qtys, conds []string) (string, error) {
	if len(qtys) != len(ids) || len(conds) != len(ids) {
		return "", errors.New("mismatched card, quantity and condition lists")
	}
	var data strings.Builder
	for i, hash := range ids {
		co, err := b.GetUUID(hash)
		if err != nil {
			continue
		}
		sku := findInstanceID("SCG", hash, mtgban.Condition(conds[i]))

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
	req.Header.Set("X-API-KEY", Config().API["scg_mass_entry"])

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var responsePayload struct {
		AffiliateDataID string `json:"affiliateDataId"`
	}
	err = json.NewDecoder(resp.Body).Decode(&responsePayload)
	if err != nil {
		return "", err
	}

	return responsePayload.AffiliateDataID, nil
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

var tcgConditionMap = map[mtgban.Condition]string{
	mtgban.NM: "Near Mint",
	mtgban.SP: "Lightly Played",
	mtgban.MP: "Moderately Played",
	mtgban.HP: "Heavily Played",
	mtgban.PO: "Damaged",
}

// csvRow is one row of a marketplace CSV: a card in one condition, and its
// quantity across every entry naming that pair.
type csvRow struct {
	id   string
	cond mtgban.Condition
	qty  int
}

// mergeCSVRows merges the entries naming the same card in the same condition
// into one row, in first-seen order. qtys and conds, when present, are the
// size of ids; a missing quantity counts as 1 and a missing condition as NM.
func mergeCSVRows(ids, qtys, conds []string) []csvRow {
	var rows []csvRow
	index := map[csvRow]int{}
	for i, id := range ids {
		quantity := 1
		if qtys != nil {
			q, err := strconv.Atoi(qtys[i])
			if err == nil {
				quantity = q
			}
		}
		cond := mtgban.NM
		if conds != nil && conds[i] != "" {
			cond = mtgban.Condition(conds[i])
		}
		key := csvRow{id: id, cond: cond}
		j, found := index[key]
		if !found {
			j = len(rows)
			index[key] = j
			rows = append(rows, key)
		}
		rows[j].qty += quantity
	}
	return rows
}

// Convert a slice of ids (BAN uuids) to a list of TCG product SKUs on a CSV
//
// If present, qtys and conds need to be the same size of ids.
// If absent, quantity will be computed on the fly and entries will be merged
// in a single entry (tcgplayer does not support csv operations with identical
// items) and conditions will be set to NM.
// UUID2TCGCSV writes a TCGplayer-importable CSV. The edition, display-name,
// number, and rarity columns come from the tcg catalog snapshot, i.e. from
// TCGplayer's own catalog, so they always pass TCGplayer's name-match check
// (our names don't always match theirs exactly, see commit 1e39d5d). Cards
// missing from the catalog keep these columns blank - TCGplayer skips the
// check when they're empty.
func UUID2TCGCSV(b *mtgmatcher.Backend, w *csv.Writer, ids, qtys, conds []string) error {
	market, err := findSellerInventory("TCGPlayer")
	if err != nil {
		return err
	}
	direct, _ := findSellerInventory("TCGDirectLow")
	low, _ := findSellerInventory("TCGLow")
	sealed, _ := findSellerInventory("TCGSealed")

	// TCGplayer's own identifiers, from the catalog dump
	productLine, tcgProducts := GetTCGCatalog()

	err = w.Write(tcgcsvHeader)
	if err != nil {
		return err
	}

	for _, row := range mergeCSVRows(ids, qtys, conds) {
		id, cond := row.id, row.cond
		var prices [3]float64

		co, err := b.GetUUID(id)
		if err != nil {
			continue
		}

		var tcgSkuID string
		if co.Sealed {
			tcgSkuID = findInstanceID("TCGSealed", id, cond)
			for _, entry := range sealed[id] {
				prices[0] = entry.Price
				break
			}
		} else {
			tcgSkuID = findInstanceID("TCGPlayer", id, cond)
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

		tcgEntry := tcgProducts[findTCGproductID(b, id)]

		record := make([]string, 0, len(tcgcsvHeader))
		record = append(record, tcgSkuID)
		record = append(record, productLine)
		record = append(record, tcgEntry.Edition)
		record = append(record, tcgEntry.Name)
		record = append(record, "")
		record = append(record, tcgEntry.Number)
		record = append(record, tcgEntry.Rarity)
		record = append(record, condLong)
		record = append(record, fmt.Sprintf("%0.2f", prices[0]))
		record = append(record, fmt.Sprintf("%0.2f", prices[1]))
		record = append(record, "")
		record = append(record, fmt.Sprintf("%0.2f", prices[2]))
		record = append(record, "")
		record = append(record, fmt.Sprint(row.qty))
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

func (s *site) MKMHandler(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	w.Header().Set("Content-Type", "application/json")

	isDecklist := strings.Contains(r.URL.Path, "decklist")

	cardID := r.URL.Path
	cardID = strings.TrimPrefix(cardID, "/api/cardmarket/decklist/")

	var data any
	var err error
	var useCSV bool
	if isDecklist {
		UserNotify("mkmDecklist", cardID)
		data, err = getDecklist(b, cardID)
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
		co, _ := b.GetUUID(cardID)
		setCSVDownloadHeaders(w, co.Name+".csv")

		csvWriter := csv.NewWriter(w)
		err = UUID2MKMCSV(b, csvWriter, data.([]string), nil, nil)
		if err != nil {
			dropDownloadHeaders(w)
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

var mkmConditionMap = map[mtgban.Condition]string{
	mtgban.NM: "NM",
	mtgban.SP: "EX",
	mtgban.MP: "GD",
	mtgban.HP: "HP",
	mtgban.PO: "PO",
}

// Convert a slice of ids (BAN uuids) to a list of TCG product SKUs on a CSV
//
// If present, qtys and conds need to be the same size of ids.
// If absent, quantity will be computed on the fly and entries will be merged
// in a single entry (tcgplayer does not support csv operations with identical
// items) and conditions will be set to NM.
func UUID2MKMCSV(b *mtgmatcher.Backend, w *csv.Writer, ids, qtys, conds []string) error {
	trend, _ := findSellerInventory("MKMTrend")
	low, _ := findSellerInventory("MKMLow")

	err := w.Write(mkmcsvHeader)
	if err != nil {
		return err
	}

	for _, row := range mergeCSVRows(ids, qtys, conds) {
		id, cond := row.id, row.cond

		co, err := b.GetUUID(id)
		if err != nil {
			continue
		}

		mkmID := findOriginalID("MKMTrend", id)
		if mkmID == "" {
			mkmID = findOriginalID("MKMLow", id)
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

		record = append(record, mkmID)
		record = append(record, fmt.Sprint(row.qty))
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
		record = append(record, b.RarityLabel(co.Rarity))
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
	host := string(Config().Game)
	gameName := mtgmatcher.Title(host)

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

func (s *site) SearchAPI(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	b := ds.backend
	// The API middleware checks a ?sig= and lets a request without one
	// through unchecked, so a cookie counts only once it is checked here.
	sig := r.FormValue("sig")
	if sig == "" {
		sig = verifiedSignature(r)
	}

	out := PriceAPIOutput{}
	out.Meta.Date = time.Now()
	out.Meta.Version = APIVersion
	out.Meta.BaseURL = absoluteURL(r, "/go/")

	isJSON := strings.HasSuffix(r.URL.Path, ".json")
	isCSV := strings.HasSuffix(r.URL.Path, ".csv")
	// v2 serves v1's CSV, as its price API does
	isV2 := strings.HasPrefix(r.URL.Path, "/api/v2/search/")
	isAPI := isV2 || strings.HasPrefix(r.URL.Path, "/api/mtgban/search/")
	isV2JSON := isV2 && isJSON

	// Only allow JSON from a different (protected) endpoint
	if isJSON && !isAPI {
		pageVars := genPageNav(s, r, "Error", sig)
		pageVars.Title = "Unauthorized"
		pageVars.ErrorMessage = "Invalid endpoint for JSON"
		render(w, "home.html", pageVars)
		return
	}

	// Load whether a user can download CSV and validate the query parameter
	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	if isCSV && !canDownloadCSV {
		pageVars := genPageNav(s, r, "Error", sig)
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
	if isV2JSON && idOpt != "" && !slices.Contains(v2IDModes, idOpt) {
		out.Meta.Version = APIVersionV2
		out.Error = fmt.Sprintf("unknown id %q, use one of %s", idOpt, strings.Join(v2IDModes, ", "))
		json.NewEncoder(w).Encode(&out)
		return
	}
	explicitID := idOpt != ""
	if !explicitID {
		idOpt = "scryfall"
	}
	tagName := r.FormValue("tag")
	if tagName == "" {
		tagName = "names"
	}

	miscSearchOpts := readSearchMiscOpts(r)
	config := parseSearchOptionsNG(b, query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	// The export links carry the sticky bar as its own parameter rather
	// than spliced into the path, so the csv holds the rows the page did.
	applySearchScope(&config, scopeFilters(b, strings.TrimSpace(r.FormValue("scope"))))
	if isSealed {
		config.SearchMode = "sealed"
		// v2 keeps an id the request asks for
		if !isV2JSON || !explicitID {
			idOpt = "mtgjson"
		}
	}

	// Perform search
	allKeys, _ := searchAndFilter(ds, config)

	// Sort as the search page does, reverse included
	sortSearchKeys(r, ds, allKeys, dropOdds(b, config), readSearchSort(r, config))

	// Limit results to be processed
	if len(allKeys) > MaxSearchTotalResults {
		allKeys = allKeys[:MaxSearchTotalResults]
	}

	canRetail := canAccessMode(enabledModes, "retail")
	canBuylist := canAccessMode(enabledModes, "buylist")

	// The demo (sig-less) JSON endpoint sees only the demo stores; per the
	// storeEligible precedence an explicit store list is the entire policy,
	// so it replaces the parsed store filters (blocklists included)
	demoStores := sig == "" && isJSON
	demoFilter := func(name string, forSeller bool) []FilterStoreElem {
		return []FilterStoreElem{{
			Name:          name,
			Values:        fixupStoreCodeNG(strings.Join(Config().APIDemoStores, ",")),
			OnlyForSeller: forSeller,
			OnlyForVendor: !forSeller,
		}}
	}

	// A key sees only the stores it was sold, as on the price API. Its scope
	// is one more store filter, so the query's own still narrow within it.
	// A site login signs API=true for the API page, which names no store.
	storesOpt := GetParamFromSig(sig, "API")
	if storesOpt != "" && storesOpt != "true" && isAPI {
		config.StoreFilters = append(config.StoreFilters, FilterStoreElem{
			Name:   "store",
			Values: fixupStoreCodeNG(strings.Join(apiEnabledStores(storesOpt), ",")),
		})
	}

	// Retrieve prices through the same gathering the search page uses, so
	// every filter the query carries (stores, conditions, prices) shapes
	// the output instead of only the card-level ones
	var foundSellers, foundVendors map[string]map[mtgban.Condition][]SearchEntry
	var retailV2, buylistV2 *v2Section
	if isRetail && canRetail {
		cfg := config
		if demoStores {
			cfg.StoreFilters = demoFilter("seller", true)
		}
		if isV2JSON {
			retailV2 = sellerSearchV2(b, idOpt, allKeys, cfg, isSealed)
		} else {
			foundSellers = searchSellersNG(allKeys, cfg)
			out.Retail = banPricesFromRows(b, allKeys, foundSellers, idOpt, tagName, true, true, false)
		}
	}
	if isBuylist && canBuylist {
		cfg := config
		if demoStores {
			cfg.StoreFilters = demoFilter("vendor", false)
		}
		if isV2JSON {
			buylistV2 = vendorSearchV2(b, idOpt, allKeys, cfg, isSealed)
		} else {
			foundVendors = searchVendorsNG(allKeys, cfg)
			out.Buylist = banPricesFromRows(b, allKeys, foundVendors, idOpt, tagName, true, true, true)
		}
	}

	if isV2JSON {
		out.Meta.Version = APIVersionV2
		w.Header().Set("Content-Type", "application/json")
		err := writeV2Response(w, b, out.Meta, retailV2, buylistV2)
		if err != nil {
			log.Println("API v2 search write:", err)
		}
		return
	}

	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&out)
		return
	}

	if isCSV {
		setCSVDownloadHeaders(w, "mtgban_search.csv")

		// Reuse the walked rows, keyed by BAN UUID so foil/nonfoil stay
		// separate (CSV is never the demo mode, so the rows above carry
		// the full store policy)
		var results map[string]map[string]*BanPrice
		if isRetail && canRetail {
			results = banPricesFromRows(b, allKeys, foundSellers, "", tagName, true, true, false)
		} else if isBuylist && canBuylist {
			results = banPricesFromRows(b, allKeys, foundVendors, "", tagName, true, true, true)
		}

		err := BanPrice2CSV(b, w, results, allKeys)
		if err != nil {
			dropDownloadHeaders(w)
			UserNotify("search", err.Error())
			pageVars := genPageNav(s, r, "Error", sig)
			pageVars.Title = "Error"
			pageVars.InfoMessage = "Unable to download CSV right now"
			render(w, "home.html", pageVars)
			return
		}
		return
	}
}

// validStoreName matches the names bantool publishes stores under;
// LoadFromCloud refuses anything else before listing.
var validStoreName = regexp.MustCompile(`^[a-z0-9_]+$`)

func (s *site) LoadFromCloud(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path
	name = strings.TrimPrefix(name, "/api/load/")

	if !validStoreName.MatchString(name) {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}
	if GetParamFromSig(r.FormValue("sig"), "API") != name {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}

	prefix := string(Config().Game) + "/" + name + "/"
	idx, err := listDumpsWithRetry(DataBucket, Config().Game, prefix)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	scrapersConfig := idx.byStore[name]
	if len(scrapersConfig) == 0 {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}

	var failed, loaded []string
	for kind, list := range scrapersConfig {
		ok := false
		for _, shorthand := range list {
			err := loadScraperWithRetry(DataBucket, Config().Game, name, kind, shorthand)
			if err != nil {
				log.Println(err)
				failed = append(failed, fmt.Sprintf("%s/%s: %s", kind, shorthand, err))
				continue
			}
			ok = true
		}
		if ok {
			loaded = append(loaded, kind)
		}
	}

	updateScraperIndexStore(name, scrapersConfig)
	// Whatever did load is news to the alerts, failures or not.
	s.pokeAlerts(loaded...)

	// A scraper that just finished producing and still will not load is the
	// case worth waking someone for, unlike the same absence at startup.
	if len(failed) > 0 {
		slices.Sort(failed)
		msg := fmt.Sprintf("Server reloaded %s, %d did not load: %s", name, len(failed), strings.Join(failed, "; "))
		ServerNotify("reload", msg, true)
		// The caller is the scraper that just published, and a reload it
		// asked for and did not get is its news as much as the channel's.
		errorResponse(w, http.StatusInternalServerError, msg)
		return
	}

	ServerNotify("reload", "Server reloaded "+name)
	s.offline.RequestRefresh()
	w.Write([]byte(`{"status": "ok"}`))
}

func (s *site) LoadDatastoreFromCloud(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := verify(r)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Answer as soon as the reload is under way. Loading takes minutes, and
	// a caller that waits for it holds a connection open long enough that
	// whatever sits in front gives up and reports a gateway error against a
	// reload that is running perfectly well. What the load then did is on
	// the admin page, and in the server notifications.
	if !s.startDatastoreReload(Config().DatastorePath, "api") {
		// Read after the call that queued this one, so it names the reload
		// it waits for.
		state := s.reloads.Status()
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status": "ok", "state": "queued", "after": %q}`, state.StartedAt.UTC().Format(time.RFC3339))
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "ok", "state": "started"}`))
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
