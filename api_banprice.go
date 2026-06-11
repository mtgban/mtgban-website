package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	APIVersion = "1"
)

type BanPrice struct {
	Regular    float64            `json:"regular,omitempty"`
	Foil       float64            `json:"foil,omitempty"`
	Etched     float64            `json:"etched,omitempty"`
	Sealed     float64            `json:"sealed,omitempty"`
	Cond       string             `json:"cond,omitempty"`
	Qty        int                `json:"qty,omitempty"`
	QtyFoil    int                `json:"qty_foil,omitempty"`
	QtyEtched  int                `json:"qty_etched,omitempty"`
	QtySealed  int                `json:"qty_sealed,omitempty"`
	Conditions map[string]float64 `json:"conditions,omitempty"`
	Quantities map[string]int     `json:"quantities,omitempty"`
}

type PriceAPIOutput struct {
	Error string `json:"error,omitempty"`
	Meta  struct {
		Date    time.Time `json:"date"`
		Version string    `json:"version"`
		BaseURL string    `json:"base_url"`
	} `json:"meta"`

	// uuid > store > price {regular/foil/etched}
	Retail  map[string]map[string]*BanPrice `json:"retail,omitempty"`
	Buylist map[string]map[string]*BanPrice `json:"buylist,omitempty"`
}

func PriceAPI(w http.ResponseWriter, r *http.Request) {
	sig := r.FormValue("sig")
	out := PriceAPIOutput{}
	out.Meta.Date = time.Now()
	out.Meta.Version = APIVersion
	out.Meta.BaseURL = ServerURL + "/go/"

	urlPath := strings.TrimPrefix(r.URL.Path, "/api/mtgban/")

	if !strings.HasSuffix(urlPath, ".json") && !strings.HasSuffix(urlPath, ".csv") {
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}

	// Endpoint for retrieving the set codes
	if strings.HasPrefix(urlPath, "sets") {
		sets := mtgmatcher.GetAllSets()
		filter := r.FormValue("filter")
		if filter == "singles" {
			var filtered []string
			for _, code := range sets {
				set, err := mtgmatcher.GetSet(code)
				if err != nil {
					continue
				}
				if len(set.Cards) > 0 {
					filtered = append(filtered, code)
				}
			}
			sets = filtered
		} else if filter == "sealed" {
			var filtered []string
			for _, code := range sets {
				set, err := mtgmatcher.GetSet(code)
				if err != nil {
					continue
				}
				if len(set.SealedProduct) > 0 {
					filtered = append(filtered, code)
				}
			}
			sets = filtered
		}

		if strings.HasSuffix(urlPath, ".json") {
			json.NewEncoder(w).Encode(&sets)
		} else if strings.HasSuffix(urlPath, ".csv") {
			w.Header().Set("Content-Type", "text/csv")
			csvWriter := csv.NewWriter(w)
			csvWriter.Write([]string{"Code"})
			for _, code := range sets {
				csvWriter.Write([]string{code})
			}
			csvWriter.Flush()
		}
		return
	}

	storesOpt := GetParamFromSig(sig, "API")
	if DevMode && !SigCheck && storesOpt == "" {
		storesOpt = "DEV_ACCESS"
	}
	if sig == "" && storesOpt == "" {
		storesOpt = strings.Join(Config.ApiDemoStores, ",")
		// Disable a few endpoints for this specific mode
		if strings.Contains(urlPath, "all.") || strings.Contains(urlPath, "retail.") || strings.Contains(urlPath, "buylist.") {
			out.Error = "Invalid endpoint or missing signature"
			json.NewEncoder(w).Encode(&out)
			return
		}
	}

	var enabledStores []string
	switch storesOpt {
	case "ALL_ACCESS":
		for _, seller := range GetSellers() {
			shorthand := seller.Info().Shorthand
			if !slices.Contains(Config.SearchRetailBlockList, shorthand) && !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
		for _, vendor := range GetVendors() {
			shorthand := vendor.Info().Shorthand
			if !slices.Contains(Config.SearchBuylistBlockList, shorthand) &&
				!slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
	case "DEV_ACCESS":
		for _, seller := range GetSellers() {
			shorthand := seller.Info().Shorthand
			if !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
		for _, vendor := range GetVendors() {
			shorthand := vendor.Info().Shorthand
			if !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
	default:
		enabledStores = strings.Split(storesOpt, ",")
	}

	// Endpoint for retrieving the stores shorthands
	if strings.HasPrefix(urlPath, "stores") {
		output := enabledStores
		filter := r.FormValue("filter")
		if filter == "singles" {
			var filtered []string
			for _, seller := range GetSellers() {
				if (seller.Info().SealedMode && filter == "singles") || (!seller.Info().SealedMode && filter == "sealed") {
					continue
				}
				shorthand := seller.Info().Shorthand
				if slices.Contains(enabledStores, shorthand) && !slices.Contains(filtered, shorthand) {
					filtered = append(filtered, shorthand)
				}
			}
			for _, vendor := range GetVendors() {
				if (vendor.Info().SealedMode && filter == "singles") || (!vendor.Info().SealedMode && filter == "sealed") {
					continue
				}
				shorthand := vendor.Info().Shorthand
				if slices.Contains(enabledStores, shorthand) && !slices.Contains(filtered, shorthand) {
					filtered = append(filtered, shorthand)
				}
			}
			output = filtered
		}

		// Keep sorted
		sort.Strings(output)

		// See if the user requested names instead (preserving order above)
		tagName := r.FormValue("tag")
		if tagName == "names" {
			var filtered []string
			for _, tag := range output {
				filtered = append(filtered, scraperName(tag))
			}
			output = filtered
		}

		if strings.HasSuffix(urlPath, ".json") {
			json.NewEncoder(w).Encode(&output)
		} else if strings.HasSuffix(urlPath, ".csv") {
			w.Header().Set("Content-Type", "text/csv")
			csvWriter := csv.NewWriter(w)
			csvWriter.Write([]string{"Code"})
			for _, code := range output {
				csvWriter.Write([]string{code})
			}
			csvWriter.Flush()
		}
		return
	}

	enabledModes := strings.Split(GetParamFromSig(sig, "APImode"), ",")
	idOpt := r.FormValue("id")
	qty, _ := strconv.ParseBool(r.FormValue("qty"))
	conds, _ := strconv.ParseBool(r.FormValue("conds"))
	filterByFinish := r.FormValue("finish")
	tagName := r.FormValue("tag")
	if sig == "" {
		enabledModes = []string{"all"}
		if tagName == "" {
			tagName = "tags"
		}
	}

	// Filter by user preference, as long as it's listed in the enabled stores
	filterByVendors := r.FormValue("vendor")
	if filterByVendors != "" {
		var newEnabledStores []string
		for _, filtered := range strings.Split(filterByVendors, ",") {
			if slices.Contains(enabledStores, filtered) {
				newEnabledStores = append(newEnabledStores, filtered)
			}
		}
		enabledStores = newEnabledStores
	}

	filterByEdition := ""
	var filterByHash []string
	if strings.Contains(urlPath, "/") {
		base := path.Base(urlPath)
		if strings.HasSuffix(urlPath, ".json") {
			base = strings.TrimSuffix(base, ".json")
		} else if strings.HasSuffix(urlPath, ".csv") {
			base = strings.TrimSuffix(base, ".csv")
		}

		// Check if the path element is a set name or a hash
		set, err := mtgmatcher.GetSet(base)
		if err == nil {
			filterByEdition = set.Code
		} else {
			for _, opts := range [][]bool{
				// Check for nonfoil, foil, etched
				[]bool{false, false}, []bool{true, false}, []bool{false, true},
			} {
				uuid, err := mtgmatcher.MatchId(base, opts...)
				if err != nil {
					continue
				}
				// Skip if hash is already present
				if slices.Contains(filterByHash, uuid) {
					continue
				}
				filterByHash = append(filterByHash, uuid)
			}
			// Speed up search by keeping only the needed edition
			if len(filterByHash) > 0 {
				co, err := mtgmatcher.GetUUID(filterByHash[0])
				if err == nil {
					filterByEdition = co.SetCode
				}
			}
		}

		if filterByEdition == "" && filterByHash == nil {
			out.Error = "Not found"
			json.NewEncoder(w).Encode(&out)
			return
		}
	}

	// Only filtered output can have csv encoding, and only for retail or buylist requests
	checkCSVoutput := (filterByEdition == "" && filterByHash == nil && filterByFinish == "") || strings.HasPrefix(urlPath, "all")
	if strings.HasSuffix(urlPath, ".csv") && checkCSVoutput {
		out.Error = "Invalid request"
		json.NewEncoder(w).Encode(&out)
		return
	}

	// Only export conditions when a single store or edition is enabled
	// or always export them if a list of card is requested
	// or let user decide in case of DEV_ACCESS
	if len(enabledStores) == 1 {
		conds = true
	} else if conds && storesOpt != "DEV_ACCESS" {
		conds = filterByHash != nil || filterByEdition != ""
	}

	start := time.Now()

	dumpType := ""
	canRetail := slices.Contains(enabledModes, "retail") || (slices.Contains(enabledModes, "all") || (DevMode && !SigCheck))
	canBuylist := slices.Contains(enabledModes, "buylist") || (slices.Contains(enabledModes, "all") || (DevMode && !SigCheck))
	canSealed := slices.Contains(enabledModes, "sealed") || (slices.Contains(enabledModes, "all") || (DevMode && !SigCheck))
	isSealed := strings.HasPrefix(urlPath, "sealed") && canSealed
	if isSealed {
		dumpType += "sealed"
	}

	if ((strings.HasPrefix(urlPath, "retail") || strings.HasPrefix(urlPath, "all")) && canRetail) || isSealed {
		dumpType += "retail"
		out.Retail = getSellerPrices(idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, qty, conds, isSealed, tagName)
	}
	if ((strings.HasPrefix(urlPath, "buylist") || strings.HasPrefix(urlPath, "all")) && canBuylist) || isSealed {
		dumpType += "buylist"
		out.Buylist = getVendorPrices(idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, qty, conds, isSealed, tagName)
	}

	user := GetParamFromSig(sig, "UserEmail")
	if sig == "" && user == "" {
		user = "anonymous"
	}
	msg := fmt.Sprintf("[%v] %s (%s / %s) requested a '%s' API dump ('%s','%q','%s')", time.Since(start), user, r.Header.Get("X-Forwarded-For"), r.RemoteAddr, dumpType, filterByEdition, filterByHash, filterByFinish)
	if qty {
		msg += " with quantities"
	}
	if conds {
		msg += " with conditions"
	}
	if strings.HasSuffix(urlPath, ".json") {
		msg += " in json"
	} else if strings.HasSuffix(urlPath, ".csv") {
		msg += " in csv"
	}
	APINotify(msg)

	if out.Retail == nil && out.Buylist == nil {
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}

	if strings.HasSuffix(urlPath, ".json") {
		json.NewEncoder(w).Encode(&out)
		return
	} else if strings.HasSuffix(urlPath, ".csv") {
		var err error
		if out.Retail != nil {
			err = BanPrice2CSV(w, out.Retail, nil)
		} else if out.Buylist != nil {
			err = BanPrice2CSV(w, out.Buylist, nil)
		}
		if err != nil {
			log.Println(err)
		}
		return
	}

	out.Error = "Internal Server Error"
	json.NewEncoder(w).Encode(&out)
}

func getIdFunc(mode string) func(co *mtgmatcher.CardObject) string {
	switch mode {
	case "tcg":
		return func(co *mtgmatcher.CardObject) string {
			return findTCGproductId(co.UUID)
		}
	case "scryfall":
		return func(co *mtgmatcher.CardObject) string {
			return co.Identifiers["scryfallId"]
		}
	case "mtgjson":
		return func(co *mtgmatcher.CardObject) string {
			if co.Sealed {
				return co.UUID
			}
			return co.Identifiers["mtgjsonId"]
		}
	case "name":
		return func(co *mtgmatcher.CardObject) string {
			if co.Sealed {
				return co.Name
			}
			return fmt.Sprintf("%s|%s|%s", co.Name, co.SetCode, co.Number)
		}
	case "mkm":
		return func(co *mtgmatcher.CardObject) string {
			return co.Identifiers["mcmId"]
		}
	case "ck":
		return func(co *mtgmatcher.CardObject) string {
			if co.Etched {
				id, found := co.Identifiers["cardKingdomEtchedId"]
				if found {
					return id
				}
			} else if co.Foil {
				return co.Identifiers["cardKingdomFoilId"]
			}
			return co.Identifiers["cardKingdomId"]
		}
	}
	return func(co *mtgmatcher.CardObject) string {
		return co.UUID
	}
}

func getSellerPrices(mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}
	for _, seller := range GetSellers() {
		// Only keep the right product type
		if (!sealed && seller.Info().SealedMode) ||
			(sealed && !seller.Info().SealedMode) {
			continue
		}

		// Skip any seller that are not enabled
		if !slices.Contains(enabledStores, seller.Info().Shorthand) {
			continue
		}

		// Get inventory
		inventory := seller.Inventory()

		var sellerTag string
		switch tagName {
		case "names":
			sellerTag = seller.Info().Name
		default:
			sellerTag = seller.Info().Shorthand
		}

		// Determine whether the response should include qty information
		// Needs to be explicitly requested, all the index prices are skipped,
		// and of course any seller without quantity information
		shouldQty := qty && !seller.Info().MetadataOnly && !seller.Info().NoQuantityInventory
		shouldBaseCond := !seller.Info().MetadataOnly && !seller.Info().SealedMode

		for _, cardId := range filterByHash {
			processEntry(out, inventory[cardId], mode, cardId, filterByEdition, filterByFinish, sellerTag, shouldQty, conds, shouldBaseCond)
		}
		if filterByHash == nil {
			for cardId := range inventory {
				processEntry(out, inventory[cardId], mode, cardId, filterByEdition, filterByFinish, sellerTag, shouldQty, conds, shouldBaseCond)
			}
		}
	}

	return out
}

func processEntry[T mtgban.GenericEntry](out map[string]map[string]*BanPrice, entries []T, idMode, cardId, scraperTag string, qty, conds, shouldBaseCond bool) {
	if len(entries) == 0 {
		return
	}
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return
	}
	if filterByEdition != "" && co.SetCode != filterByEdition {
		return
	}
	if filterByFinish != "" && checkFinish(co, filterByFinish) {
		return
	}
	id := getIdFunc(idMode)(co)
	if id == "" {
		return
	}

	basePrice := entries[0].Pricing()
	if basePrice == 0 {
		return
	}

	_, found := out[id]
	if !found {
		out[id] = map[string]*BanPrice{}
	}
	if out[id][scraperTag] == nil {
		out[id][scraperTag] = &BanPrice{}
	}

	if shouldBaseCond {
		out[id][scraperTag].Cond = entries[0].Condition()
	}

	if conds && out[id][scraperTag].Conditions == nil {
		out[id][scraperTag].Conditions = map[string]float64{}
	}

	if co.Sealed {
		out[id][scraperTag].Sealed = basePrice
		if qty {
			for i := range entries {
				out[id][scraperTag].QtySealed += entries[i].Qty()
			}
		}
	} else if co.Etched {
		out[id][scraperTag].Etched = basePrice
		if qty {
			for i := range entries {
				out[id][scraperTag].QtyEtched += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition() + "_etched"
				out[id][scraperTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = map[string]int{}
					}
					out[id][scraperTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	} else if co.Foil {
		out[id][scraperTag].Foil = basePrice
		if qty {
			for i := range entries {
				out[id][scraperTag].QtyFoil += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition() + "_foil"
				out[id][scraperTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = map[string]int{}
					}
					out[id][scraperTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	} else {
		out[id][scraperTag].Regular = basePrice
		if qty {
			for i := range entries {
				out[id][scraperTag].Qty += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition()
				out[id][scraperTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = map[string]int{}
					}
					out[id][scraperTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	}
}

func getVendorPrices(mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}
	for _, vendor := range GetVendors() {
		// Only keep the right product type
		if (!sealed && vendor.Info().SealedMode) ||
			(sealed && !vendor.Info().SealedMode) {
			continue
		}

		// Skip any vendor that are not enabled
		if !slices.Contains(enabledStores, vendor.Info().Shorthand) {
			continue
		}

		// Get buylist
		buylist := vendor.Buylist()

		var vendorTag string
		switch tagName {
		case "names":
			vendorTag = vendor.Info().Name
		default:
			vendorTag = vendor.Info().Shorthand
		}

		// Loop through cards
		shouldQty := qty && (!vendor.Info().MetadataOnly || vendor.Info().Shorthand == "SYP")
		shouldBaseCond := !vendor.Info().MetadataOnly && !vendor.Info().SealedMode
		for _, cardId := range filterByHash {
			processEntry(out, buylist[cardId], mode, cardId, filterByEdition, filterByFinish, vendorTag, shouldQty, conds, shouldBaseCond)
		}
		if filterByHash == nil {
			for cardId := range buylist {
				processEntry(out, buylist[cardId], mode, cardId, filterByEdition, filterByFinish, vendorTag, shouldQty, conds, shouldBaseCond)
			}
		}
	}

	return out
}

func checkFinish(co *mtgmatcher.CardObject, finish string) bool {
	if co.Sealed {
		return false
	}
	switch finish {
	case "nonfoil":
		return co.Foil || co.Etched
	case "foil":
		return !co.Foil || co.Etched
	case "etched":
		return co.Foil || !co.Etched
	}
	return false
}

// BanPrice2CSV is a convenience wrapper around SimplePrice2CSV that
// writes directly to an http.ResponseWriter.
func BanPrice2CSV(httpWriter http.ResponseWriter, pm map[string]map[string]*BanPrice, sorted []string) error {
	httpWriter.Header().Set("Content-Type", "text/csv")
	w := csv.NewWriter(httpWriter)
	return SimplePrice2CSV(w, pm, nil, sorted, false)
}

// SimplePrice2CSV converts price data to CSV. When uploadedData is provided,
// each row corresponds to an uploaded entry and includes Loaded columns.
// When uploadedData is nil, rows are derived from the price map keys (using
// sorted for ordering if non-nil).
func SimplePrice2CSV(w *csv.Writer, pm map[string]map[string]*BanPrice, uploadedData []UploadEntry, sorted []string, preferFlavor bool) error {
	var allScrapers []string
	var allIndexes []string
	for id := range pm {
		for scraperKey := range pm[id] {
			if slices.Contains(allScrapers, scraperKey) {
				continue
			}

			for _, scraper := range GetSellers() {
				if scraper.Info().Shorthand == scraperKey && scraper.Info().MetadataOnly {
					if !slices.Contains(allIndexes, scraperKey) {
						allIndexes = append(allIndexes, scraperKey)
					}
				}
			}
			for _, scraper := range GetVendors() {
				if scraper.Info().Shorthand == scraperKey && scraper.Info().MetadataOnly {
					if !slices.Contains(allIndexes, scraperKey) {
						allIndexes = append(allIndexes, scraperKey)
					}
				}
			}

			allScrapers = append(allScrapers, scraperKey)
		}
	}

	sort.Strings(allScrapers)

	allScraperNames := make([]string, len(allScrapers))
	for i, key := range allScrapers {
		name := scraperName(key)
		if name == "" {
			name = key
		}
		allScraperNames[i] = name
	}

	hasUploadData := len(uploadedData) > 0

	header := []string{"UUID", "Card Name", "Set Code", "Edition", "Number", "Finish"}
	header = append(header, allScraperNames...)
	if hasUploadData {
		header = append(header, "Loaded Price", "Loaded Condition", "Loaded Quantity", "Notes")
	}
	err := w.Write(header)
	if err != nil {
		return err
	}

	if hasUploadData {
		for j := range uploadedData {
			if uploadedData[j].MismatchError != nil {
				continue
			}

			id := uploadedData[j].CardId
			if _, found := pm[id]; !found {
				continue
			}

			condition := uploadedData[j].OriginalCondition

			record, err := priceRowToCSV(pm, id, allScrapers, allIndexes, condition, preferFlavor)
			if err != nil {
				continue
			}

			ogPrice := ""
			if uploadedData[j].OriginalPrice != 0 {
				ogPrice = fmt.Sprintf("%0.2f", uploadedData[j].OriginalPrice)
			}
			record = append(record, ogPrice, condition)

			qty := ""
			if uploadedData[j].HasQuantity {
				qty = fmt.Sprint(uploadedData[j].Quantity)
			}
			record = append(record, qty, uploadedData[j].Notes)

			if err := w.Write(record); err != nil {
				return err
			}
			w.Flush()
		}
	} else {
		if sorted == nil {
			for id := range pm {
				sorted = append(sorted, id)
			}
		}
		for _, id := range sorted {
			record, err := priceRowToCSV(pm, id, allScrapers, allIndexes, "", preferFlavor)
			if err != nil {
				continue
			}
			if err := w.Write(record); err != nil {
				return err
			}
			w.Flush()
		}
	}

	return nil
}

func priceRowToCSV(pm map[string]map[string]*BanPrice, id string, allScrapers, allIndexes []string, condition string, preferFlavor bool) ([]string, error) {
	co, err := mtgmatcher.GetUUID(id)
	if err != nil {
		uuid := mtgmatcher.ExternalUUID(id)
		if uuid != "" {
			co, err = mtgmatcher.GetUUID(uuid)
		}
		if err != nil {
			return nil, err
		}
	}

	cardName := co.Name
	if preferFlavor && co.FlavorName != "" && allLanguageFlags[co.Language] != "" {
		cardName = co.FlavorName
	}

	prices := make([]string, len(allScrapers))
	for i, scraper := range allScrapers {
		entry, found := pm[id][scraper]
		if !found {
			continue
		}
		cond := condition
		if slices.Contains(allIndexes, scraper) {
			cond = ""
		}
		price := getPrice(entry, cond)
		prices[i] = fmt.Sprintf("%0.2f", price)
	}

	scryfallID, found := co.Identifiers["scryfallId"]
	displayID := id
	if found {
		displayID = scryfallID
	}

	finish := "nonfoil"
	if co.Etched {
		finish = "etched"
	} else if co.Foil {
		finish = "foil"
	} else if co.Sealed {
		finish = "sealed"
	}

	record := []string{displayID, cardName, co.SetCode, co.Edition, co.Number, finish}
	record = append(record, prices...)
	return record, nil
}
