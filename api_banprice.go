package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"golang.org/x/exp/slices"
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
	out.Meta.BaseURL = getBaseURL(r) + "/go/"

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
		for _, seller := range Sellers {
			if seller == nil {
				continue
			}
			shorthand := seller.Info().Shorthand
			if !slices.Contains(Config.SearchRetailBlockList, shorthand) && !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
		for _, vendor := range Vendors {
			if vendor == nil {
				continue
			}
			shorthand := vendor.Info().Shorthand
			if !slices.Contains(Config.SearchBuylistBlockList, shorthand) &&
				!slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
	case "DEV_ACCESS":
		for _, seller := range Sellers {
			if seller == nil {
				continue
			}
			shorthand := seller.Info().Shorthand
			if !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
		for _, vendor := range Vendors {
			if vendor == nil {
				continue
			}
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
			for _, seller := range Sellers {
				if seller == nil || (seller.Info().SealedMode && filter == "singles") || (!seller.Info().SealedMode && filter == "sealed") {
					continue
				}
				shorthand := seller.Info().Shorthand
				if slices.Contains(enabledStores, shorthand) && !slices.Contains(filtered, shorthand) {
					filtered = append(filtered, shorthand)
				}
			}
			for _, vendor := range Vendors {
				if vendor == nil || (vendor.Info().SealedMode && filter == "singles") || (!vendor.Info().SealedMode && filter == "sealed") {
					continue
				}
				shorthand := vendor.Info().Shorthand
				if slices.Contains(enabledStores, shorthand) && !slices.Contains(filtered, shorthand) {
					filtered = append(filtered, shorthand)
				}
			}
			output = filtered
		}

		sort.Strings(output)

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

	// Filter by user preference, as long as it's listed in the enebled stores
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
		user = "DEMO"
	}
	msg := fmt.Sprintf("[%v] %s requested a '%s' API dump ('%s','%q','%s')", time.Since(start), user, dumpType, filterByEdition, filterByHash, filterByFinish)
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

	if DevMode {
		log.Println(msg)
	} else {
		UserNotify("api", msg)
	}

	if out.Retail == nil && out.Buylist == nil {
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}

	if strings.HasSuffix(urlPath, ".json") {
		json.NewEncoder(w).Encode(&out)
		return
	} else if strings.HasSuffix(urlPath, ".csv") {
		w.Header().Set("Content-Type", "text/csv")
		var err error
		csvWriter := csv.NewWriter(w)
		if out.Retail != nil {
			err = BanPrice2CSV(csvWriter, out.Retail, qty, conds, isSealed)
		} else if out.Buylist != nil {
			err = BanPrice2CSV(csvWriter, out.Buylist, qty, conds, isSealed)
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
	for _, seller := range Sellers {
		if seller == nil {
			continue
		}

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
		inventory, err := seller.Inventory()
		if err != nil {
			log.Println(err)
			continue
		}

		var sellerTag string
		switch tagName {
		default:
			// The default version is a compatibility mode that uses store names
			// when multiple are present (only for mtg)
			if Config.Game == "" {
				shorthand := seller.Info().Shorthand
				if len(ScraperOptions[ScraperMap[shorthand]].Keepers) > 0 {
					sellerTag = ScraperNames[shorthand]
				} else {
					sellerTag = shorthand
				}
			} else {
				sellerTag = seller.Info().Shorthand
			}
		case "names":
			sellerTag = seller.Info().Name
		case "tags":
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

func processEntry[T mtgban.GenericEntry](out map[string]map[string]*BanPrice, entries []T, mode, cardId, filterByEdition, filterByFinish, sellerTag string, qty, conds, shouldBaseCond bool) {
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
	id := getIdFunc(mode)(co)
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
	if out[id][sellerTag] == nil {
		out[id][sellerTag] = &BanPrice{}
	}

	if shouldBaseCond {
		out[id][sellerTag].Cond = entries[0].Condition()
	}

	if conds && out[id][sellerTag].Conditions == nil {
		out[id][sellerTag].Conditions = map[string]float64{}
	}

	if co.Sealed {
		out[id][sellerTag].Sealed = basePrice
		if qty {
			for i := range entries {
				out[id][sellerTag].QtySealed += entries[i].Qty()
			}
		}
	} else if co.Etched {
		out[id][sellerTag].Etched = basePrice
		if qty {
			for i := range entries {
				out[id][sellerTag].QtyEtched += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition() + "_etched"
				out[id][sellerTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][sellerTag].Quantities == nil {
						out[id][sellerTag].Quantities = map[string]int{}
					}
					out[id][sellerTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	} else if co.Foil {
		out[id][sellerTag].Foil = basePrice
		if qty {
			for i := range entries {
				out[id][sellerTag].QtyFoil += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition() + "_foil"
				out[id][sellerTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][sellerTag].Quantities == nil {
						out[id][sellerTag].Quantities = map[string]int{}
					}
					out[id][sellerTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	} else {
		out[id][sellerTag].Regular = basePrice
		if qty {
			for i := range entries {
				out[id][sellerTag].Qty += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				condTag := entries[i].Condition()
				out[id][sellerTag].Conditions[condTag] = entries[i].Pricing()
				if qty && entries[i].Qty() > 0 {
					if out[id][sellerTag].Quantities == nil {
						out[id][sellerTag].Quantities = map[string]int{}
					}
					out[id][sellerTag].Quantities[condTag] = entries[i].Qty()
				}
			}
		}
	}
}

func getVendorPrices(mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}
	for _, vendor := range Vendors {
		if vendor == nil {
			continue
		}

		// Only keep the right proudct type
		if (!sealed && vendor.Info().SealedMode) ||
			(sealed && !vendor.Info().SealedMode) {
			continue
		}

		// Skip any vendor that are not enabled
		if !slices.Contains(enabledStores, vendor.Info().Shorthand) {
			continue
		}

		// Get buylist
		buylist, err := vendor.Buylist()
		if err != nil {
			log.Println(err)
			continue
		}

		var vendorTag string
		switch tagName {
		default:
			// The default version is a compatibility mode that uses store names
			// when multiple are present (only for mtg)
			if Config.Game == "" {
				shorthand := vendor.Info().Shorthand
				if len(ScraperOptions[ScraperMap[shorthand]].KeepersBL) > 0 {
					vendorTag = ScraperNames[shorthand]
				} else {
					vendorTag = shorthand
				}
			} else {
				vendorTag = vendor.Info().Shorthand
			}
		case "names":
			vendorTag = vendor.Info().Name
		case "tags":
			vendorTag = vendor.Info().Shorthand
		}

		// Loop through cards
		shouldQty := qty && !vendor.Info().MetadataOnly
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

func BanPrice2CSV(w *csv.Writer, pm map[string]map[string]*BanPrice, shouldQty, shouldCond, sealed bool) error {
	skuHeader := "UUID"
	header := []string{skuHeader, "TCG Product Id", "Store", "Name", "Edition"}
	if !sealed {
		header = append(header, "Number", "Finish", "Rarity")
	}

	header = append(header, "Price")
	if shouldCond && !sealed {
		header = append(header, "Condition")
	}
	if shouldQty {
		header = append(header, "Quantity")
	}

	err := w.Write(header)
	if err != nil {
		return err
	}

	for id := range pm {
		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			co, err = mtgmatcher.GetUUID(mtgmatcher.Scryfall2UUID(id))
			if err != nil {
				continue
			}
		}

		tcgId := findTCGproductId(co.UUID)

		for scraper, entry := range pm[id] {
			prices := []float64{entry.Regular, entry.Foil, entry.Etched, entry.Sealed}
			qtys := []int{entry.Qty, entry.QtyFoil, entry.QtyEtched, entry.QtySealed}
			finishes := []string{"nonfoil", "foil", "etched", "sealed"}

			for i, price := range prices {
				if price == 0 {
					continue
				}

				cardData := []string{co.Name, co.SetCode}
				if !sealed {
					cardData = append(cardData, co.Number, finishes[i], co.Rarity)
				}

				priceStr := fmt.Sprintf("%0.2f", price)

				var qtyStr string
				if shouldQty && qtys[i] != 0 {
					qtyStr = fmt.Sprintf("%d", qtys[i])
				}

				if shouldCond && !sealed {
					for _, tag := range mtgban.FullGradeTags {
						record := []string{co.UUID, tcgId, scraper}
						record = append(record, cardData...)

						subtag := tag
						if finishes[i] == "foil" || finishes[i] == "etched" {
							subtag += "_" + finishes[i]
						}

						subPrice := entry.Conditions[subtag]
						if subPrice == 0 {
							continue
						}

						condPriceStr := fmt.Sprintf("%0.2f", subPrice)
						record = append(record, condPriceStr, tag)
						if shouldQty {
							var subQtyStr string

							qty := entry.Quantities[subtag]
							if qty != 0 {
								subQtyStr = fmt.Sprintf("%d", qtys[i])
							}

							record = append(record, subQtyStr)
						}

						err = w.Write(record)
						if err != nil {
							return err
						}
					}
				} else {
					var cond string
					if !sealed {
						cond = entry.Cond
					}
					var qty string
					if shouldQty {
						qty = qtyStr
					}

					record := []string{co.UUID, tcgId, scraper}
					record = append(record, cardData...)
					record = append(record, priceStr, cond, qty)

					err = w.Write(record)
					if err != nil {
						return err
					}

				}
			}
		}
		w.Flush()
	}
	return nil
}

// Convert uploadedData to CSV, using the associated map of uuid->keys->prices
func SimplePrice2CSV(w *csv.Writer, pm map[string]map[string]*BanPrice, uploadedDada []UploadEntry) error {
	var allScraperNames []string
	var allScrapers []string
	var isIndex []string
	for id := range pm {
		for scraperKey := range pm[id] {
			// If this scraper is already known, continue
			if slices.Contains(allScrapers, scraperKey) {
				continue
			}
			// If this scraper doesn't have a name (usually due to dev) skip it
			name, found := ScraperNames[scraperKey]
			if !found {
				continue
			}

			// Add to the arrays
			allScraperNames = append(allScraperNames, name)
			allScrapers = append(allScrapers, scraperKey)

			// Determine whether scraper is an index and should appear regardless of conditions
			for _, scraper := range Sellers {
				if scraper != nil && scraper.Info().Shorthand == scraperKey && !slices.Contains(isIndex, scraperKey) && scraper.Info().MetadataOnly {
					isIndex = append(isIndex, scraperKey)
				}
			}
			for _, scraper := range Vendors {
				if scraper != nil && scraper.Info().Shorthand == scraperKey && !slices.Contains(isIndex, scraperKey) && scraper.Info().MetadataOnly {
					isIndex = append(isIndex, scraperKey)
				}
			}
		}
	}

	// Keep alphabetical order
	sort.Strings(allScrapers)
	sort.Strings(allScraperNames)

	header := []string{"Scryfall ID", "Card Name", "Set Code", "Number", "Finish"}
	header = append(header, allScraperNames...)
	header = append(header, "Loaded Price", "Loaded Condition", "Loaded Quantity", "Notes")
	err := w.Write(header)
	if err != nil {
		return err
	}

	for j := range uploadedDada {
		if uploadedDada[j].MismatchError != nil {
			continue
		}

		id := uploadedDada[j].CardId
		_, found := pm[id]
		if !found {
			continue
		}

		var cardName, code, number string
		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			continue
		}
		cardName = co.Name
		code = co.SetCode
		number = co.Number

		prices := make([]string, len(allScrapers))

		for i, scraper := range allScrapers {
			entry, found := pm[id][scraper]
			if !found {
				continue
			}
			condition := uploadedDada[j].OriginalCondition
			if slices.Contains(isIndex, scraper) {
				condition = ""
			}
			price := getPrice(entry, condition)
			prices[i] = fmt.Sprintf("%0.2f", price)
		}
		ogPrice := ""
		if uploadedDada[j].OriginalPrice != 0 {
			ogPrice = fmt.Sprintf("%0.2f", uploadedDada[j].OriginalPrice)
		}
		prices = append(prices, ogPrice)

		prices = append(prices, uploadedDada[j].OriginalCondition)

		qty := ""
		if uploadedDada[j].HasQuantity {
			qty = fmt.Sprint(uploadedDada[j].Quantity)
		}
		prices = append(prices, qty)

		prices = append(prices, uploadedDada[j].Notes)

		scryfallID, found := co.Identifiers["scryfallId"]
		if found {
			id = scryfallID
		}

		record := []string{id, cardName, code, number}
		if co.Etched {
			record = append(record, "etched")
		} else if co.Foil {
			record = append(record, "foil")
		} else {
			record = append(record, "nonfoil")
		}
		record = append(record, prices...)

		err = w.Write(record)
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}
