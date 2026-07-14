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

	"github.com/mtgban/mtgban-website/banprice"
)

const (
	APIVersion = "1"
)

// The price API wire types live in the banprice package, importable by
// external consumers of the API; these aliases keep the website-wide
// BanPrice naming.
type (
	BanPrice      = banprice.Price
	BanConditions = banprice.Conditions
	BanQuantities = banprice.Quantities
)

var conditionTags = banprice.ConditionTags

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

// apiEnabledStores expands the sig's API store option into the concrete
// store list. ALL_ACCESS generates it from the search blocklists at runtime
// (so scrapers added after the sig was issued are picked up), DEV_ACCESS
// sees everything, and an explicit list is taken as-is: a sig's own store
// list bypasses the blocklists by design.
func apiEnabledStores(storesOpt string) []string {
	var enabledStores []string
	switch storesOpt {
	case "ALL_ACCESS", "DEV_ACCESS":
		var blocklistRetail, blocklistBuylist []string
		if storesOpt == "ALL_ACCESS" {
			blocklistRetail = Config.SearchRetailBlockList
			blocklistBuylist = Config.SearchBuylistBlockList
		}
		for _, seller := range GetSellers() {
			shorthand := seller.Info().Shorthand
			if storeEligible(shorthand, nil, blocklistRetail) && !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
		for _, vendor := range GetVendors() {
			shorthand := vendor.Info().Shorthand
			if storeEligible(shorthand, nil, blocklistBuylist) && !slices.Contains(enabledStores, shorthand) {
				enabledStores = append(enabledStores, shorthand)
			}
		}
	default:
		enabledStores = strings.Split(storesOpt, ",")
	}
	return enabledStores
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

	enabledStores := apiEnabledStores(storesOpt)

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
			if storeEligible(filtered, enabledStores, nil) {
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
	canRetail := canAccessMode(enabledModes, "retail")
	canBuylist := canAccessMode(enabledModes, "buylist")
	canSealed := canAccessMode(enabledModes, "sealed")
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

// getIdFromMode returns the id the given output mode uses for a card, or ""
// when the card lacks one. This is a plain switch rather than a returned
// closure on purpose: processEntry calls it once per (store, card), and the
// former func-value call both allocated a closure per call and forced the
// freshly copied CardObject to escape to the heap, dominating full-dump
// allocations.
func getIdFromMode(mode string, co *mtgmatcher.CardObject) string {
	switch mode {
	case "tcg":
		return findTCGproductId(co.UUID)
	case "scryfall":
		return co.Identifiers["scryfallId"]
	case "mtgjson":
		if co.Sealed {
			return co.UUID
		}
		return co.Identifiers["mtgjsonId"]
	case "name":
		if co.Sealed {
			return co.Name
		}
		return fmt.Sprintf("%s|%s|%s", co.Name, co.SetCode, co.Number)
	case "mkm":
		return co.Identifiers["mcmId"]
	case "ck":
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
	return co.UUID
}

// resolveEditionFilter turns an edition filter into the uuid list to walk:
// scanning whole inventories and checking the set code per entry was the
// dominant cost of edition dumps. Returns nil for an unknown set, which
// callers treat as no results.
func resolveEditionFilter(filterByEdition string, filterByHash []string, sealed bool) []string {
	if filterByHash != nil || filterByEdition == "" {
		return filterByHash
	}
	if sealed {
		return mtgmatcher.GetSealedUUIDsInSet(filterByEdition)
	}
	return mtgmatcher.GetUUIDsInSet(filterByEdition)
}

// apiSearchConfig builds the narrow search config a filtered API request
// funnels through the website's gathering functions: the resolved uuids
// (kept to the sealed/singles partition the endpoint serves, which the
// direct scan used to enforce via the stores' SealedMode flag), the finish
// predicate, and a positive store filter from the caller's enabled stores.
// enabledStores is the whole store policy - explicit sig store lists
// override blocklists by design, and ALL_ACCESS folds them in upstream -
// so no blocklist is applied here.
func apiSearchConfig(uuids, enabledStores []string, filterByFinish string, sealed bool) SearchConfig {
	// The set index buckets are read-only, so partition into a fresh slice
	kept := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		co, err := mtgmatcher.GetUUID(uuid)
		if err == nil && co.Sealed == sealed {
			kept = append(kept, uuid)
		}
	}

	stores := make([]string, len(enabledStores))
	for i := range enabledStores {
		stores[i] = strings.ToLower(enabledStores[i])
	}

	config := SearchConfig{
		SearchMode: "hashing",
		UUIDs:      kept,
		StoreFilters: []FilterStoreElem{
			{Name: "seller", Values: stores, OnlyForSeller: true},
			{Name: "vendor", Values: stores, OnlyForVendor: true},
		},
	}
	if filterByFinish != "" {
		config.CardFilters = []FilterElem{{
			Name:   "finish",
			Values: fixupFinishNG(filterByFinish),
		}}
	}
	return config
}

// banPricesFromRows aggregates the search walk's per-condition rows into the
// BanPrice map the price API serves, mirroring the direct processEntry scan:
// rows preserve record order (best grade first, then price), so the first
// row seen per store is the record's best entry and keys the base price; a
// zero base price drops the store; Conditions are last-write-wins within a
// grade exactly like the entry loop. INDEX rows are metadata prices whose
// underlying grade is always NM.
func banPricesFromRows(cardIds []string, found map[string]map[string][]SearchEntry, idMode, tagName string, qty, conds, vendorSide bool) map[string]map[string]*BanPrice {
	// Rows carry neither MetadataOnly (the vendor qty rule needs it: sealed
	// metadata vendors keep their grade bucket, so INDEX membership is not
	// a reliable proxy) nor the raw scraper name (SearchEntry.ScraperName
	// has NameOverride applied), so look up the side's info once.
	var names map[string]string
	var indexStores map[string]bool
	if vendorSide {
		indexStores = map[string]bool{}
		names = map[string]string{}
		for _, vendor := range GetVendors() {
			indexStores[vendor.Info().Shorthand] = vendor.Info().MetadataOnly
			names[vendor.Info().Shorthand] = vendor.Info().Name
		}
	} else {
		names = map[string]string{}
		for _, seller := range GetSellers() {
			names[seller.Info().Shorthand] = seller.Info().Name
		}
	}

	out := map[string]map[string]*BanPrice{}
	for _, cardId := range cardIds {
		buckets := found[cardId]
		if len(buckets) == 0 {
			continue
		}
		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			continue
		}
		id := getIdFromMode(idMode, co)
		if id == "" {
			continue
		}

		suffix := ""
		if co.Etched {
			suffix = "_etched"
		} else if co.Foil {
			suffix = "_foil"
		}

		// Per-store output for this card; nil marks a store dropped for a
		// zero base price. Different uuids can share an output id (a name
		// or tcg id spans finishes), so entries merge into out across cards.
		prices := map[string]*BanPrice{}
		for _, cond := range AllConditions {
			for i := range buckets[cond] {
				row := &buckets[cond][i]

				price, seen := prices[row.Shorthand]
				if !seen {
					// First row per store is the record's best entry. The
					// zero check is defensive only: the walk already drops
					// zero-priced entries (shouldSkipPriceNG), the same
					// contract processEntry applies to the full dumps.
					if row.Price == 0 {
						prices[row.Shorthand] = nil
						continue
					}
					tag := row.Shorthand
					if tagName == "names" {
						// The scraper list is looked up separately from the
						// walk's, so a concurrent reload swap can leave a
						// shorthand unmapped; fall back rather than keying
						// the output on an empty string
						if name := names[row.Shorthand]; name != "" {
							tag = name
						}
					}
					if out[id] == nil {
						out[id] = map[string]*BanPrice{}
					}
					price = out[id][tag]
					if price == nil {
						price = &BanPrice{}
						out[id][tag] = price
					}
					prices[row.Shorthand] = price

					if co.Sealed {
						price.Sealed = row.Price
					} else if co.Etched {
						price.Etched = row.Price
					} else if co.Foil {
						price.Foil = row.Price
					} else {
						price.Regular = row.Price
					}
					if cond != "INDEX" && !co.Sealed {
						price.Cond = cond
					}
				}
				if price == nil {
					continue
				}

				shouldQty := qty && !row.NoQuantity
				if vendorSide {
					shouldQty = qty && (!indexStores[row.Shorthand] || row.Shorthand == "SYP")
				}
				if shouldQty {
					if co.Sealed {
						price.QtySealed += row.Quantity
					} else if co.Etched {
						price.QtyEtched += row.Quantity
					} else if co.Foil {
						price.QtyFoil += row.Quantity
					} else {
						price.Qty += row.Quantity
					}
				}

				if conds && !co.Sealed {
					condTag := cond
					if condTag == "INDEX" {
						condTag = "NM"
					}
					condTag += suffix
					if price.Conditions == nil {
						price.Conditions = &BanConditions{}
					}
					price.Conditions.Set(condTag, row.Price)
					if shouldQty && row.Quantity > 0 {
						if price.Quantities == nil {
							price.Quantities = &BanQuantities{}
						}
						price.Quantities.Set(condTag, row.Quantity)
					}
				}
			}
		}
	}
	return out
}

func getSellerPrices(mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}

	// Filtered requests funnel through the shared search gathering: resolve
	// the filter to a uuid list, walk the same path the website search does,
	// and aggregate the rows. Full dumps keep the direct scan below - they
	// have no filter to resolve, and aggregating in place costs orders of
	// magnitude less than materializing rows for the whole pool.
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(uuids, enabledStores, filterByFinish, sealed)
		cardIds, err := searchAndFilter(config)
		if err != nil {
			return out
		}
		return banPricesFromRows(cardIds, searchSellersNG(cardIds, config), mode, tagName, qty, conds, false)
	}

	var finishFilter []string
	if filterByFinish != "" {
		finishFilter = fixupFinishNG(filterByFinish)
	}

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

		rule := EntryRule{
			Finish: finishFilter,
		}
		for cardId := range inventory {
			processEntry(out, inventory[cardId], mode, cardId, sellerTag, shouldQty, conds, shouldBaseCond, rule)
		}
	}

	return out
}

type EntryRule struct {
	// Finish holds fixupFinishNG values and is applied through the same
	// finish predicate the search filters use
	Finish []string

	MinPrice float64
	Rate     float64
}

func processEntry[T mtgban.GenericEntry](out map[string]map[string]*BanPrice, entries []T, idMode, cardId, scraperTag string, qty, conds, shouldBaseCond bool, rules ...EntryRule) {
	// Zero-priced listings are ignored throughout, matching the search walk
	// the filtered endpoints ride (shouldSkipPriceNG drops them before they
	// become rows): the base price is the first nonzero entry, and zero
	// entries contribute neither conditions nor quantities. Records sort by
	// grade then price, so the base stays the best grade's cheapest listing.
	base := -1
	for i := range entries {
		if entries[i].Pricing() != 0 {
			base = i
			break
		}
	}
	if base == -1 {
		return
	}
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return
	}
	id := getIdFromMode(idMode, co)
	if id == "" {
		return
	}

	rate := 1.0
	for _, rule := range rules {
		if len(rule.Finish) > 0 && applyCardFilter("finish", rule.Finish, co) {
			return
		}
		if entries[base].Pricing() < rule.MinPrice {
			return
		}
		if rule.Rate != 0 {
			rate = rule.Rate
		}
	}

	basePrice := entries[base].Pricing() * rate

	_, found := out[id]
	if !found {
		out[id] = map[string]*BanPrice{}
	}
	if out[id][scraperTag] == nil {
		out[id][scraperTag] = &BanPrice{}
	}

	if shouldBaseCond {
		out[id][scraperTag].Cond = entries[base].Condition()
	}

	if co.Sealed {
		out[id][scraperTag].Sealed = basePrice
		if qty {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				out[id][scraperTag].QtySealed += entries[i].Qty()
			}
		}
	} else if co.Etched {
		out[id][scraperTag].Etched = basePrice
		if qty {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				out[id][scraperTag].QtyEtched += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				condTag := entries[i].Condition() + "_etched"
				if out[id][scraperTag].Conditions == nil {
					out[id][scraperTag].Conditions = &BanConditions{}
				}
				out[id][scraperTag].Conditions.Set(condTag, entries[i].Pricing()*rate)
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = &BanQuantities{}
					}
					out[id][scraperTag].Quantities.Set(condTag, entries[i].Qty())
				}
			}
		}
	} else if co.Foil {
		out[id][scraperTag].Foil = basePrice
		if qty {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				out[id][scraperTag].QtyFoil += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				condTag := entries[i].Condition() + "_foil"
				if out[id][scraperTag].Conditions == nil {
					out[id][scraperTag].Conditions = &BanConditions{}
				}
				out[id][scraperTag].Conditions.Set(condTag, entries[i].Pricing()*rate)
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = &BanQuantities{}
					}
					out[id][scraperTag].Quantities.Set(condTag, entries[i].Qty())
				}
			}
		}
	} else {
		out[id][scraperTag].Regular = basePrice
		if qty {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				out[id][scraperTag].Qty += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if entries[i].Pricing() == 0 {
					continue
				}
				condTag := entries[i].Condition()
				if out[id][scraperTag].Conditions == nil {
					out[id][scraperTag].Conditions = &BanConditions{}
				}
				out[id][scraperTag].Conditions.Set(condTag, entries[i].Pricing()*rate)
				if qty && entries[i].Qty() > 0 {
					if out[id][scraperTag].Quantities == nil {
						out[id][scraperTag].Quantities = &BanQuantities{}
					}
					out[id][scraperTag].Quantities.Set(condTag, entries[i].Qty())
				}
			}
		}
	}
}

func getVendorPrices(mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}

	// Filtered requests funnel through the shared search gathering, exactly
	// like getSellerPrices
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(uuids, enabledStores, filterByFinish, sealed)
		cardIds, err := searchAndFilter(config)
		if err != nil {
			return out
		}
		return banPricesFromRows(cardIds, searchVendorsNG(cardIds, config), mode, tagName, qty, conds, true)
	}

	var finishFilter []string
	if filterByFinish != "" {
		finishFilter = fixupFinishNG(filterByFinish)
	}

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

		rule := EntryRule{
			Finish: finishFilter,
		}
		for cardId := range buylist {
			processEntry(out, buylist[cardId], mode, cardId, vendorTag, shouldQty, conds, shouldBaseCond, rule)
		}
	}

	return out
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
