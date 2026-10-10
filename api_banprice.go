package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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
	APIVersion   = "1"
	APIVersionV2 = "2"
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

// PriceAPIMeta describes a price API response, in every version.
type PriceAPIMeta struct {
	Date    time.Time `json:"date"`
	Version string    `json:"version"`
	BaseURL string    `json:"base_url"`
}

type PriceAPIOutput struct {
	Error string       `json:"error,omitempty"`
	Meta  PriceAPIMeta `json:"meta"`

	// uuid > store > price {regular/foil/etched}
	Retail  map[string]map[string]*BanPrice `json:"retail,omitempty"`
	Buylist map[string]map[string]*BanPrice `json:"buylist,omitempty"`
}

// apiEnabledStores expands the sig's API store option into the concrete
// store list. ALL_ACCESS generates it from the search blocklists at runtime
// (so scrapers added after the sig was issued are picked up), DEV_ACCESS
// sees everything, and an explicit list is taken as-is, BASE_ACCESS filters
// anything sealed or outside the main region unless it is metadata-only; a
// sig's own store list bypasses the blocklists by design.
func apiEnabledStores(storesOpt string) []string {
	var enabledStores []string
	switch storesOpt {
	case "ALL_ACCESS", "DEV_ACCESS", "BASE_ACCESS":
		var blocklistRetail, blocklistBuylist []string
		if storesOpt != "DEV_ACCESS" {
			blocklistRetail = Config().SearchRetailBlockList
			blocklistBuylist = Config().SearchBuylistBlockList
		}
		add := func(info mtgban.ScraperInfo, blocklist []string) {
			if storeEligible(info.Shorthand, nil, blocklist) && !slices.Contains(enabledStores, info.Shorthand) &&
				(storesOpt != "BASE_ACCESS" || baseAccessStoreEligible(info)) {
				enabledStores = append(enabledStores, info.Shorthand)
			}
		}
		for _, seller := range GetSellers() {
			add(seller.Info(), blocklistRetail)
		}
		for _, vendor := range GetVendors() {
			add(vendor.Info(), blocklistBuylist)
		}
	default:
		enabledStores = strings.Split(storesOpt, ",")
	}
	return enabledStores
}

// baseAccessStoreEligible keeps BASE_ACCESS focused on singles in the main
// region, while allowing metadata-only indexes such as Cardmarket Trends to
// contribute even when their source is outside that region.
func baseAccessStoreEligible(info mtgban.ScraperInfo) bool {
	return !info.SealedMode && (info.CountryFlag == "" || info.MetadataOnly)
}

// writeV2Response writes a v2 response, as json.Encoder would encode its
// meta and its retail and buylist maps: the sections are walked card by card
// as they are written, and one with no card is left out.
func writeV2Response(w io.Writer, b *mtgmatcher.Backend, meta PriceAPIMeta, retail, buylist *v2Section) error {
	head, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	_, err = bw.WriteString(`{"meta":`)
	if err != nil {
		return err
	}
	_, err = bw.Write(head)
	if err != nil {
		return err
	}
	for _, section := range []struct {
		name string
		v2   *v2Section
	}{{"retail", retail}, {"buylist", buylist}} {
		if section.v2 == nil {
			continue
		}
		cw := banprice.NewWriter(bw, `,"`+section.name+`":`)
		err = section.v2.walk(b, cw.Card)
		if err != nil {
			return err
		}
		err = cw.Close()
		if err != nil {
			return err
		}
	}
	_, err = bw.WriteString("}\n")
	if err != nil {
		return err
	}
	return bw.Flush()
}

// PriceAPI serves /api/mtgban/, the v1 price API.
func (s *site) PriceAPI(w http.ResponseWriter, r *http.Request) {
	s.priceAPI(w, r, "/api/mtgban/", APIVersion)
}

// PriceAPIv2 serves /api/v2/: the endpoints and options of v1, with every
// price a store has for a card as a list of grades under its finish. qty and
// conds do not apply, since the list always carries both, nor does tag:
// prices are keyed by store shorthand, which stores.json describes. The
// prices' CSV output is v1's, and finishes.json lists the finishes prices
// are keyed by.
func (s *site) PriceAPIv2(w http.ResponseWriter, r *http.Request) {
	s.priceAPI(w, r, "/api/v2/", APIVersionV2)
}

func (s *site) priceAPI(w http.ResponseWriter, r *http.Request, prefix, version string) {
	b := s.backend()
	sig := r.FormValue("sig")
	out := PriceAPIOutput{}
	out.Meta.Date = time.Now()
	out.Meta.Version = version
	out.Meta.BaseURL = absoluteURL(r, "/go/")

	urlPath := strings.TrimPrefix(r.URL.Path, prefix)

	if !strings.HasSuffix(urlPath, ".json") && !strings.HasSuffix(urlPath, ".csv") {
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}
	// kind is the endpoint the path names, ahead of any set or id under it.
	kind, _, _ := strings.Cut(strings.TrimSuffix(strings.TrimSuffix(urlPath, ".json"), ".csv"), "/")
	isFullDump := !strings.Contains(urlPath, "/")

	// Endpoint for retrieving the set codes
	if strings.HasPrefix(urlPath, "sets") {
		sets := b.GetAllSets()
		filter := r.FormValue("filter")
		if filter == "singles" {
			var filtered []string
			for _, code := range sets {
				set, err := b.GetSet(code)
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
				set, err := b.GetSet(code)
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

	// Endpoint for retrieving the finishes v2 keys prices by
	if version == APIVersionV2 && strings.HasPrefix(urlPath, "finishes") {
		finishes := filterV2Finishes(s.datastore().finishes, r.FormValue("filter"))
		if strings.HasSuffix(urlPath, ".json") {
			json.NewEncoder(w).Encode(&finishes)
		} else {
			writeV2FinishesCSV(w, finishes)
		}
		return
	}

	storesOpt := GetParamFromSig(sig, "API")
	if DevMode && !SigCheck && storesOpt == "" {
		storesOpt = "DEV_ACCESS"
	}
	if sig == "" && storesOpt == "" {
		storesOpt = strings.Join(Config().APIDemoStores, ",")
		// Disable a few endpoints for this specific mode
		if isFullDump && (kind == "all" || kind == "retail" || kind == "buylist") {
			out.Error = "Invalid endpoint or missing signature"
			json.NewEncoder(w).Encode(&out)
			return
		}
	}

	enabledStores := apiEnabledStores(storesOpt)

	// Endpoint for retrieving the stores shorthands, and in v2 what each is
	if version == APIVersionV2 && strings.HasPrefix(urlPath, "stores") {
		stores := v2StoreList(enabledStores, r.FormValue("filter"))
		if strings.HasSuffix(urlPath, ".json") {
			json.NewEncoder(w).Encode(&stores)
		} else {
			writeV2StoresCSV(w, stores)
		}
		return
	}
	if strings.HasPrefix(urlPath, "stores") {
		output := enabledStores
		filter := r.FormValue("filter")
		if filter == "singles" || filter == "sealed" {
			filtered := []string{}
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

	if kind != "retail" && kind != "buylist" && kind != "all" && kind != "sealed" {
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}

	enabledModes := strings.Split(GetParamFromSig(sig, "APImode"), ",")
	idOpt := r.FormValue("id")
	if version == APIVersionV2 && idOpt != "" && !slices.Contains(v2IDModes, idOpt) {
		out.Error = fmt.Sprintf("unknown id %q, use one of %s", idOpt, strings.Join(v2IDModes, ", "))
		json.NewEncoder(w).Encode(&out)
		return
	}
	qty, _ := strconv.ParseBool(r.FormValue("qty"))
	conds, _ := strconv.ParseBool(r.FormValue("conds"))
	filterByFinish := r.FormValue("finish")
	// A finish is a single's; a sealed request lists every product
	if kind == "sealed" {
		filterByFinish = ""
	}
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
		set, err := b.GetSet(base)
		if err == nil {
			filterByEdition = set.Code
		} else {
			for _, opts := range [][]bool{
				// Check for nonfoil, foil, etched
				{false, false}, {true, false}, {false, true},
			} {
				uuid, err := b.MatchID(base, opts...)
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
				co, err := b.GetUUID(filterByHash[0])
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
	checkCSVoutput := (filterByEdition == "" && filterByHash == nil && filterByFinish == "") || kind == "all"
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
	isSealed := kind == "sealed" && canSealed
	if isSealed {
		dumpType += "sealed"
	}

	// v2 serves v1's CSV, which already has one row per uuid with its finish
	isV2 := version == APIVersionV2 && strings.HasSuffix(urlPath, ".json")
	var retailV2, buylistV2 *v2Section

	if ((kind == "retail" || kind == "all") && canRetail) || isSealed {
		dumpType += "retail"
		if isV2 {
			retailV2 = sellerSectionV2(b, idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, isSealed)
		} else {
			out.Retail = getSellerPrices(b, idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, qty, conds, isSealed, tagName)
		}
	}
	if ((kind == "buylist" || kind == "all") && canBuylist) || isSealed {
		dumpType += "buylist"
		if isV2 {
			buylistV2 = vendorSectionV2(b, idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, isSealed)
		} else {
			out.Buylist = getVendorPrices(b, idOpt, enabledStores, filterByEdition, filterByHash, filterByFinish, qty, conds, isSealed, tagName)
		}
	}

	user := GetParamFromSig(sig, "UserEmail")
	if sig == "" && user == "" {
		user = "anonymous"
	}
	msg := fmt.Sprintf("%s (%s / %s) requested a '%s' API dump ('%s','%q','%s')", user, r.Header.Get("X-Forwarded-For"), r.RemoteAddr, dumpType, filterByEdition, filterByHash, filterByFinish)
	if qty && !isV2 {
		msg += " with quantities"
	}
	if conds && !isV2 {
		msg += " with conditions"
	}
	if strings.HasSuffix(urlPath, ".json") {
		msg += " in json"
	} else if strings.HasSuffix(urlPath, ".csv") {
		msg += " in csv"
	}
	if version != APIVersion {
		msg += " (v" + version + ")"
	}

	if out.Retail == nil && out.Buylist == nil && retailV2 == nil && buylistV2 == nil {
		APINotify(fmt.Sprintf("[%v] %s", time.Since(start), msg))
		out.Error = "Not found"
		json.NewEncoder(w).Encode(&out)
		return
	}

	// v2 builds its prices as it writes them, so it is timed once written
	if isV2 {
		err := writeV2Response(w, b, out.Meta, retailV2, buylistV2)
		if err != nil {
			log.Println("API v2 write:", err)
		}
		APINotify(fmt.Sprintf("[%v] %s", time.Since(start), msg))
		return
	}
	APINotify(fmt.Sprintf("[%v] %s", time.Since(start), msg))
	if strings.HasSuffix(urlPath, ".json") {
		json.NewEncoder(w).Encode(&out)
		return
	} else if strings.HasSuffix(urlPath, ".csv") {
		var err error
		if out.Retail != nil {
			err = BanPrice2CSV(b, w, out.Retail, nil)
		} else if out.Buylist != nil {
			err = BanPrice2CSV(b, w, out.Buylist, nil)
		}
		if err != nil {
			log.Println(err)
		}
		return
	}

	out.Error = "Internal Server Error"
	json.NewEncoder(w).Encode(&out)
}

// getIDFromMode returns the id the given output mode uses for a card, or ""
// when the card lacks one. This is a plain switch rather than a returned
// closure on purpose: processEntry calls it once per (store, card), and the
// former func-value call both allocated a closure per call and forced the
// freshly copied CardObject to escape to the heap, dominating full-dump
// allocations.
func getIDFromMode(b *mtgmatcher.Backend, mode string, co *mtgmatcher.CardObject) string {
	switch mode {
	case "tcg":
		return findTCGproductID(b, co.UUID)
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
func resolveEditionFilter(b *mtgmatcher.Backend, filterByEdition string, filterByHash []string, sealed bool) []string {
	if filterByHash != nil || filterByEdition == "" {
		return filterByHash
	}
	if sealed {
		return b.GetSealedUUIDsInSet(filterByEdition)
	}
	return b.GetUUIDsInSet(filterByEdition)
}

// apiSearchConfig builds the narrow search config a filtered API request
// funnels through the website's gathering functions: the resolved uuids
// (kept to the sealed/singles partition the endpoint serves, which the
// direct scan used to enforce via the stores' SealedMode flag), the finish
// predicate, and a positive store filter from the caller's enabled stores.
// enabledStores is the whole store policy - explicit sig store lists
// override blocklists by design, and ALL_ACCESS folds them in upstream -
// so no blocklist is applied here.
func apiSearchConfig(b *mtgmatcher.Backend, uuids, enabledStores []string, filterByFinish string, sealed bool) SearchConfig {
	// The set index buckets are read-only, so partition into a fresh slice
	kept := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		co, err := b.GetUUID(uuid)
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
// zero base price drops the store; each grade keeps its best price and its
// total copies, through setGrade like the entry loop. INDEX rows are
// metadata prices whose underlying grade is always NM.
func banPricesFromRows(b *mtgmatcher.Backend, cardIDs []string, found map[string]map[mtgban.Condition][]SearchEntry, idMode, tagName string, qty, conds, vendorSide bool) map[string]map[string]*BanPrice {
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
	for _, cardID := range cardIDs {
		buckets := found[cardID]
		if len(buckets) == 0 {
			continue
		}
		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}
		id := getIDFromMode(b, idMode, co)
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
						price.Cond = string(cond)
					}
				}
				if price == nil {
					continue
				}

				quantity, noQuantity := row.Quantity, row.NoQuantity

				shouldQty := qty && !noQuantity
				if vendorSide {
					// A row is read as a want-count only when its unit says
					// so - !IsOffer() would also let a synthetic row like
					// an average count through, which carries no want at
					// all to sum.
					shouldQty = qty && (!indexStores[row.Shorthand] || row.PriceUnit == PriceUnitCount)
				}
				if shouldQty {
					if co.Sealed {
						price.QtySealed += quantity
					} else if co.Etched {
						price.QtyEtched += quantity
					} else if co.Foil {
						price.QtyFoil += quantity
					} else {
						price.Qty += quantity
					}
				}

				if conds && !co.Sealed {
					condTag := string(cond)
					if condTag == "INDEX" {
						condTag = "NM"
					}
					condTag += suffix
					setGrade(price, condTag, row.Price, quantity, vendorSide, shouldQty)
				}
			}
		}
	}
	return out
}

func getSellerPrices(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}

	// Filtered requests funnel through the shared search gathering: resolve
	// the filter to a uuid list, walk the same path the website search does,
	// and aggregate the rows. Full dumps keep the direct scan below - they
	// have no filter to resolve, and aggregating in place costs orders of
	// magnitude less than materializing rows for the whole pool.
	//
	// apiSearchConfig builds hashing mode with no query, where searchAndFilter
	// only filters the uuids it is handed; filterUUIDs does that directly,
	// without the datastore snapshot searchAndFilter reads.
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(b, uuids, enabledStores, filterByFinish, sealed)
		cardIDs := filterUUIDs(b, config.UUIDs, config.CardFilters)
		return banPricesFromRows(b, cardIDs, searchSellersNG(cardIDs, config), mode, tagName, qty, conds, false)
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
		for cardID := range inventory {
			processEntry(b, out, inventory[cardID], mode, cardID, sellerTag, shouldQty, conds, shouldBaseCond, rule)
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

func processEntry[T mtgban.GenericEntry](b *mtgmatcher.Backend, out map[string]map[string]*BanPrice, entries []T, idMode, cardID, scraperTag string, qty, conds, shouldBaseCond bool, rules ...EntryRule) {
	// Unpriced listings (zero, or a NaN) are ignored throughout, matching the
	// search walk the filtered endpoints ride (shouldSkipPriceNG drops them
	// before they become rows): the base price is the first priced entry, and
	// unpriced entries contribute neither conditions nor quantities. Records
	// sort by grade then price, so the base stays the best grade's cheapest
	// listing.
	base := -1
	for i := range entries {
		if !unpriced(entries[i].Pricing()) {
			base = i
			break
		}
	}
	if base == -1 {
		return
	}
	_, buy := any(entries).([]mtgban.BuylistEntry)
	co, err := b.GetUUID(cardID)
	if err != nil {
		return
	}
	id := getIDFromMode(b, idMode, co)
	if id == "" {
		return
	}

	rate := 1.0
	for _, rule := range rules {
		if len(rule.Finish) > 0 && applyCardFilter(b, "finish", rule.Finish, co) {
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
		out[id][scraperTag].Cond = string(entries[base].Condition())
	}

	if co.Sealed {
		out[id][scraperTag].Sealed = basePrice
		if qty {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				out[id][scraperTag].QtySealed += entries[i].Qty()
			}
		}
	} else if co.Etched {
		out[id][scraperTag].Etched = basePrice
		if qty {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				out[id][scraperTag].QtyEtched += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				condTag := string(entries[i].Condition()) + "_etched"
				setGrade(out[id][scraperTag], condTag, entries[i].Pricing()*rate, entries[i].Qty(), buy, qty)
			}
		}
	} else if co.Foil {
		out[id][scraperTag].Foil = basePrice
		if qty {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				out[id][scraperTag].QtyFoil += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				condTag := string(entries[i].Condition()) + "_foil"
				setGrade(out[id][scraperTag], condTag, entries[i].Pricing()*rate, entries[i].Qty(), buy, qty)
			}
		}
	} else {
		out[id][scraperTag].Regular = basePrice
		if qty {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				out[id][scraperTag].Qty += entries[i].Qty()
			}
		}
		if conds {
			for i := range entries {
				if unpriced(entries[i].Pricing()) {
					continue
				}
				condTag := string(entries[i].Condition())
				setGrade(out[id][scraperTag], condTag, entries[i].Pricing()*rate, entries[i].Qty(), buy, qty)
			}
		}
	}
}

// setGrade files one listing under its grade, which keeps the best price
// (the lowest offer, the highest buy) and the sum of the copies, as v2 does.
func setGrade(price *BanPrice, condTag string, value float64, quantity int, buy, withQty bool) {
	if price.Conditions == nil {
		price.Conditions = &BanConditions{}
	}
	best := price.Conditions.Get(condTag)
	if best == 0 || (buy && value > best) || (!buy && value < best) {
		price.Conditions.Set(condTag, value)
	}
	if withQty && quantity > 0 {
		if price.Quantities == nil {
			price.Quantities = &BanQuantities{}
		}
		price.Quantities.Set(condTag, price.Quantities.Get(condTag)+quantity)
	}
}

func getVendorPrices(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, qty, conds, sealed bool, tagName string) map[string]map[string]*BanPrice {
	out := map[string]map[string]*BanPrice{}

	// Filtered requests funnel through the shared search gathering, exactly
	// like getSellerPrices (see its comment for why filterUUIDs stands in
	// for searchAndFilter here).
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(b, uuids, enabledStores, filterByFinish, sealed)
		cardIDs := filterUUIDs(b, config.UUIDs, config.CardFilters)
		return banPricesFromRows(b, cardIDs, searchVendorsNG(cardIDs, config), mode, tagName, qty, conds, true)
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
		shouldQty := qty && (!vendor.Info().MetadataOnly || vendor.Info().QuantityPriority)
		shouldBaseCond := !vendor.Info().MetadataOnly && !vendor.Info().SealedMode

		rule := EntryRule{
			Finish: finishFilter,
		}
		for cardID := range buylist {
			processEntry(b, out, buylist[cardID], mode, cardID, vendorTag, shouldQty, conds, shouldBaseCond, rule)
		}
	}

	return out
}

// BanPrice2CSV is a convenience wrapper around SimplePrice2CSV that
// writes directly to an http.ResponseWriter.
func BanPrice2CSV(b *mtgmatcher.Backend, httpWriter http.ResponseWriter, pm map[string]map[string]*BanPrice, sorted []string) error {
	httpWriter.Header().Set("Content-Type", "text/csv")
	w := csv.NewWriter(httpWriter)
	return SimplePrice2CSV(b, w, pm, nil, sorted, false)
}

// SimplePrice2CSV converts price data to CSV. When uploadedData is provided,
// each row corresponds to an uploaded entry and includes Loaded columns.
// When uploadedData is nil, rows are derived from the price map keys (using
// sorted for ordering if non-nil).
func SimplePrice2CSV(b *mtgmatcher.Backend, w *csv.Writer, pm map[string]map[string]*BanPrice, uploadedData []UploadEntry, sorted []string, preferFlavor bool) error {
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

	header := []string{"UUID"}
	// The SKU is per condition, so it is only meaningful for uploads,
	// where every row carries the condition it was loaded with
	if hasUploadData {
		header = append(header, "TCGplayer SKU")
	}
	header = append(header, "Card Name", "Set Code", "Edition", "Number", "Finish")
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

			id := uploadedData[j].CardID
			if _, found := pm[id]; !found {
				continue
			}

			condition := uploadedData[j].OriginalCondition

			record, err := priceRowToCSV(b, pm, id, allScrapers, allIndexes, condition, preferFlavor, true)
			if err != nil {
				continue
			}

			ogPrice := ""
			if uploadedData[j].OriginalPrice != 0 {
				ogPrice = fmt.Sprintf("%0.2f", uploadedData[j].OriginalPrice)
			}
			record = append(record, ogPrice, string(condition))

			qty := ""
			if uploadedData[j].HasQuantity {
				qty = fmt.Sprint(uploadedData[j].Quantity)
			}
			record = append(record, qty, uploadedData[j].Notes)

			if err := w.Write(record); err != nil {
				return err
			}
		}
	} else {
		if sorted == nil {
			for id := range pm {
				sorted = append(sorted, id)
			}
		}
		for _, id := range sorted {
			record, err := priceRowToCSV(b, pm, id, allScrapers, allIndexes, "", preferFlavor, false)
			if err != nil {
				continue
			}
			if err := w.Write(record); err != nil {
				return err
			}
		}
	}

	// The csv writer buffers; one flush at the end instead of per row.
	w.Flush()
	return w.Error()
}

func priceRowToCSV(b *mtgmatcher.Backend, pm map[string]map[string]*BanPrice, id string, allScrapers, allIndexes []string, condition mtgban.Condition, preferFlavor, withSKU bool) ([]string, error) {
	co, err := b.GetUUID(id)
	if err != nil {
		uuid := externalUUID(b, id)
		if uuid != "" {
			co, err = b.GetUUID(uuid)
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

	record := []string{displayID}
	if withSKU {
		record = append(record, uuid2TCGSKU(id, co.Sealed, condition))
	}
	record = append(record, cardName, co.SetCode, co.Edition, co.Number, finish)
	record = append(record, prices...)
	return record, nil
}
