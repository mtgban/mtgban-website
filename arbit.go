package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	MaxArbitResults = 450
	MaxPriceRatio   = 120.0
	MinSpread       = 10.0
	MaxSpreadGlobal = 1000
	MinSpreadGlobal = 200.0

	MaxResultsGlobal      = 300
	MaxResultsGlobalLimit = 50
	MinSpreadGlobalPro    = 50

	MinSpreadNegative = -30
	MinDiffNegative   = -100

	ProfConst       = 2
	ProfConstGlobal = 10

	DefaultSortingOption = "profitability"

	// For sealed simulations
	IQRThreshold = 150
)

var FilteredEditions = []string{
	"Collectors’ Edition",
	"Foreign Black Border",
	"Foreign White Border",
	"Intl. Collectors’ Edition",
	"Limited Edition Alpha",
	"Limited Edition Beta",
	"Unlimited Edition",
	"Legends Italian",
	"The Dark Italian",
	"Rinascimento",
	"Chronicles Japanese",
	"Foreign Black Border",
	"Fourth Edition Black Border",
}

// The on/off options, in the order the filter bar lists them. Every
// threshold is a field of arbitState instead.
var FilterOptKeys = []string{
	"rl",
	"abu4h",
	"decklists",
	"syp",
	"stocks",
	"legit",
	"stable",
	"tradable",
}

type FilterOpt struct {
	Title string
	Func  func(*mtgban.ArbitOpts)

	ArbitOnly  bool
	GlobalOnly bool
	NoSealed   bool
	SealedOnly bool

	// Shown only on the reverse page, whose two sides are a seller to buy
	// from and a buylist to sell into
	ReverseOnly bool
}

// Shown reports whether an arbitrage page offers the option, given which
// page it is and whether the source is sealed. The filter bar asks it, and
// arbitState.applied applies only the options it shows.
func (opt FilterOpt) Shown(globalMode, reverseMode, sealedSource bool) bool {
	switch {
	case opt.ArbitOnly && globalMode,
		opt.GlobalOnly && !globalMode,
		opt.ReverseOnly && !reverseMode,
		opt.NoSealed && sealedSource,
		opt.SealedOnly && !sealedSource:
		return false
	}
	return true
}

// User-readable option name and associated function/visibility option
var FilterOptConfig = map[string]FilterOpt{
	"rl": {
		Title: "only RL",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.OnlyReserveList = true
		},
		NoSealed: true,
	},
	"abu4h": {
		Title: "only ABU4H",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.OnlyEditions = ABU4H
		},
		ArbitOnly: true,
		NoSealed:  true,
	},
	"decklists": {
		Title: "only Decklists",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.SealedDecklist = true
		},
		SealedOnly: true,
	},
	"syp": {
		Title: "only SYP",
		Func: func(opts *mtgban.ArbitOpts) {
			oldFunc := opts.CustomCardFilter
			opts.CustomCardFilter = func(co *mtgmatcher.CardObject) (float64, bool) {
				syp, err := findVendorBuylist("SYP")
				if err != nil {
					return 0, true
				}
				_, onSypList := syp[co.UUID]
				if !onSypList {
					return 0, true
				}
				if oldFunc != nil {
					return oldFunc(co)
				}
				return 1, false
			}
		},
		NoSealed:   true,
		GlobalOnly: true,
	},
	"stocks": {
		Title: "only Stocks",
		Func: func(opts *mtgban.ArbitOpts) {
			oldFunc := opts.CustomCardFilter
			opts.CustomCardFilter = func(co *mtgmatcher.CardObject) (float64, bool) {
				inv, _ := findSellerInventory("STKS")
				_, onStocks := inv[co.UUID]
				if !onStocks {
					return 0, true
				}
				if oldFunc != nil {
					return oldFunc(co)
				}
				return 1, false
			}
		},
		NoSealed:   true,
		GlobalOnly: true,
	},
	"legit": {
		Title: "only Legit",
		Func: func(opts *mtgban.ArbitOpts) {
			oldFunc := opts.CustomPriceFilter
			tcgMarket, _ := findSellerInventory("TCGMarket")
			opts.CustomPriceFilter = func(cardId string, invEntry mtgban.InventoryEntry) (float64, bool) {
				if invalidDirectIn(tcgMarket, cardId, invEntry.Price) {
					return 0, true
				}
				if oldFunc != nil {
					return oldFunc(cardId, invEntry)
				}
				return 1, false
			}
		},
		GlobalOnly: true,
		NoSealed:   true,
	},
	"stable": {
		Title: "only Stable",
		Func: func(opts *mtgban.ArbitOpts) {
			oldFunc := opts.CustomPriceFilter
			opts.CustomPriceFilter = func(cardId string, invEntry mtgban.InventoryEntry) (float64, bool) {
				if getTCGSimulationIQR(cardId) > IQRThreshold {
					return 0, true
				}
				if oldFunc != nil {
					return oldFunc(cardId, invEntry)
				}
				return 1, false
			}
		},
		GlobalOnly: true,
		SealedOnly: true,
	},
	"tradable": {
		Title:       "only Tradable",
		ReverseOnly: true,
	},
}

var BadConditions = []mtgban.Condition{mtgban.MP, mtgban.HP, mtgban.PO}

var ABU4H = []string{
	"Limited Edition Alpha",
	"Limited Edition Beta",
	"Unlimited Edition",
	"Arabian Nights",
	"Antiquities",
	"Legends",
	"The Dark",
}

func init() {
	if len(FilterOptKeys) != len(FilterOptConfig) {
		panic("FilterOptKeys length differs from FilterOptConfig")
	}
}

// arbitCardIDs collects the card id of every entry, for resolving their
// sorting data in one pass.
func arbitCardIDs(entries []mtgban.ArbitEntry) []string {
	cardIDs := make([]string, len(entries))
	for i := range entries {
		cardIDs[i] = entries[i].CardID
	}
	return cardIDs
}

// arbitLess returns the comparator for sorting entries in the given
// mode, or nil for unknown modes (caller leaves the slice unsorted,
// matching the prior switch's absence of a default case).
func arbitLess(b *mtgmatcher.Backend, entries []mtgban.ArbitEntry, mode string, globalMode bool) func(i, j *mtgban.ArbitEntry) bool {
	switch mode {
	case "available":
		return func(i, j *mtgban.ArbitEntry) bool {
			return i.InventoryEntry.Quantity > j.InventoryEntry.Quantity
		}
	case "sell_price":
		return func(i, j *mtgban.ArbitEntry) bool {
			return i.InventoryEntry.Price > j.InventoryEntry.Price
		}
	case "buy_price":
		if globalMode {
			return func(i, j *mtgban.ArbitEntry) bool {
				return i.ReferenceEntry.Price > j.ReferenceEntry.Price
			}
		}
		return func(i, j *mtgban.ArbitEntry) bool {
			return i.BuylistEntry.BuyPrice > j.BuylistEntry.BuyPrice
		}
	case "profitability":
		return func(i, j *mtgban.ArbitEntry) bool {
			// Profitability is NaN when spread < 0; fall back to raw
			// spread ordering so the NaN doesn't poison the comparator.
			if i.Spread < 0 || j.Spread < 0 {
				return i.Spread > j.Spread
			}
			return i.Profitability > j.Profitability
		}
	case "diff":
		return func(i, j *mtgban.ArbitEntry) bool {
			return i.Difference > j.Difference
		}
	case "spread":
		return func(i, j *mtgban.ArbitEntry) bool {
			return i.Spread > j.Spread
		}
	case "edition":
		sortData := resolveSortingData(b, arbitCardIDs(entries))
		return func(i, j *mtgban.ArbitEntry) bool {
			if i.CardID == j.CardID {
				return i.InventoryEntry.Conditions < j.InventoryEntry.Conditions
			}
			return cmpSets(sortData[i.CardID], sortData[j.CardID])
		}
	case "alpha":
		sortData := resolveSortingData(b, arbitCardIDs(entries))
		return func(i, j *mtgban.ArbitEntry) bool {
			if i.CardID == j.CardID {
				return i.InventoryEntry.Conditions < j.InventoryEntry.Conditions
			}
			return cmpSetsAlphabetical(sortData[i.CardID], sortData[j.CardID])
		}
	}
	return nil
}

type Arbitrage struct {
	Name  string
	Key   string
	Arbit []mtgban.ArbitEntry

	// Optional multipler to obtain the store credit value
	CreditMultiplier float64

	// Disable the Trade Price column
	HasNoCredit bool

	// Disable the Quantity column
	HasNoQty bool

	// Disable the Conditions column
	HasNoConds bool

	// Disable the Buy Price column
	HasNoPrice bool

	// Disable the Profitability, Difference, and Spread columns
	HasNoArbit bool

	// List of cardId:marketPrice that might not have the best prices
	SussyList map[string]float64
}

// ArbitVars are the PageVars fields only the arbitrage pages (arbit, global,
// reverse) fill and read.
type ArbitVars struct {
	ExtraNav        []NavElem
	DirectStockNote string
	GlobalMode      bool

	// The filter bar, and the state as a query (no source, no sort) for the
	// sort links
	ArbitBar   arbitBar
	ArbitQuery string

	// The cookie the page saves the reader's filters in, and when the saved
	// state it was drawn from was applied, 0 for none
	ArbitCookie  string
	ArbitSavedAt int64
}

func (s *site) Arbit(w http.ResponseWriter, r *http.Request) {
	arbit(s, s.datastore(), w, r, false)
}

func (s *site) Reverse(w http.ResponseWriter, r *http.Request) {
	arbit(s, s.datastore(), w, r, true)
}

func arbit(s *site, ds *datastore, w http.ResponseWriter, r *http.Request, reverse bool) {
	sig := verifiedSignature(r)

	pageName := "Arbitrage"
	if reverse {
		pageName = "Reverse"
	}
	pageVars := genPageNav(s, r, pageName, sig)
	pageVars.ReverseMode = reverse

	var allowlistSellers []string
	allowlistSellersOpt := GetParamFromSig(sig, "ArbitEnabled")

	if allowlistSellersOpt == "ALL" || (DevMode && !SigCheck) {
		allowlistSellers = filterSellers(func(info mtgban.ScraperInfo) bool {
			return !info.MetadataOnly
		})
	} else if allowlistSellersOpt == "" {
		allowlistSellers = Config().ArbitDefaultSellers
	} else {
		allowlistSellers = strings.Split(allowlistSellersOpt, ",")
	}

	blocklistVendors := arbitBlockedVendors(sig)

	if r.FormValue("page") == "options" {
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
		return
	}
	cookieName := "ArbitVendorsList"
	if reverse {
		cookieName = "ReverseVendorsList"
	}

	filters := strings.Split(readCookie(r, cookieName), ",")
	for _, code := range filters {
		if !slices.Contains(blocklistVendors, code) {
			blocklistVendors = append(blocklistVendors, code)
		}
	}

	start := time.Now()

	scraperCompare(ds, w, r, pageVars, allowlistSellers, blocklistVendors, scraperCompareOpts{
		AllResults: true,
	})

	user := GetParamFromSig(sig, "UserEmail")
	msg := fmt.Sprintf("Request by %s took %v", user, time.Since(start))
	UserNotify("arbit", msg)
	LogPages["Arbitrage"].Println(msg)
}

func (s *site) Global(w http.ResponseWriter, r *http.Request) {
	sig := verifiedSignature(r)

	pageVars := genPageNav(s, r, "Global", sig)
	pageVars.GlobalMode = true

	anyEnabledOpt := GetParamFromSig(sig, "AnyEnabled")
	anyEnabled, _ := strconv.ParseBool(anyEnabledOpt)

	anyExperimentOpt := GetParamFromSig(sig, "AnyExperimentsEnabled")
	anyExperiment, _ := strconv.ParseBool(anyExperimentOpt)

	anySpreadOpt := GetParamFromSig(sig, "AnySpread")
	anySpread, _ := strconv.ParseBool(anySpreadOpt)

	anyEnabled = anyEnabled || (DevMode && !SigCheck)
	anyExperiment = anyExperiment || (DevMode && !SigCheck)
	anySpread = anySpread || (DevMode && !SigCheck)

	// The "menu" section, the reference
	allowlistSellers := filterSellers(func(info mtgban.ScraperInfo) bool {
		if anyEnabled {
			// This is the list of allowed global sellers, minus the ones blocked from search
			return slices.Contains(Config().GlobalAllowList, info.Shorthand) &&
				(anyExperiment || !slices.Contains(Config().SearchRetailBlockList, info.Shorthand))
		}
		// These are hardcoded to provide a preview of the tool
		return info.Shorthand == "TCGMarket" || info.Shorthand == "MKMTrend"
	})

	// The "Jump to" section, the probe
	blocklistVendors := globalProbeBlocklist()

	if r.FormValue("page") == "options" {
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
		return
	}

	cookieName := "GlobalVendorsList"

	filters := strings.Split(readCookie(r, cookieName), ",")
	for _, code := range filters {
		if !slices.Contains(blocklistVendors, code) {
			blocklistVendors = append(blocklistVendors, code)
		}
	}

	start := time.Now()

	scraperCompare(s.datastore(), w, r, pageVars, allowlistSellers, blocklistVendors, scraperCompareOpts{
		AllResults: anyEnabled,
		AnySpread:  anySpread,
	})

	user := GetParamFromSig(sig, "UserEmail")
	msg := fmt.Sprintf("Request by %s took %v", user, time.Since(start))
	UserNotify("global", msg)
	LogPages["Global"].Println(msg)
}

// scraperCompareOpts gates the behavior of scraperCompare for its three
// callers (Arbit, Reverse, Global). Replaces the previous positional
// `flags ...bool` whose meaning was decoded from flags[0]/[1]/[2] inside
// the function and required reading the body to understand each call.
type scraperCompareOpts struct {
	AllResults bool // false caps the result list (MaxArbitResults, or MaxResultsGlobalLimit in global mode)
	AnySpread  bool // lower Global's spread floor to MinSpreadGlobalPro
}

// hasNoQty tells whether a table has no quantity column: a store keeping no
// quantities, but for TCGplayer Direct's own stock on reverse, where its
// copies are the table's.
func hasNoQty(scraper mtgban.Scraper, reverseMode bool) bool {
	_, stocked := scraper.(*directStockSeller)
	if reverseMode && stocked && tcgDirectSnapshot(time.Now()) != nil {
		return false
	}
	return scraper.Info().MetadataOnly || scraper.Info().NoQuantityInventory
}

// suspectPriceFor answers the price on a row that one overpriced TCG Direct
// listing can inflate, and nil where the page shows no such price.
//
// Which price it is depends on the page. Global compares against the reference
// seller's own listing, the only mode that fills ReferenceEntry at all. Reverse
// never sees that listing directly, but TCG Direct (net) derives its buy price
// from it, so a single overpriced Direct listing reaches the page as an offer
// to buy.
//
// The derived price is the same price wherever it is shown, so the side it
// arrives on is what names it rather than the page: reverse reads it off the
// source, and arbit off the vendor whose table it is. Keying on the source
// alone left it unwarned on every arbit page, which is where most of it is
// read - one Scrap Trawler offering $23934.02 against a $483.56 listing, and
// a Mox Pearl offering $6941.24 on the pages of five separate sellers.
func suspectPriceFor(globalMode, reverseMode bool, sourceShort, scraperShort string) func(mtgban.ArbitEntry) float64 {
	switch {
	case globalMode && scraperShort == "TCGDirect":
		return func(res mtgban.ArbitEntry) float64 {
			return res.ReferenceEntry.Price
		}
	case reverseMode && sourceShort == "TCGDirectNet":
		return func(res mtgban.ArbitEntry) float64 {
			return res.BuylistEntry.BuyPrice
		}
	case !globalMode && !reverseMode && scraperShort == "TCGDirectNet":
		return func(res mtgban.ArbitEntry) float64 {
			return res.BuylistEntry.BuyPrice
		}
	}
	return nil
}

func scraperCompare(ds *datastore, w http.ResponseWriter, r *http.Request, pageVars PageVars, allowlistSellers []string, blocklistVendors []string, cmp scraperCompareOpts) {
	r.ParseForm()
	b := ds.backend

	var source mtgban.Scraper
	var message string

	limitedResults := !cmp.AllResults

	offer := newArbitOffer(ds)
	savedCookie := arbitSavedCookie(pageVars.GlobalMode)
	state, savedAt := requestArbitState(r.Form, readCookie(r, savedCookie), offer)
	sorting := state.Sort

	for k, v := range r.Form {
		switch k {
		case "source":
			// Source can be a Seller or Vendor depending on operation mode
			if pageVars.ReverseMode {
				if slices.Contains(blocklistVendors, v[0]) {
					log.Println("Unauthorized attempt with", v[0])
					message = "Unknown " + v[0] + " seller"
					break
				}

				for _, vendor := range GetVendors() {
					if vendor.Info().Shorthand == v[0] {
						source = vendor
						break
					}
				}
			} else {
				if !slices.Contains(allowlistSellers, v[0]) {
					log.Println("Unauthorized attempt with", v[0])
					message = "Unknown " + v[0] + " seller"
					break
				}

				for _, seller := range GetSellers() {
					if seller.Info().Shorthand == v[0] {
						source = seller
						// Global prices against Direct; its stock caps no
						// trade there.
						if !pageVars.GlobalMode {
							source = withDirectStock(seller)
						}
						break
					}
				}
			}
			if source == nil {
				message = "Unknown " + v[0] + " source"
			}
		}
	}

	if message != "" {
		pageVars.Title = "Errors have been made"
		pageVars.ErrorMessage = message

		render(w, "arbit.html", pageVars)
		return
	}

	// Set up menu bar, by selecting which scrapers should be selectable as source
	var menuScrapers []mtgban.Scraper
	if pageVars.ReverseMode {
		for _, vendor := range GetVendors() {
			if slices.Contains(blocklistVendors, vendor.Info().Shorthand) {
				continue
			}
			menuScrapers = append(menuScrapers, vendor)
		}
	} else {
		for _, seller := range GetSellers() {
			if !slices.Contains(allowlistSellers, seller.Info().Shorthand) {
				continue
			}
			menuScrapers = append(menuScrapers, seller)
		}
	}

	// Keep the menu in a stable alphabetical order. The scraper snapshots are
	// kept in load order (updates replace entries in place), so without this the
	// menu follows config order instead of name order.
	sort.SliceStable(menuScrapers, func(i, j int) bool {
		return strings.ToLower(scraperName(menuScrapers[i].Info().Shorthand)) <
			strings.ToLower(scraperName(menuScrapers[j].Info().Shorthand))
	})

	// Populate the menu bar with the pool selected above
	for _, scraper := range menuScrapers {
		var link string
		if pageVars.GlobalMode {
			link = "/global"
		} else {
			link = "/arbit"
			if pageVars.ReverseMode {
				link = "/reverse"
			}
		}

		nav := NavElem{
			Name:  scraperName(scraper.Info().Shorthand),
			Short: scraper.Info().Shorthand,
			Link:  link,
		}

		if scraper.Info().SealedMode && !strings.Contains(nav.Name, "Sealed") {
			nav.Name += " Sealed"
		}

		// A store link carries the filters it was asked for, and none where
		// it was asked for none, so the page's defaults still apply there
		v := url.Values{}
		if r.Form.Has(arbitMarker) || !state.isZero() {
			v = state.values()
		}
		v.Set("source", scraper.Info().Shorthand)

		nav.Link += "?" + v.Encode()

		if source != nil && source.Info().Shorthand == scraper.Info().Shorthand {
			nav.Active = true
		}
		pageVars.ExtraNav = append(pageVars.ExtraNav, nav)
	}

	if source == nil {
		if limitedResults {
			pageVars.InfoMessage = "Increase your tier to discover more cards and more markets!"
		}

		render(w, "arbit.html", pageVars)
		return
	}

	pageVars.ScraperShort = source.Info().Shorthand

	pageVars.Arb = []Arbitrage{}
	pageVars.Metadata = map[string]GenericCard{}

	mode := arbitMode{
		Global:    pageVars.GlobalMode,
		Reverse:   pageVars.ReverseMode,
		Sealed:    source.Info().SealedMode,
		AnySpread: cmp.AnySpread,
	}
	opts, rows := state.apply(b, mode)
	applied := state.applied(mode)

	query := state.values()
	query.Del("sort")
	pageVars.ArbitQuery = query.Encode()
	pageVars.ArbitBar = newArbitBar(state, mode, offer, b, source.Info().Shorthand)
	pageVars.ArbitBar.Open = readCookie(r, "ArbitFiltersOpen") == "1"
	pageVars.ArbitCookie = savedCookie
	pageVars.ArbitSavedAt = savedAt

	preferFlavor := readSearchMiscOpts(r).has("preferFlavor")

	// The sealed rows here carry the same link into a product's contents as
	// the search results do, so they follow the same setting.
	pageVars.SealedContents = sealedContentsPref(readCookie(r, "SearchSealedContents"))

	pageVars.DirectStockNote = tcgDirectStockNote()

	// The pool of scrapers that source will be compared against
	var scrapers []mtgban.Scraper
	if pageVars.GlobalMode || pageVars.ReverseMode {
		for _, seller := range GetSellers() {
			// Skip unactionable sellers
			if seller.Info().SealedMode && seller.Info().MetadataOnly {
				continue
			}

			// Keep categories separate
			if source.Info().SealedMode != seller.Info().SealedMode {
				continue
			}

			// Reverse buys Direct's own stock.
			if pageVars.ReverseMode {
				seller = withDirectStock(seller)
			}
			scrapers = append(scrapers, seller)
		}
	} else {
		for _, vendor := range GetVendors() {
			if source.Info().SealedMode != vendor.Info().SealedMode {
				continue
			}

			scrapers = append(scrapers, vendor)
		}
	}

	// The grades the reader dropped, which TCGDirect's own below must not
	// carry over to the scrapers after it.
	conditions := opts.Conditions
	for _, scraper := range scrapers {
		if scraper.Info().Shorthand == source.Info().Shorthand {
			continue
		}
		if slices.Contains(blocklistVendors, scraper.Info().Shorthand) {
			continue
		}

		// An index price is a statistic, not an offer, and reverse buys from
		// the scraper side: where an index has no supply to average it
		// reports a fraction of a cent, and dividing a real buy price by that
		// puts every such row above every real listing on the page. Global
		// keeps them, since there the index is the reference the probe is
		// measured against rather than a side of the trade
		if applied["tradable"] && scraper.Info().MetadataOnly {
			continue
		}

		// Set custom scraper options
		opts.Conditions = conditions
		if pageVars.GlobalMode && scraper.Info().Shorthand == "TCGDirect" {
			opts.Conditions = slices.Clone(conditions)
			for _, grade := range BadConditions {
				if !slices.Contains(opts.Conditions, grade) {
					opts.Conditions = append(opts.Conditions, grade)
				}
			}
		}

		var arbit []mtgban.ArbitEntry
		if pageVars.GlobalMode && source.Info().SealedMode {
			arbit = mtgban.Mismatch(b, opts, source.(mtgban.Seller), scraper.(mtgban.Seller))
		} else if pageVars.GlobalMode {
			arbit = mtgban.Mismatch(b, opts, scraper.(mtgban.Seller), source.(mtgban.Seller))
		} else if pageVars.ReverseMode {
			arbit = mtgban.Arbit(b, opts, source.(mtgban.Vendor), scraper.(mtgban.Seller))
		} else {
			arbit = mtgban.Arbit(b, opts, scraper.(mtgban.Vendor), source.(mtgban.Seller))
		}
		// The side whose copies a row buys: the probe on Global
		seller := source
		if pageVars.ReverseMode || (pageVars.GlobalMode && source.Info().SealedMode) {
			seller = scraper
		}
		arbit = slices.DeleteFunc(arbit, func(res mtgban.ArbitEntry) bool {
			return !rows.keep(res, seller.Info().NoQuantityInventory)
		})
		if !pageVars.GlobalMode && seller.Info().Shorthand == tcgDirectStore {
			arbit = rankDirectAsOneCopy(arbit, opts.MinProfitability)
		}
		if len(arbit) == 0 {
			continue
		}

		// For Global, drop results before sorting, to add some extra variance
		if pageVars.GlobalMode {
			maxResults := MaxResultsGlobal
			// Lower max number of results for the preview
			if limitedResults {
				maxResults = MaxResultsGlobalLimit
			}
			if len(arbit) > maxResults {
				arbit = arbit[:maxResults]
			}
		}

		suspectPrice := suspectPriceFor(pageVars.GlobalMode, pageVars.ReverseMode,
			source.Info().Shorthand, scraper.Info().Shorthand)

		// The same option drops the derived buy prices the market contradicts.
		// "only Legit" cannot reach them: it filters through CustomPriceFilter,
		// which only ever sees the seller's side of the trade. Nor can it reach
		// a Global comparison's reference price because
		// Mismatch hands the filter the probe's entry rather than the
		// reference's: the TCGDirect price it vetted is the reference there,
		// and a Direct listing above twice the market passed. Both are dropped
		// here, on the price suspectPriceFor names for the mode.
		if suspectPrice != nil && (applied["tradable"] || applied["legit"]) {
			tcgMarket, _ := findSellerInventory("TCGMarket")
			arbit = slices.DeleteFunc(arbit, func(res mtgban.ArbitEntry) bool {
				return invalidDirectIn(tcgMarket, res.CardID, suspectPrice(res))
			})
			if len(arbit) == 0 {
				continue
			}
		}

		var sussy map[string]float64
		if !applied["legit"] && !applied["tradable"] && suspectPrice != nil {
			sussy = map[string]float64{}

			tcgMarket, _ := findSellerInventory("TCGMarket")
			for _, res := range arbit {
				isSussy := invalidDirectIn(tcgMarket, res.CardID, suspectPrice(res))
				if isSussy {
					sussy[res.CardID] = tcgMarketPriceIn(tcgMarket, res.CardID)
				}
			}
		}
		if !applied["stable"] && scraper.Info().SealedMode {
			sussy = map[string]float64{}

			for _, res := range arbit {
				iqr := getTCGSimulationIQR(res.CardID)
				if iqr > 150 {
					sussy[res.CardID] = iqr
				}
			}
		}

		// Sort as requested
		if sorting == "" {
			sorting = DefaultSortingOption
		}
		less := arbitLess(b, arbit, sorting, pageVars.GlobalMode)
		if less != nil {
			sort.Slice(arbit, func(i, j int) bool { return less(&arbit[i], &arbit[j]) })
		}
		pageVars.SortOption = sorting

		// For Arbit, drop any excessive results after sorting
		if !pageVars.GlobalMode && len(arbit) > MaxArbitResults {
			arbit = arbit[:MaxArbitResults]
		}

		// The trade credit belongs to whichever side is the vendor: the
		// per-table scraper normally, the shared source in reverse mode
		// (there the scrapers are sellers and the trade-in happens at the
		// source, so its credit policy applies to every table).
		creditInfo := scraper.Info()
		if pageVars.ReverseMode {
			creditInfo = source.Info()
		}

		entry := Arbitrage{
			Name:             scraperName(scraper.Info().Shorthand),
			Key:              scraper.Info().Shorthand,
			Arbit:            arbit,
			HasNoCredit:      creditInfo.CreditMultiplier == 0,
			HasNoQty:         hasNoQty(scraper, pageVars.ReverseMode),
			CreditMultiplier: creditInfo.CreditMultiplier,
			SussyList:        sussy,
		}
		if pageVars.GlobalMode {
			entry.HasNoCredit = true
			entry.HasNoConds = source.Info().MetadataOnly || source.Info().SealedMode
		} else if source.Info().SealedMode {
			entry.HasNoConds = scraper.Info().MetadataOnly
		}

		pageVars.Arb = append(pageVars.Arb, entry)
		for i := range arbit {
			pageVars.Metadata.add(b, arbit[i].CardID, preferFlavor)
		}
	}

	if len(pageVars.Arb) == 0 {
		pageVars.InfoMessage = "No arbitrage available!"
	}

	if pageVars.GlobalMode {
		pageVars.Title = "Market Imbalance in " + scraperName(source.Info().Shorthand)
	} else {
		pageVars.Title = "Arbitrage"
		if pageVars.ReverseMode {
			pageVars.Title += " towards "
		} else {
			pageVars.Title += " from "
		}
		pageVars.Title += scraperName(source.Info().Shorthand)
	}

	render(w, "arbit.html", pageVars)
}
