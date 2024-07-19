package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"golang.org/x/exp/slices"
)

const (
	MaxArbitResults = 450
	MaxPriceRatio   = 120.0
	MinSpread       = 10.0
	MinProfitable   = 4.0
	MaxSpreadGlobal = 1000
	MinSpreadGlobal = 200.0

	MaxResultsGlobal      = 300
	MaxResultsGlobalLimit = 50

	MinSpreadNegative = -30
	MinDiffNegative   = -100

	MinSpreadHighYield       = 100
	MinSpreadHighYieldGlobal = 350

	ProfConst       = 2
	ProfConstGlobal = 10

	DefaultSortingOption = "profitability"
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

// Every single boolean option
var FilterOptKeys = []string{
	"nocond",
	"nofoil",
	"onlyfoil",
	"nocomm",
	"nononrl",
	"nononabu4h",
	"onlyprof",
	"noposi",
	"nopenny",
	"nobuypenny",
	"nolow",
	"nodiff",
	"nodiffplus",
	"noqty",
	"norand",
	"nosyp",
	"nostock",
	"nosus",
}

type FilterOpt struct {
	Title string
	Func  func(*mtgban.ArbitOpts)

	ArbitOnly  bool
	GlobalOnly bool
	BetaFlag   bool
	NoSealed   bool
	SealedOnly bool
}

// User-readable option name and associated function/visibility option
var FilterOptConfig = map[string]FilterOpt{
	"nocond": {
		Title: "only NM/SP",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.Conditions = BadConditions
		},
		NoSealed: true,
	},
	"nofoil": {
		Title: "only non-Foil",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.NoFoil = true
		},
		NoSealed: true,
	},
	"onlyfoil": {
		Title: "only Foil",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.OnlyFoil = true
		},
		NoSealed: true,
	},
	"nocomm": {
		Title: "only Rare/Mythic",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.Rarities = UCRarity
		},
		NoSealed: true,
	},
	"nononrl": {
		Title: "only RL",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.OnlyReserveList = true
		},
		BetaFlag: true,
		NoSealed: true,
	},
	"nononabu4h": {
		Title: "only ABU4H",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.OnlyEditions = ABU4H
		},
		ArbitOnly: true,
		BetaFlag:  true,
		NoSealed:  true,
	},
	"onlyprof": {
		Title: "only Profitable",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinProfitability = MinProfitable
		},
		BetaFlag: true,
		NoSealed: true,
	},
	"noposi": {
		Title: "only Negative",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinSpread = MinSpreadNegative
			opts.MinDiff = MinDiffNegative
			opts.MaxSpread = MinSpread
		},
		ArbitOnly: true,
		NoSealed:  true,
	},
	"nopenny": {
		Title: "only Bucks+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinPrice = 1
		},
		NoSealed: true,
	},
	"nobuypenny": {
		Title: "only BuyBucks+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinBuyPrice = 1
		},
		ArbitOnly: true,
		NoSealed:  true,
	},
	"nolow": {
		Title: "only Yield+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinSpread = MinSpreadHighYield
		},
	},
	"nodiff": {
		Title: "only Difference+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinDiff = 1
		},
	},
	"nodiffplus": {
		Title: "only Difference++",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinDiff = 5
		},
	},
	"noqty": {
		Title: "only Quantity+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.MinQuantity = 1
		},
		ArbitOnly: true,
	},
	"norand": {
		Title: "only Decklists+",
		Func: func(opts *mtgban.ArbitOpts) {
			opts.SealedDecklist = true
		},
		SealedOnly: true,
	},
	"nosyp": {
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
	"nostock": {
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
	"nosus": {
		Title: "only Legit",
		Func: func(opts *mtgban.ArbitOpts) {
			oldFunc := opts.CustomPriceFilter
			opts.CustomPriceFilter = func(cardId string, invEntry mtgban.InventoryEntry) (float64, bool) {
				marketPrice := getTCGMarketPrice(cardId)
				if invEntry.Price/2 > marketPrice {
					return 0, true
				}
				if oldFunc != nil {
					return oldFunc(cardId, invEntry)
				}
				return 1, false
			}
		},
		NoSealed:   true,
		GlobalOnly: true,
	},
}

var BadConditions = []string{"MP", "HP", "PO"}
var UCRarity = []string{"uncommon", "common"}

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

func Arbit(w http.ResponseWriter, r *http.Request) {
	arbit(w, r, false)
}

func Reverse(w http.ResponseWriter, r *http.Request) {
	arbit(w, r, true)
}

func arbit(w http.ResponseWriter, r *http.Request, reverse bool) {
	sig := getSignatureFromCookies(r)

	pageName := "Arbitrage"
	if reverse {
		pageName = "Reverse"
	}
	pageVars := genPageNav(pageName, sig)

	var anyOptionEnabled bool

	var allowlistSellers []string
	allowlistSellersOpt := GetParamFromSig(sig, "ArbitEnabled")

	if allowlistSellersOpt == "ALL" || (DevMode && !SigCheck) {
		for _, seller := range Sellers {
			if seller == nil || seller.Info().MetadataOnly {
				continue
			}
			allowlistSellers = append(allowlistSellers, seller.Info().Shorthand)
		}
		// Enable any option with BetaFlag
		anyOptionEnabled = true
	} else if allowlistSellersOpt == "DEV" {
		allowlistSellers = append(Config.ArbitDefaultSellers, Config.DevSellers...)
	} else if allowlistSellersOpt == "" {
		allowlistSellers = Config.ArbitDefaultSellers
	} else {
		allowlistSellers = strings.Split(allowlistSellersOpt, ",")
	}

	var blocklistVendors []string
	blocklistVendorsOpt := GetParamFromSig(sig, "ArbitDisabledVendors")
	if blocklistVendorsOpt == "" {
		blocklistVendors = Config.ArbitBlockVendors
	} else if blocklistVendorsOpt != "NONE" {
		blocklistVendors = strings.Split(blocklistVendorsOpt, ",")
	}

	if r.FormValue("page") == "opt" {
		// Load all available vendors
		var vendorKeys []string
		if reverse {
			for _, seller := range Sellers {
				if seller == nil || slices.Contains(blocklistVendors, seller.Info().Shorthand) {
					continue
				}
				vendorKeys = append(vendorKeys, seller.Info().Shorthand)
			}
		} else {
			for _, vendor := range Vendors {
				if vendor == nil || slices.Contains(blocklistVendors, vendor.Info().Shorthand) {
					continue
				}
				vendorKeys = append(vendorKeys, vendor.Info().Shorthand)
			}
		}
		pageVars.VendorKeys = vendorKeys
	} else {
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
	}

	pageVars.ReverseMode = reverse

	start := time.Now()

	scraperCompare(w, r, pageVars, allowlistSellers, blocklistVendors, true, anyOptionEnabled)

	user := GetParamFromSig(sig, "UserEmail")
	msg := fmt.Sprintf("Request by %s took %v", user, time.Since(start))
	UserNotify("arbit", msg)
	LogPages["Arbit"].Println(msg)
}

func Global(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Global", sig)

	anyEnabledOpt := GetParamFromSig(sig, "AnyEnabled")
	anyEnabled, _ := strconv.ParseBool(anyEnabledOpt)

	anyExperimentOpt := GetParamFromSig(sig, "AnyExperimentsEnabled")
	anyExperiment, _ := strconv.ParseBool(anyExperimentOpt)

	anyEnabled = anyEnabled || (DevMode && !SigCheck)
	anyExperiment = anyExperiment || (DevMode && !SigCheck)

	// The "menu" section, the reference
	var allowlistSellers []string
	for _, seller := range Sellers {
		if seller == nil {
			continue
		}
		if anyEnabled {
			// This is the list of allowed global sellers, minus the ones blocked from search
			if slices.Contains(Config.GlobalAllowList, seller.Info().Shorthand) {
				if !anyExperiment && slices.Contains(Config.SearchRetailBlockList, seller.Info().Shorthand) {
					continue
				}
				allowlistSellers = append(allowlistSellers, seller.Info().Shorthand)
			} else if anyExperiment && slices.Contains(Config.DevSellers, seller.Info().Shorthand) {
				// Append any experimental ones if enabled
				allowlistSellers = append(allowlistSellers, seller.Info().Shorthand)
			}
		} else {
			// These are hardcoded to provide a preview of the tool
			if seller.Info().Shorthand != TCG_MARKET &&
				seller.Info().Shorthand != MKM_TREND {
				continue
			}
			allowlistSellers = append(allowlistSellers, seller.Info().Shorthand)
		}
	}

	// The "Jump to" section, the probe
	var blocklistVendors []string
	for _, seller := range Sellers {
		if seller == nil {
			continue
		}
		if slices.Contains(Config.GlobalProbeList, seller.Info().Shorthand) {
			continue
		}
		blocklistVendors = append(blocklistVendors, seller.Info().Shorthand)
	}

	// Inform the render this is Global
	pageVars.GlobalMode = true

	start := time.Now()

	scraperCompare(w, r, pageVars, allowlistSellers, blocklistVendors, anyEnabled)

	user := GetParamFromSig(sig, "UserEmail")
	msg := fmt.Sprintf("Request by %s took %v", user, time.Since(start))
	UserNotify("global", msg)
	LogPages["Global"].Println(msg)
}

func scraperCompare(w http.ResponseWriter, r *http.Request, pageVars PageVars, allowlistSellers []string, blocklistVendors []string, flags ...bool) {
	r.ParseForm()

	var source mtgban.Scraper
	var message string
	var sorting string
	arbitFilters := map[string]bool{}

	limitedResults := len(flags) > 0 && !flags[0]
	anyOptionEnabled := len(flags) > 1 && flags[1]

	pageVars.CanShowAll = anyOptionEnabled

	// Set these flags for global, since it's likely users will want them
	if pageVars.GlobalMode {
		arbitFilters["nopenny"] = !arbitFilters["nopenny"]
		arbitFilters["nodiff"] = !arbitFilters["nodiff"]
		arbitFilters["nosus"] = !arbitFilters["nosus"]
	}

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

				for _, vendor := range Vendors {
					if vendor == nil {
						continue
					}
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

				for _, seller := range Sellers {
					if seller == nil {
						continue
					}

					if seller.Info().Shorthand == v[0] {
						source = seller
						break
					}
				}
			}
			if source == nil {
				message = "Unknown " + v[0] + " source"
			}

		case "sort":
			sorting = v[0]

		// Assume anything else is a boolean option
		default:
			// Skip options reserved for arbit-only
			if pageVars.GlobalMode && FilterOptConfig[k].ArbitOnly {
				continue
			}
			// Skip experimental options
			if !anyOptionEnabled && FilterOptConfig[k].BetaFlag {
				continue
			}
			// Skip sealed options when on sealed
			if source != nil && source.Info().SealedMode && FilterOptConfig[k].NoSealed {
				continue
			}
			if source != nil && !source.Info().SealedMode && FilterOptConfig[k].SealedOnly {
				continue
			}
			arbitFilters[k], _ = strconv.ParseBool(v[0])
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
		for _, vendor := range Vendors {
			if vendor == nil || slices.Contains(blocklistVendors, vendor.Info().Shorthand) {
				continue
			}
			menuScrapers = append(menuScrapers, vendor)
		}
	} else {
		for _, seller := range Sellers {
			if seller == nil || !slices.Contains(allowlistSellers, seller.Info().Shorthand) {
				continue
			}
			menuScrapers = append(menuScrapers, seller)
		}
	}

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
			Name:  scraper.Info().Name,
			Short: scraper.Info().Shorthand,
			Link:  link,
		}

		if scraper.Info().SealedMode && !strings.Contains(nav.Name, "Sealed") {
			nav.Name += " Sealed"
		}

		v := url.Values{}
		v.Set("source", scraper.Info().Shorthand)
		for key, val := range arbitFilters {
			v.Set(key, fmt.Sprint(val))
		}
		v.Set("sort", fmt.Sprint(sorting))

		nav.Link += "?" + v.Encode()

		if source != nil && source.Info().Shorthand == scraper.Info().Shorthand {
			nav.Active = true
			nav.Class = "selected"
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

	pageVars.IsSealed = source.Info().SealedMode
	pageVars.ScraperShort = source.Info().Shorthand
	pageVars.HasAffiliate = slices.Contains(Config.AffiliatesList, source.Info().Shorthand)
	pageVars.ArbitFilters = arbitFilters
	pageVars.ArbitOptKeys = FilterOptKeys
	pageVars.ArbitOptConfig = FilterOptConfig

	pageVars.Arb = []Arbitrage{}
	pageVars.Metadata = map[string]GenericCard{}

	opts := &mtgban.ArbitOpts{
		MinSpread:             MinSpread,
		ProfitabilityConstant: ProfConst,
	}

	// Set options
	for _, key := range FilterOptKeys {
		isSet := arbitFilters[key]
		_, hasFunc := FilterOptConfig[key]
		if isSet && hasFunc {
			FilterOptConfig[key].Func(opts)
		}
	}

	// Customize opts for Globals
	if pageVars.GlobalMode && !source.Info().SealedMode {
		opts.MinSpread = MinSpreadGlobal
		opts.MaxSpread = MaxSpreadGlobal
		opts.MaxPriceRatio = MaxPriceRatio

		if arbitFilters["nolow"] {
			opts.MinSpread = MinSpreadHighYieldGlobal
		}
		if arbitFilters["nodiff"] {
			opts.MinDiff = 5
		}
		if arbitFilters["nodiffplus"] {
			opts.MinDiff = 10
		}

		opts.Editions = FilteredEditions
	}

	if !pageVars.GlobalMode && source.Info().SealedMode {
		opts.MinSpread = MinSpreadNegative
		opts.MinDiff = MinDiffNegative
		opts.ProfitabilityConstant = ProfConstGlobal
	}

	// The pool of scrapers that source will be compared against
	var scrapers []mtgban.Scraper
	if pageVars.GlobalMode || pageVars.ReverseMode {
		for _, seller := range Sellers {
			if seller == nil {
				continue
			}

			// Skip unactionable sellers
			if seller.Info().SealedMode && seller.Info().MetadataOnly {
				continue
			}

			// Keep categories separate
			if source.Info().SealedMode != seller.Info().SealedMode {
				continue
			}

			scrapers = append(scrapers, seller)
		}
	} else {
		for _, vendor := range Vendors {
			if vendor == nil || source.Info().SealedMode != vendor.Info().SealedMode {
				continue
			}

			scrapers = append(scrapers, vendor)
		}
	}

	for _, scraper := range scrapers {
		if scraper.Info().Shorthand == source.Info().Shorthand {
			continue
		}
		if slices.Contains(blocklistVendors, scraper.Info().Shorthand) {
			continue
		}

		// Set custom scraper options
		opts.Conditions = nil
		if pageVars.GlobalMode && scraper.Info().Shorthand == TCG_DIRECT {
			opts.Conditions = BadConditions
		}

		var arbit []mtgban.ArbitEntry
		var err error
		if pageVars.GlobalMode && source.Info().SealedMode {
			arbit, err = mtgban.Mismatch(opts, source.(mtgban.Seller), scraper.(mtgban.Seller))
		} else if pageVars.GlobalMode {
			arbit, err = mtgban.Mismatch(opts, scraper.(mtgban.Seller), source.(mtgban.Seller))
		} else if pageVars.ReverseMode {
			arbit, err = mtgban.Arbit(opts, source.(mtgban.Vendor), scraper.(mtgban.Seller))
		} else {
			arbit, err = mtgban.Arbit(opts, scraper.(mtgban.Vendor), source.(mtgban.Seller))
		}
		if err != nil {
			log.Println(err)
			continue
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

		// Gather all the card Ids that might be invalid
		var sussy map[string]float64
		if !arbitFilters["nosus"] && scraper.Info().Shorthand == TCG_DIRECT {
			sussy = map[string]float64{}

			for _, res := range arbit {
				marketPrice := getTCGMarketPrice(res.CardId)
				if res.ReferenceEntry.Price/2 > marketPrice {
					sussy[res.CardId] = marketPrice
				}
			}
		}

		// Sort as requested
		if sorting == "" {
			sorting = DefaultSortingOption
		}
		switch sorting {
		case "available":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].InventoryEntry.Quantity > arbit[j].InventoryEntry.Quantity
			})
		case "sell_price":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].InventoryEntry.Price > arbit[j].InventoryEntry.Price
			})
		case "buy_price":
			if pageVars.GlobalMode {
				sort.Slice(arbit, func(i, j int) bool {
					return arbit[i].ReferenceEntry.Price > arbit[j].ReferenceEntry.Price
				})
			} else {
				sort.Slice(arbit, func(i, j int) bool {
					return arbit[i].BuylistEntry.BuyPrice > arbit[j].BuylistEntry.BuyPrice
				})
			}
		case "profitability":
			sort.Slice(arbit, func(i, j int) bool {
				// Profitability is NaN when spread is less than 0
				if arbit[i].Spread < 0 || arbit[j].Spread < 0 {
					return arbit[i].Spread > arbit[j].Spread
				}
				return arbit[i].Profitability > arbit[j].Profitability
			})
		case "diff":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].Difference > arbit[j].Difference
			})
		case "spread":
			sort.Slice(arbit, func(i, j int) bool {
				return arbit[i].Spread > arbit[j].Spread
			})
		case "edition":
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardId == arbit[j].CardId {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return sortSets(arbit[i].CardId, arbit[j].CardId)
			})
		case "alpha":
			sort.Slice(arbit, func(i, j int) bool {
				if arbit[i].CardId == arbit[j].CardId {
					return arbit[i].InventoryEntry.Conditions < arbit[j].InventoryEntry.Conditions
				}
				return sortSetsAlphabetical(arbit[i].CardId, arbit[j].CardId)
			})
		}
		pageVars.SortOption = sorting

		// For Arbit, drop any excessive results after sorting
		if !pageVars.GlobalMode && len(arbit) > MaxArbitResults {
			arbit = arbit[:MaxArbitResults]
		}

		name := scraper.Info().Name
		switch name {
		case "Sealed EV Scraper":
			name = "Card Kingdom Singles Buylist"
		}

		entry := Arbitrage{
			Name:             name,
			Key:              scraper.Info().Shorthand,
			Arbit:            arbit,
			HasNoCredit:      scraper.Info().CreditMultiplier == 0,
			HasNoQty:         scraper.Info().MetadataOnly || scraper.Info().NoQuantityInventory,
			CreditMultiplier: scraper.Info().CreditMultiplier,
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
			cardId := arbit[i].CardId
			_, found := pageVars.Metadata[cardId]
			if found {
				continue
			}
			pageVars.Metadata[cardId] = uuid2card(cardId, true)
			if pageVars.Metadata[cardId].Reserved {
				pageVars.HasReserved = true
			}
			if pageVars.Metadata[cardId].Stocks {
				pageVars.HasStocks = true
			}
			if pageVars.Metadata[cardId].SypList {
				pageVars.HasSypList = true
			}
		}
	}

	if len(pageVars.Arb) == 0 {
		pageVars.InfoMessage = "No arbitrage available!"
	}

	if pageVars.GlobalMode {
		pageVars.Title = "Market Imbalance in " + source.Info().Name
	} else {
		pageVars.Title = "Arbitrage"
		if pageVars.ReverseMode {
			pageVars.Title += " towards "
		} else {
			pageVars.Title += " from "
		}
		pageVars.Title += source.Info().Name
	}

	render(w, "arbit.html", pageVars)
}
