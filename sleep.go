package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type Sleeper struct {
	CardId string
	Level  int
}

const (
	SleeperSize = 7
	MaxSleepers = 34
	MaxSpread   = 650.0

	SleepersMinPrice = 3.0

	ErrNoSleepers = "No Sleepers Available (please try again in a few minutes)"
)

var SleeperLetters = []string{
	"S", "A", "B", "C", "D", "E", "F",
}
var SleeperColors = []string{
	"#ff7f7f", "#ffbf7f", "#ffff7f", "#7fff7f", "#7fbfff", "#7f7fff", "#ff7fff",
}

func Sleepers(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Sleepers", sig)

	// Load the defaul blocklist (same as Search)
	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	// Expand with any custom list if necessary
	if Config.SleepersBlockList != nil {
		blocklistRetail = append(blocklistRetail, Config.SleepersBlockList...)
		blocklistBuylist = append(blocklistBuylist, Config.SleepersBlockList...)
	}

	skipSellersOpt := readCookie(r, "SleepersSellersList")
	if skipSellersOpt != "" {
		blocklistRetail = append(blocklistRetail, strings.Split(skipSellersOpt, ",")...)
	}
	skipVendorsOpt := readCookie(r, "SleepersVendorsList")
	if skipVendorsOpt != "" {
		blocklistBuylist = append(blocklistBuylist, strings.Split(skipVendorsOpt, ",")...)
	}

	var skipEditions []string
	skipEditionsOpt := readCookie(r, "SleepersEditionList")
	if skipEditionsOpt != "" {
		skipEditions = strings.Split(skipEditionsOpt, ",")
	}

	for _, seller := range Sellers {
		if seller.Info().SealedMode ||
			slices.Contains(blocklistRetail, seller.Info().Shorthand) {
			continue
		}

		pageVars.SellerKeys = append(pageVars.SellerKeys, seller.Info().Shorthand)
	}

	cyoa, _ := strconv.ParseBool(GetParamFromSig(sig, "SleepersCYOA"))
	pageVars.CanShowAll = cyoa || (DevMode && !SigCheck)

	var tiers map[string]int

	start := time.Now()

	page := r.FormValue("page")
	switch page {
	default:
		pageVars.Subtitle = "Index"

		render(w, "sleep.html", pageVars)

		return
	case "options":
		pageVars.Subtitle = "Options"

		var sellerKeys, vendorKeys []string
		for _, seller := range Sellers {
			if seller.Info().CountryFlag != "" ||
				seller.Info().SealedMode ||
				seller.Info().MetadataOnly ||
				slices.Contains(blocklistRetail, seller.Info().Shorthand) {
				continue
			}

			sellerKeys = append(sellerKeys, seller.Info().Shorthand)
		}

		for _, vendor := range Vendors {
			if vendor.Info().CountryFlag != "" ||
				vendor.Info().SealedMode ||
				vendor.Info().MetadataOnly ||
				slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
				continue
			}

			vendorKeys = append(vendorKeys, vendor.Info().Shorthand)
		}

		pageVars.Editions = AllEditionsKeys
		pageVars.EditionsMap = AllEditionsMap
		pageVars.SellerKeys = sellerKeys
		pageVars.VendorKeys = vendorKeys

		render(w, "sleep.html", pageVars)

		return
	case "bulk":
		pageVars.Subtitle = "Bulk me up"

		tiers = getBulks(skipEditions)

	case "reprint":
		pageVars.Subtitle = "Long time no reprint"

		tiers = getReprints(skipEditions)
	case "mismatch":
		pageVars.Subtitle = "Market Mismatch"

		tiers = getTiers(blocklistRetail, blocklistBuylist, skipEditions)
	case "gap":
		pageVars.Subtitle = "Ocean Gap"

		ref, target := r.FormValue("ref"), r.FormValue("target")
		tiers = getGap(blocklistRetail, ref, target, skipEditions)
	case "hotlist":
		pageVars.Subtitle = "Highest buylist growth"

		tiers = getHotlist(skipEditions)
	}

	sleepers, err := sleepersLayout(tiers)
	if err != nil {
		ServerNotify("sleep", "unable to generate sleepers: "+err.Error())

		pageVars.Title = "Errors have been made"
		pageVars.InfoMessage = ErrNoSleepers

		render(w, "sleep.html", pageVars)
		return
	}

	miscSearchOpts := strings.Split(readCookie(r, "SearchMiscOpts"), ",")
	preferFlavor := slices.Contains(miscSearchOpts, "preferFlavor")
	pageVars.ShowUpsell = !slices.Contains(miscSearchOpts, "noUpsell")

	pageVars.Metadata = map[string]GenericCard{}
	for _, cardIds := range sleepers {
		for _, cardId := range cardIds {
			_, found := pageVars.Metadata[cardId]
			if !found {
				pageVars.Metadata[cardId] = uuid2card(cardId, true, false, preferFlavor)
			}
		}
	}

	pageVars.Sleepers = sleepers
	pageVars.SleepersKeys = SleeperLetters
	pageVars.SleepersColors = SleeperColors

	// Log performance
	user := GetParamFromSig(sig, "UserEmail")
	msg := fmt.Sprintf("Sleepers call by %s with took %v", user, time.Since(start))
	UserNotify("sleepers", msg)
	LogPages["Sleepers"].Println(msg)

	if DevMode {
		start = time.Now()
	}
	render(w, "sleep.html", pageVars)
	if DevMode {
		log.Println("Sleepers render took", time.Since(start))
	}
}

func getBulks(skipEditions []string) map[string]int {
	inv, err := findSellerInventory("TCGLow")
	if err != nil {
		return nil
	}
	bl, err := findVendorBuylist("CK")
	if err != nil {
		return nil
	}

	tiers := map[string]int{}

	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil || slices.Contains(skipEditions, set.Code) {
			continue
		}

		switch set.Code {
		case "OPCA", "PLST", "MB2", "30A":
			continue
		}

		// Skip anything older than 5 years
		releaseDate, err := time.Parse("2006-01-02", set.ReleaseDate)
		if err != nil {
			continue
		}
		if time.Now().Sub(releaseDate).Hours()/24/365 > 5 {
			continue
		}

		count := 0
		cardPrices := map[string]float64{}
		var totalPrices float64
		for _, card := range set.Cards {
			uuid := mtgmatcher.Scryfall2UUID(card.Identifiers["scryfallId"])
			co, err := mtgmatcher.GetUUID(uuid)
			if err != nil {
				continue
			}
			if co.Foil || co.Etched || co.IsPromo ||
				co.HasPromoType(mtgmatcher.PromoTypeBoosterfun) ||
				co.HasPromoType(mtgmatcher.PromoTypePromoPack) {
				continue
			}

			// Only consider common and uncommon cards
			entries, found := inv[uuid]
			if !found {
				continue
			}
			if card.Rarity == "common" || card.Rarity == "uncommon" {
				count++
				price := entries[0].Price
				totalPrices += price
				cardPrices[uuid] = price
			}
		}
		if count == 0 {
			continue
		}

		averagePrice := totalPrices / float64(count)

		for uuid, price := range cardPrices {
			if price < averagePrice {
				continue
			}

			// Assign a value considering how big of a gap the minimum price has
			tiers[uuid] = int(price-averagePrice) + 1

			// Assign additional value if buylist has non-bulk worth
			var blPrice float64
			blEntries, found := bl[uuid]
			if found {
				blPrice = blEntries[0].BuyPrice
			}
			if blPrice > SleepersMinPrice {
				tiers[uuid] += 1
			}
		}
	}

	return tiers
}

func getHotlist(skipEditions []string) map[string]int {
	tiers := map[string]int{}

	bl, _ := findVendorBuylist("CK")

	// Skip bad editions
	skipEditions = append(skipEditions, "30A", "PTK", "CED", "CEI", "CMB1", "CMB2")

	for cardId, hotlistEntries := range Infos["hotlist"] {
		// Make sure the older price is set, otherwise a lot of cards that were
		// previously not being bought will show up and pollute results
		oldPrice := hotlistEntries[0].Price
		if oldPrice == 0 {
			continue
		}

		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil || slices.Contains(skipEditions, co.SetCode) {
			continue
		}

		var currentPrice float64
		currentEntries, found := bl[cardId]
		if found {
			currentPrice = currentEntries[0].BuyPrice
		}

		difference := currentPrice - oldPrice
		spread := 100 * (currentPrice - oldPrice) / oldPrice

		// Modeled after the "profitability" formula, coupling spread and difference
		tiers[cardId] = int(100 * difference / (currentPrice + 10) * math.Log(1+spread))
	}

	return tiers
}

func getReprints(skipEditions []string) map[string]int {
	tiers := map[string]int{}

	// Filter results
	for _, key := range ReprintsKeys {
		reprints, found := ReprintsMap[key]
		if !found {
			continue
		}

		var minPrice float64
		var uuid string
		latest := reprints[0].Date

		for _, reprint := range reprints {
			if slices.Contains(skipEditions, reprint.SetCode) {
				continue
			}
			if minPrice == 0 || minPrice > reprint.Price {
				minPrice = reprint.Price
				uuid = reprint.UUID
			}
		}
		// Sanity check
		if minPrice == 0 {
			continue
		}

		// Assign a custom value to the card
		// Use Seconds to give a heavier weight on older items and square of
		// price to let expensive cards have a bigger impact
		// Log just spreads the results more nicely on the tier system
		tiers[uuid] = int(math.Log(float64(time.Now().Sub(latest).Seconds()) * minPrice * minPrice))
	}

	return tiers
}

func getTiers(blocklistRetail, blocklistBuylist, skipEditions []string) map[string]int {
	tiers := map[string]int{}

	var tcgSeller mtgban.Seller
	for _, seller := range Sellers {
		if seller != nil && seller.Info().Shorthand == "TCGLow" {
			tcgSeller = seller
			break
		}
	}

	opts := &mtgban.ArbitOpts{
		MinSpread:        MinSpread,
		MaxSpread:        MaxSpread,
		MinPrice:         SleepersMinPrice,
		Editions:         skipEditions,
		Conditions:       []string{"MP", "HP", "PO"},
		MaxPriceRatio:    MaxPriceRatio,
		CustomCardFilter: noOversize,
	}

	for _, seller := range Sellers {
		if seller.Info().MetadataOnly {
			continue
		}
		if seller.Info().CountryFlag != "" {
			continue
		}
		if seller.Info().SealedMode {
			continue
		}

		// Skip any seller explicitly in blocklist
		if slices.Contains(blocklistRetail, seller.Info().Shorthand) {
			continue
		}

		for _, vendor := range Vendors {
			if vendor.Info().Shorthand == seller.Info().Shorthand {
				continue
			}
			if vendor.Info().CountryFlag != "" {
				continue
			}

			// Skip any vendor explicitly in blocklist
			if slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
				continue
			}

			arbit := mtgban.Arbit(opts, vendor, seller)

			// Load the tiers
			for i := range arbit {
				tiers[arbit[i].CardId]++
			}
		}

		if tcgSeller != nil {
			mismatch := mtgban.Mismatch(opts, tcgSeller, seller)

			// Load the tiers
			for i := range mismatch {
				tiers[mismatch[i].CardId]++
			}
		}
	}

	return tiers
}

func getGap(blocklistRetail []string, ref, target string, skipEditions []string) map[string]int {
	tiers := map[string]int{}

	log.Println("Sleepers comparing", ref, "with", target)

	var referenceSeller mtgban.Seller
	var targetSeller mtgban.Seller
	for _, seller := range Sellers {
		if seller.Info().SealedMode ||
			slices.Contains(blocklistRetail, seller.Info().Shorthand) {
			continue
		}
		if seller.Info().Shorthand == ref {
			referenceSeller = seller
		}
		if seller.Info().Shorthand == target {
			targetSeller = seller
		}
	}

	if targetSeller == nil || referenceSeller == nil {
		return nil
	}

	// By default skip problematic sets
	skipEditions = append(skipEditions, "30A", "PTK", "CED", "CEI")

	opts := &mtgban.ArbitOpts{
		MaxSpread:        MaxSpread,
		MinPrice:         SleepersMinPrice * 2,
		Editions:         skipEditions,
		CustomCardFilter: noOversize,
		Conditions:       []string{"MP", "HP", "PO"},
	}

	mismatch := mtgban.Mismatch(opts, referenceSeller, targetSeller)

	marketCheck, _ := findSellerInventory("TCGMarket")

	// Filter out entries that are invalid
	for i := range mismatch {
		cardId := mismatch[i].CardId

		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			continue
		}
		if co.HasPromoType(mtgmatcher.PromoTypeSerialized) {
			continue
		}

		// Validate prices, skip in case anything is sus
		if ref == "TCGLow" {
			checkPrice := 0.0
			entries, found := marketCheck[cardId]
			if found {
				checkPrice = entries[0].Price
			}
			// tcg low cannot be higher than tcg market
			if mismatch[i].ReferenceEntry.Price > checkPrice {
				continue
			}
		}

		// Multiply by 100 to preseve the mantissa and have more
		// values to distribute across the table
		tiers[cardId] = int(mismatch[i].Spread * 100)
	}

	return tiers
}

func noOversize(co *mtgmatcher.CardObject) (float64, bool) {
	if co.Rarity == "oversize" {
		return 0, true
	}
	return 1, false
}

// Return a map of letter : []cardId from a map of cardId : amount
func sleepersLayout(tiers map[string]int) (map[string][]string, error) {
	results := []Sleeper{}
	for c := range tiers {
		if tiers[c] > 1 {
			results = append(results, Sleeper{
				CardId: c,
				Level:  tiers[c],
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("empty results")
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Level > results[j].Level
	})

	maxrange := float64(SleeperSize - 1)
	minrange := float64(0)
	exp := float64(minrange - maxrange)
	max := float64(results[0].Level)
	min := float64(results[len(results)-1].Level)

	if DevMode {
		log.Println("Max value:", max)
		log.Println("Min value:", min)
	}

	// Avoid a division by 0
	if max == min {
		return nil, errors.New("invalid range")
	}

	sleepers := map[string][]string{}
	for _, res := range results {
		value := float64(res.Level)
		// Normalize between 0,1
		r := (value - min) / (max - min)
		// Scale to the size of the table
		level := int(math.Floor(r*exp) + maxrange)

		if DevMode {
			cc, _ := mtgmatcher.GetUUID(res.CardId)
			log.Println(level, res.Level, cc)
		}

		if level >= SleeperSize {
			break
		}

		letter := SleeperLetters[level]

		sleepers[letter] = append(sleepers[letter], res.CardId)
	}

	// Sort sleepers by price
	inv, err := findSellerInventory("TCGLow")
	if err != nil {
		return nil, err
	}
	for _, letter := range SleeperLetters {
		sort.Slice(sleepers[letter], func(i, j int) bool {
			var priceI, priceJ float64
			entries, found := inv[sleepers[letter][i]]
			if found {
				priceI = entries[0].Price
			}
			entries, found = inv[sleepers[letter][j]]
			if found {
				priceJ = entries[0].Price
			}
			// Just to preserve order
			if priceI == priceJ {
				return sleepers[letter][i] < sleepers[letter][j]
			}
			return priceI > priceJ
		})

		// Truncate to avoid flooding the page
		if len(sleepers[letter]) > MaxSleepers {
			sleepers[letter] = sleepers[letter][:MaxSleepers]
		}
	}

	return sleepers, nil
}
