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
	"sync"
	"time"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/matcher/magic"
	"github.com/mtgban/go-mtgban/mtgban"
)

type Sleeper struct {
	CardID string
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

// sleepersLanguages are the printings that trade on the English market: plain
// English, plus the flavour languages the datastore files separately. A
// Phyrexian or Quenya card is sold like any other, so it belongs in the
// tiers; a French or Japanese one has listings too thin for a sleeper call to
// mean anything.
//
// Listed rather than derived by dropping the flagged languages, so a
// language nobody has seen yet stays out until someone looks at it.
var sleepersLanguages = []string{
	"English",
	"Ancient Greek",
	"Arabic",
	"Dwarvish",
	"Hebrew",
	"Klingon",
	"Latin",
	"Phyrexian",
	"Quenya",
	"Sanskrit",
}

// playtestEditions hold nothing but playtest cards; sleepersLayout drops the
// playtest cards printed in other sets.
var playtestEditions = []string{"CMB1", "CMB2", "PUNK", "UNK"}

// SleepVars are the PageVars fields only the sleepers page fills and reads.
type SleepVars struct {
	Sleepers       map[string][]string
	SleepersKeys   []string
	SleepersColors []string
}

func (s *site) Sleepers(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	b := ds.backend
	p := s.prices()
	sig := verifiedSignature(r)

	pageVars := genPageNav(s, r, "Sleepers", sig)

	blocklistRetail, blocklistBuylist := sleepBlocklists(sig)

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
	skipEditions = append(skipEditions, playtestEditions...)

	pageVars.SellerKeys = p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.SealedMode && !slices.Contains(blocklistRetail, info.Shorthand)
	})
	pageVars.StoreNames = p.storeNames()

	cyoa, _ := strconv.ParseBool(GetParamFromSig(sig, "SleepersCYOA"))
	pageVars.CanShowAll = cyoa || (DevMode && !SigCheck)

	pageVars.HasVelocity = salesVelocityStore.Snapshot() != nil

	var tiers map[string]int

	start := time.Now()

	page := r.FormValue("page")
	// With no sales loaded the velocity page has nothing to rank.
	if page == "velocity" && !pageVars.HasVelocity {
		page = ""
	}
	switch page {
	default:
		pageVars.Subtitle = "Index"

		render(w, "sleep.html", pageVars)

		return
	case "options":
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
		return
	case "bulk":
		pageVars.Subtitle = "Bulk me up"

		tiers = getBulks(b, p, skipEditions)

	case "reprint":
		pageVars.Subtitle = "Long time no reprint"

		tiers = getReprints(skipEditions)
	case "mismatch":
		pageVars.Subtitle = "Market Mismatch"

		tiers = getTiers(b, p, blocklistRetail, blocklistBuylist, skipEditions)
	case "gap":
		pageVars.Subtitle = "Ocean Gap"

		ref, target := r.FormValue("ref"), r.FormValue("target")
		tiers = getGap(b, p, blocklistRetail, ref, target, skipEditions)
	case "hotlist":
		pageVars.Subtitle = "Highest buylist growth"

		tiers = getHotlist(b, p, skipEditions)
	case "velocity":
		pageVars.Subtitle = "Sales Velocity"

		tiers = getVelocity(b, skipEditions)
	}

	sleepers, err := sleepersLayout(b, p, tiers)
	if err != nil {
		ServerNotify("sleep", "unable to generate sleepers: "+err.Error())

		pageVars.Title = "Errors have been made"
		pageVars.InfoMessage = ErrNoSleepers

		render(w, "sleep.html", pageVars)
		return
	}

	miscSearchOpts := readSearchMiscOpts(r)
	preferFlavor := miscSearchOpts.has("preferFlavor")
	pageVars.ShowUpsell = !miscSearchOpts.has("noUpsell")

	pageVars.Metadata = map[string]GenericCard{}
	for _, cardIDs := range sleepers {
		for _, cardID := range cardIDs {
			pageVars.Metadata.add(b, p, cardID, preferFlavor)
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

func getBulks(b *matcher.Backend, p *prices, skipEditions []string) map[string]int {
	inv, err := p.sellerInventory("TCGLow")
	if err != nil {
		return nil
	}
	bl, err := p.vendorBuylist("CK")
	if err != nil {
		return nil
	}

	tiers := map[string]int{}

	for _, code := range b.GetAllSets() {
		set, err := b.GetSet(code)
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
		if time.Since(releaseDate).Hours()/24/365 > 5 {
			continue
		}

		count := 0
		cardPrices := map[string]float64{}
		var totalPrices float64
		for _, card := range set.Cards {
			uuid := b.ConvertID(matcher.IDSpaceScryfall, card.Identifiers["scryfallId"])
			co, err := b.GetUUID(uuid)
			if err != nil {
				continue
			}
			if co.Foil || co.Etched || co.IsPromo ||
				co.HasPromoType(magic.PromoTypeBoosterfun) ||
				co.HasPromoType(magic.PromoTypePromoPack) {
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
				tiers[uuid]++
			}
		}
	}

	return tiers
}

func getHotlist(b *matcher.Backend, p *prices, skipEditions []string) map[string]int {
	tiers := map[string]int{}

	bl, _ := p.vendorBuylist("CK")

	// Skip bad editions
	skipEditions = append(skipEditions, "30A", "PTK", "CED", "CEI")

	for cardID, hotlistEntries := range GetInfos()["hotlist"] {
		// Make sure the older price is set, otherwise a lot of cards that were
		// previously not being bought will show up and pollute results
		oldPrice := hotlistEntries[0].Price
		if oldPrice == 0 {
			continue
		}

		co, err := b.GetUUID(cardID)
		if err != nil || slices.Contains(skipEditions, co.SetCode) {
			continue
		}

		var currentPrice float64
		currentEntries, found := bl[cardID]
		if found {
			currentPrice = currentEntries[0].BuyPrice
		}

		difference := currentPrice - oldPrice
		spread := 100 * (currentPrice - oldPrice) / oldPrice

		// Modeled after the "profitability" formula, coupling spread and difference.
		// NOTE: this still uses natural log (math.Log), whereas the canonical PI
		// formula in go-mtgban and upload.go now uses log10. Left as ln deliberately:
		// these integer tier buckets are calibrated against this scale, so switching
		// to log10 would shift every tier. Revisit if/when the tiers are recalibrated.
		tiers[cardID] = int(100 * difference / (currentPrice + 10) * math.Log(1+spread))
	}

	return tiers
}

// velocityTierCap is the copies a day that reach the S tier's top. Past it a
// single outlier would stretch the scale and leave S to itself. With the log in
// getVelocity it makes the tiers start at about 25, 13, 6, 3 and 1 a day.
const velocityTierCap = 50

// getVelocity scores the cards by copies sold a day, on a log scale since a few
// sell hundreds of times what most do.
func getVelocity(b *matcher.Backend, skipEditions []string) map[string]int {
	snap := salesVelocityStore.Snapshot()
	if snap == nil {
		return nil
	}

	tiers := map[string]int{}
	for cardID, sales := range snap.Cards {
		co, err := b.GetUUID(cardID)
		if err != nil || co.Sealed || slices.Contains(skipEditions, co.SetCode) {
			continue
		}
		tiers[cardID] = int(100 * math.Log10(1+min(sales.PerDay(snap.Window), velocityTierCap)))
	}
	return tiers
}

func getReprints(skipEditions []string) map[string]int {
	tiers := map[string]int{}

	// Filter results
	reprintsKeys, reprintsMap := GetReprints()
	for _, key := range reprintsKeys {
		reprints, found := reprintsMap[key]
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
		tiers[uuid] = int(math.Log(float64(time.Since(latest).Seconds()) * minPrice * minPrice))
	}

	return tiers
}

// getTiers counts, per card, the pairs among p's stores that flag it: a
// vendor buying above a seller's asking price, or the seller asking less than
// TCGLow. Each pair's hits are held on p, shared by every reader;
// the reader's blocklists pick the pairs and skipEditions drops cards after.
func getTiers(b *matcher.Backend, p *prices, blocklistRetail, blocklistBuylist, skipEditions []string) map[string]int {
	tiers := map[string]int{}
	for _, cardIDs := range p.sleepers.hits(b, sleeperPairs(p, blocklistRetail, blocklistBuylist)) {
		for _, cardID := range cardIDs {
			tiers[cardID]++
		}
	}
	for cardID := range tiers {
		co, err := b.GetUUID(cardID)
		if err != nil || slices.Contains(skipEditions, co.Edition) || slices.Contains(skipEditions, co.SetCode) {
			delete(tiers, cardID)
		}
	}
	return tiers
}

// sleeperPair is one comparison getTiers counts: vendor's buylist against
// seller's shelf, or, with no vendor, reference's shelf against it.
type sleeperPair struct {
	seller    mtgban.Seller
	vendor    mtgban.Vendor
	reference mtgban.Seller
}

// sleeperPairs lists the pairs of p's stores the blocklists keep, every
// one for nil blocklists.
func sleeperPairs(p *prices, blocklistRetail, blocklistBuylist []string) []sleeperPair {
	tcgSeller := p.index.seller["TCGLow"]

	var pairs []sleeperPair
	for _, seller := range p.sellers {
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

		for _, vendor := range p.vendors {
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

			pairs = append(pairs, sleeperPair{seller: seller, vendor: vendor})
		}

		if tcgSeller != nil {
			pairs = append(pairs, sleeperPair{seller: seller, reference: tcgSeller})
		}
	}
	return pairs
}

// cardIDs is the card id of every entry the pair reports, once per entry.
// No edition is skipped here: getTiers drops the reader's after summing.
func (pair sleeperPair) cardIDs(b *matcher.Backend) []string {
	opts := &mtgban.ArbitOpts{
		MinSpread:        MinSpread,
		MaxSpread:        MaxSpread,
		MinPrice:         SleepersMinPrice,
		Conditions:       BadConditions,
		MaxPriceRatio:    MaxPriceRatio,
		CustomCardFilter: noOversize,
		// Safe to ask outright rather than name what to drop: sleeperPairs
		// skips sealed sellers, and sealed is the one thing the datastore
		// files with no language at all.
		OnlyLanguages: sleepersLanguages,
	}

	var entries []mtgban.ArbitEntry
	if pair.vendor != nil {
		entries = mtgban.Arbit(b, opts, pair.vendor, pair.seller)
	} else {
		entries = mtgban.Mismatch(b, opts, pair.reference, pair.seller)
	}
	cardIDs := make([]string, len(entries))
	for i := range entries {
		cardIDs[i] = entries[i].CardID
	}
	return cardIDs
}

// sleeperHits is one pair's card ids, computed by the first request to ask.
type sleeperHits struct {
	once    sync.Once
	cardIDs []string

	// Under the cache's mutex: whether cardIDs is set
	done bool
}

// sleeperCache holds one prices snapshot's pairs' hits, against the backend
// they resolved through. A published store is never changed in place, so
// newPrices carries the pairs the next snapshot still publishes into its
// own cache, and a replaced snapshot's stores go with it.
type sleeperCache struct {
	mu      sync.Mutex
	backend weak.Pointer[matcher.Backend]
	pairs   map[sleeperPair]*sleeperHits
}

// sleeperTiersFor is next's cache: the finished pairs of prev's that next
// still publishes. prev is nil before the first publish.
func sleeperTiersFor(prev, next *prices) *sleeperCache {
	c := &sleeperCache{pairs: map[sleeperPair]*sleeperHits{}}
	if prev == nil {
		return c
	}
	prev.sleepers.mu.Lock()
	defer prev.sleepers.mu.Unlock()
	c.backend = prev.sleepers.backend
	for _, pair := range sleeperPairs(next, nil, nil) {
		entry, found := prev.sleepers.pairs[pair]
		if found && entry.done {
			c.pairs[pair] = entry
		}
	}
	return c
}

// hits returns each pair's card ids, computing the ones not held yet. A pair
// is computed once however many requests ask for it at the same time; a new
// backend starts over.
func (c *sleeperCache) hits(b *matcher.Backend, pairs []sleeperPair) [][]string {
	c.mu.Lock()
	if c.backend != weak.Make(b) {
		c.backend = weak.Make(b)
		c.pairs = map[sleeperPair]*sleeperHits{}
	}
	held := make([]*sleeperHits, len(pairs))
	for i, pair := range pairs {
		entry, found := c.pairs[pair]
		if !found {
			entry = &sleeperHits{}
			c.pairs[pair] = entry
		}
		held[i] = entry
	}
	c.mu.Unlock()

	out := make([][]string, len(pairs))
	for i, entry := range held {
		entry.once.Do(func() {
			// A pair that panicked is not held empty: the next request asks again
			defer func() {
				if entry.done {
					return
				}
				c.mu.Lock()
				if c.pairs[pairs[i]] == entry {
					delete(c.pairs, pairs[i])
				}
				c.mu.Unlock()
			}()
			cardIDs := pairs[i].cardIDs(b)
			c.mu.Lock()
			entry.cardIDs, entry.done = cardIDs, true
			c.mu.Unlock()
		})
		// A request that waited on a pair that panicked asks for it itself
		c.mu.Lock()
		done := entry.done
		c.mu.Unlock()
		if !done {
			out[i] = pairs[i].cardIDs(b)
			continue
		}
		out[i] = entry.cardIDs
	}
	return out
}

func getGap(b *matcher.Backend, p *prices, blocklistRetail []string, ref, target string, skipEditions []string) map[string]int {
	tiers := map[string]int{}

	log.Println("Sleepers comparing", ref, "with", target)

	var referenceSeller mtgban.Seller
	var targetSeller mtgban.Seller
	for _, seller := range p.sellers {
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
		Conditions:       BadConditions,
		// Same reasoning as getTiers: sealed sellers are skipped above.
		OnlyLanguages: sleepersLanguages,
	}

	mismatch := mtgban.Mismatch(b, opts, referenceSeller, targetSeller)

	marketCheck, _ := p.sellerInventory("TCGMarket")

	// Filter out entries that are invalid
	for i := range mismatch {
		cardID := mismatch[i].CardID

		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}
		if co.HasPromoType(magic.PromoTypeSerialized) {
			continue
		}

		// Validate prices, skip in case anything is sus
		if ref == "TCGLow" {
			checkPrice := 0.0
			entries, found := marketCheck[cardID]
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
		tiers[cardID] = int(mismatch[i].Spread * 100)
	}

	return tiers
}

func noOversize(co *matcher.CardObject) (float64, bool) {
	if co.Rarity == "oversize" {
		return 0, true
	}
	return 1, false
}

// Return a map of letter : []cardId from a map of cardId : amount
func sleepersLayout(b *matcher.Backend, p *prices, tiers map[string]int) (map[string][]string, error) {
	results := []Sleeper{}
	for c := range tiers {
		co, err := b.GetUUID(c)
		if err == nil && co.HasPromoType("playtest") {
			continue
		}
		if tiers[c] > 1 {
			results = append(results, Sleeper{
				CardID: c,
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
	maxLevel := float64(results[0].Level)
	minLevel := float64(results[len(results)-1].Level)

	if DevMode {
		log.Println("Max value:", maxLevel)
		log.Println("Min value:", minLevel)
	}

	// Avoid a division by 0
	if maxLevel == minLevel {
		return nil, errors.New("invalid range")
	}

	sleepers := map[string][]string{}
	for _, res := range results {
		value := float64(res.Level)
		// Normalize between 0,1
		r := (value - minLevel) / (maxLevel - minLevel)
		// Scale to the size of the table
		level := int(math.Floor(r*exp) + maxrange)

		if DevMode {
			cc, _ := b.GetUUID(res.CardID)
			log.Println(level, res.Level, cc)
		}

		if level >= SleeperSize {
			break
		}

		letter := SleeperLetters[level]

		sleepers[letter] = append(sleepers[letter], res.CardID)
	}

	// Sort sleepers by price
	inv, err := p.sellerInventory("TCGLow")
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
