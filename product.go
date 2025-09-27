package main

import (
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type EditionEntry struct {
	Name     string
	Code     string
	Date     time.Time
	Keyrune  string
	Size     int
	FmtDate  string
	Special  bool
	ShowFin  bool
	HasReg   bool
	HasFoil  bool
	Rarities []string
	Colors   []string
}

// Contains all the set value computations shown on sealed products
var Infos map[string]mtgban.InventoryRecord

// All editions containing sealed products
var SealedEditionsSorted []string
var SealedEditionsList map[string][]EditionEntry

// All different editions
var AllEditionsKeys []string
var AllEditionsKeysNoFoilOrPromos []string
var AllEditionsMap map[string]EditionEntry

// Editions with parent sets
var TreeEditionsKeys []string
var TreeEditionsMap map[string][]EditionEntry

// Long time no reprint data
var ReprintsKeys []string
var ReprintsMap map[string][]ReprintEntry

// The number of editions, cards, and printings
var TotalSets, TotalCards, TotalUnique int

var categoryEdition = map[string]string{
	"archenemy":        "Boxed Sets",
	"arsenal":          "Commander Supplements",
	"box":              "Boxed Sets",
	"commander":        "Commander Decks",
	"core":             "Core Sets",
	"draft_innovation": "Draft Experiments",
	"duel_deck":        "Deck Series",
	"expansion":        "Expansions",
	"from_the_vault":   "From the Vault Sets",
	"funny":            "Funny Sets",
	"game":             "Standalone Game",
	"masterpiece":      "Boxed Sets",
	"masters":          "Reprint Sets",
	"memorabilia":      "Boxed Sets",
	"planechase":       "Boxed Sets",
	"premium_deck":     "Deck Series",
	"promo":            "Boxed Sets",
	"starter":          "Starter Sets",
	"vanguard":         "Boxed Sets",
}

var categoryOverrides = map[string]string{
	"CMB1": "masters",
	"CMB2": "masters",
	"MB2":  "masters",
	"PTG":  "box",
	"SS1":  "arsenal",
	"SS2":  "arsenal",
	"SS3":  "arsenal",
	"HOP":  "game",
	"PC2":  "game",
	"PCA":  "game",
	"E02":  "game",
	"ARC":  "game",
}

var editionRenames = map[string]string{
	"Judge Gift Cards 2014": "Judge Gift Cards",
}

// Never pick #708090 as it's the gradient base
var colorValues = map[string]string{
	"white":      "#FFFAFA",
	"blue":       "#00BFFF",
	"black":      "#111111",
	"red":        "#FF4500",
	"green":      "#32CD32",
	"colorless":  "#A9A9A9",
	"multicolor": "#FFE866",
	"amber":      "#FF8C00",
	"amethyst":   "#9932CC",
	"emerald":    "#22C022",
	"ruby":       "#FF4500",
	"sapphire":   "#0000FF",
	"steel":      "#A9A9A9",
}

func makeEditionEntry(set *mtgmatcher.Set, names ...string) EditionEntry {
	date, _ := time.Parse("2006-01-02", set.ReleaseDate)

	name := set.Name
	if len(names) > 0 && names[0] != "" {
		name = names[0]
	}
	special := false
	switch set.Code {
	case "H1R",
		"SCD":
		special = true
	}

	var rarities []string
	if len(set.Rarities) > 1 {
		rarities = set.Rarities
	}
	var colors []string
	if len(set.Colors) > 1 {
		colors = set.Colors
	}

	return EditionEntry{
		Name:     name,
		Code:     set.Code,
		Date:     date,
		Keyrune:  strings.ToLower(set.KeyruneCode),
		Size:     len(set.Cards),
		FmtDate:  set.ReleaseDate,
		Special:  special,
		ShowFin:  !set.IsNonFoilOnly && !set.IsFoilOnly,
		HasReg:   !set.IsFoilOnly,
		HasFoil:  !set.IsNonFoilOnly,
		Rarities: rarities,
		Colors:   colors,
	}
}

func getAllEditions() ([]string, map[string]EditionEntry) {
	sets := mtgmatcher.GetAllSets()

	sortedEditions := make([]string, 0, len(sets))
	listEditions := map[string]EditionEntry{}
	for _, code := range sets {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}

		sortedEditions = append(sortedEditions, code)

		listEditions[code] = makeEditionEntry(set)
	}

	sort.Slice(sortedEditions, func(i, j int) bool {
		return listEditions[sortedEditions[i]].Date.After(listEditions[sortedEditions[j]].Date)
	})

	return sortedEditions, listEditions
}

func getTreeEditions() ([]string, map[string][]EditionEntry) {
	sets := mtgmatcher.GetAllSets()

	var sortedEditions []string
	listEditions := map[string][]EditionEntry{}
	for _, code := range sets {
		// Skip empty sets
		set, err := mtgmatcher.GetSet(code)
		if err != nil || len(set.Cards) == 0 {
			continue
		}

		entry := makeEditionEntry(set)

		if set.ParentCode == "" {
			// Skip if it was already added from the other case
			_, found := listEditions[set.Code]
			if found {
				continue
			}
			// Create the head, list in the slice to be sorted
			listEditions[set.Code] = []EditionEntry{entry}
			sortedEditions = append(sortedEditions, set.Code)
		} else {
			// Find the very fist parent
			topParentCode := set.ParentCode
			for {
				topset, err := mtgmatcher.GetSet(topParentCode)
				if err != nil || topset.ParentCode == "" {
					break
				}
				topParentCode = topset.ParentCode
			}

			// Check if the head of the tree is already present
			_, found := listEditions[topParentCode]
			if !found {
				// If not, create it
				set, err := mtgmatcher.GetSet(topParentCode)
				if err != nil {
					continue
				}
				headEntry := makeEditionEntry(set)
				listEditions[topParentCode] = []EditionEntry{headEntry}
				sortedEditions = append(sortedEditions, topParentCode)
			}
			// Append the new entry
			listEditions[topParentCode] = append(listEditions[topParentCode], entry)
		}
	}

	// Sort main list by date
	sort.Slice(sortedEditions, func(i, j int) bool {
		// Sort by name in case date is the same
		if listEditions[sortedEditions[i]][0].Date == listEditions[sortedEditions[j]][0].Date {
			return listEditions[sortedEditions[i]][0].Name < listEditions[sortedEditions[j]][0].Name
		}
		return listEditions[sortedEditions[i]][0].Date.After(listEditions[sortedEditions[j]][0].Date)
	})

	// Sort sublists by date
	for _, key := range sortedEditions {
		sort.Slice(listEditions[key], func(i, j int) bool {
			// Keep the first element always first
			if j == 0 {
				return false
			}
			// Sort by name in case date is the same
			if listEditions[key][i].Date == listEditions[key][j].Date {
				return listEditions[key][i].Name < listEditions[key][j].Name
			}
			return listEditions[key][i].Date.After(listEditions[key][j].Date)
		})
	}

	return sortedEditions, listEditions
}

func getSealedEditions() ([]string, map[string][]EditionEntry) {
	sortedEditions := []string{}
	listEditions := map[string][]EditionEntry{}
	for _, code := range mtgmatcher.GetAllSets() {
		switch code {
		case "DRKITA", "LEGITA", "4EDALT":
			continue
		}

		set, err := mtgmatcher.GetSet(code)
		if err != nil || len(set.SealedProduct) == 0 {
			continue
		}

		setType := set.Type
		rename, found := categoryOverrides[set.Code]
		if found {
			setType = rename
		}
		category, found := categoryEdition[setType]
		if !found {
			category = set.Type
		}

		rename = editionRenames[set.Name]

		entry := makeEditionEntry(set, rename)
		listEditions[category] = append(listEditions[category], entry)
	}

	for key := range listEditions {
		sort.Slice(listEditions[key], func(i, j int) bool {
			return listEditions[key][i].Date.After(listEditions[key][j].Date)
		})
		sortedEditions = append(sortedEditions, key)
	}

	sort.Slice(sortedEditions, func(i, j int) bool {
		return listEditions[sortedEditions[i]][0].Date.After(listEditions[sortedEditions[j]][0].Date)
	})

	return sortedEditions, listEditions
}

type ReprintEntry struct {
	UUID    string
	SetCode string
	Date    time.Time
	Price   float64
}

const (
	YearsBeforeReprint  = 2
	MinimumReprintPrice = 3.0
)

// Produce a map of card : []ReprintEntry containing array reprints sorted by age
func getReprintsGlobal() ([]string, map[string][]ReprintEntry) {
	tcgLow, _ := findSellerInventory("TCGLow")
	tcgMarket, _ := findSellerInventory("TCGMarket")

	uuids := mtgmatcher.GetUUIDs()

	var names []string
	listReprints := map[string][]ReprintEntry{}

	var dupes []string
	for _, uuid := range uuids {
		co, _ := mtgmatcher.GetUUID(uuid)

		set, err := mtgmatcher.GetSet(co.SetCode)
		if err != nil {
			continue
		}

		// Skip very old stuff
		switch set.Code {
		case "PCEL",
			"LEG", "DRK", "ATQ", "ARN", "PTK",
			"FBB", "4BB", "DRKITA", "LEGITA", "RIN", "4EDALT", "BCHR":
			continue
		}

		// Skip strange stuff
		if co.IsReserved || mtgmatcher.IsToken(co.Name) ||
			co.BorderColor == "gold" || co.BorderColor == "silver" ||
			co.Rarity == "oversize" ||
			co.HasPromoType(mtgmatcher.PromoTypePromoPack) ||
			co.HasPromoType(mtgmatcher.PromoTypePrerelease) {
			continue
		}

		// Ignore the foil printing of printed cards
		if co.Foil && len(co.Finishes) > 1 {
			continue
		}

		// Skip processed cards (using scryfallId to catch foil/nonfoil)
		if slices.Contains(dupes, co.Identifiers["scryfallId"]) {
			continue
		}
		dupes = append(dupes, co.Identifiers["scryfallId"])

		// Load the date for the card
		printDate, err := mtgmatcher.CardReleaseDate(co.UUID)
		if err != nil {
			continue
		}

		var price float64
		entries, found := tcgLow[co.UUID]
		if !found {
			entries, found = tcgMarket[co.UUID]
		}
		if found {
			price = entries[0].Price
		}

		// Append to the results
		listReprints[co.Name] = append(listReprints[co.Name], ReprintEntry{
			UUID:  co.UUID,
			Price: price,
			Date:  printDate,
		})
	}

	// Filter results
	for name, reprints := range listReprints {
		var shouldSkip bool
		for i := range reprints {
			// Skip cards that are not old enough
			if time.Now().Sub(reprints[i].Date).Hours()/24/365 <= YearsBeforeReprint {
				shouldSkip = true
				break
			}

			// Skip cards that are too low or that don't have a price
			price := reprints[i].Price
			if price < MinimumReprintPrice {
				shouldSkip = true
				break
			}
		}

		if shouldSkip {
			delete(listReprints, name)
			continue
		}

		names = append(names, name)
		sort.Slice(reprints, func(i, j int) bool {
			return reprints[i].Date.After(reprints[j].Date)
		})
		listReprints[name] = reprints
	}

	return names, listReprints
}

var ProductKeys = []string{
	"TotalValueByTcgLow",
	"TotalValueByTcgDirect",
	"TotalValueByTcgLowMinusBulk",
	"TotalValueBuylist",
	"TotalValueDirectNet",
}

var ProductFoilKeys = []string{
	"TotalFoilValueByTcgLow",
	"TotalFoilValueByTcgDirect",
	"TotalFoilValueByTcgLowMinusBulk",
	"TotalFoilValueBuylist",
	"TotalFoilValueDirectNet",
}

var ProductTitles = []string{
	"by TCGLow",
	"by TCG Direct",
	"by TCGLow without Bulk",
	"by CK Buylist",
	"by TCG Direct (net)",
}

const (
	bulkPrice = 2.99
)

// Check if it makes sense to keep two keep foil and nonfoil separate
func combineFinish(setCode string) bool {
	set, err := mtgmatcher.GetSet(setCode)
	if err != nil {
		return false
	}

	setType := set.Type
	rename, found := categoryOverrides[setCode]
	if found {
		setType = rename
	}
	switch setType {
	case "commander",
		"box",
		"duel_deck",
		"from_the_vault",
		"masterpiece",
		"memorabilia",
		"promo":
		return true
	}

	return false
}

func bulkBuylist(co *mtgmatcher.CardObject) float64 {
	var price float64
	switch co.Rarity {
	case "mythic":
		price = 0.30
		if co.Foil {
			price = 0.25
		}
	case "rare":
		price = 0.08
		if co.Foil {
			price = 0.15
		}
	case "common", "uncommon":
		price = 5.0 / 1000
		if co.Foil {
			price = 0.02
		}
	default:
		if co.IsPromo {
			price = 0.05
		} else if mtgmatcher.IsBasicLand(co.Name) {
			price = 0.01
			if co.Foil {
				price = 0.10
			}
		}
	}
	return price
}

func runSealedAnalysis() {
	log.Println("Running set analysis")

	tcgInventory, _ := findSellerInventory("TCGLow")
	tcgDirect, _ := findSellerInventory("TCGDirect")
	ckBuylist, _ := findVendorBuylist("CK")
	directNetBuylist, _ := findVendorBuylist("TCGDirectNet")

	runRawSetValue(tcgInventory, tcgDirect, ckBuylist, directNetBuylist)
}

func runRawSetValue(tcgInventory, tcgDirect mtgban.InventoryRecord, ckBuylist, directNetBuylist mtgban.BuylistRecord) {
	inv := map[string]float64{}
	invFoil := map[string]float64{}
	invDirect := map[string]float64{}
	invDirectFoil := map[string]float64{}
	invNoBulk := map[string]float64{}
	invNoBulkFoil := map[string]float64{}
	bl := map[string]float64{}
	blFoil := map[string]float64{}
	blDirectNet := map[string]float64{}
	blDirectNetFoil := map[string]float64{}

	uuids := mtgmatcher.GetUUIDs()

	for _, uuid := range uuids {
		co, _ := mtgmatcher.GetUUID(uuid)

		// Skip sets that are not well tracked upstream
		if co.SetCode == "PMEI" || co.BorderColor == "gold" {
			continue
		}

		// Determine whether to keep prices separated or combine them
		useFoil := co.Foil && !combineFinish(co.SetCode)

		var blPrice float64
		entriesBl, found := ckBuylist[uuid]
		if !found {
			blPrice = bulkBuylist(co)
		} else {
			blPrice = entriesBl[0].BuyPrice
		}
		if useFoil {
			blFoil[co.SetCode] += blPrice
		} else {
			bl[co.SetCode] += blPrice
		}

		entriesInv, found := tcgInventory[uuid]
		if found {
			if useFoil {
				invFoil[co.SetCode] += entriesInv[0].Price
			} else {
				inv[co.SetCode] += entriesInv[0].Price
			}

			if entriesInv[0].Price > bulkPrice {
				if useFoil {
					invNoBulkFoil[co.SetCode] += entriesInv[0].Price
				} else {
					invNoBulk[co.SetCode] += entriesInv[0].Price
				}
			}
		}
		entriesInv, found = tcgDirect[uuid]
		if found {
			if useFoil {
				invDirectFoil[co.SetCode] += entriesInv[0].Price
			} else {
				invDirect[co.SetCode] += entriesInv[0].Price
			}
		}

		entriesBl, found = directNetBuylist[uuid]
		if found {
			if useFoil {
				blDirectNetFoil[co.SetCode] += entriesBl[0].BuyPrice
			} else {
				blDirectNet[co.SetCode] += entriesBl[0].BuyPrice
			}
		}
	}

	if Infos == nil {
		Infos = map[string]mtgban.InventoryRecord{}
	}

	for i, records := range []map[string]float64{
		inv,
		invDirect,
		invNoBulk,
		bl,
		blDirectNet,
		invFoil,
		invDirectFoil,
		invNoBulkFoil,
		blFoil,
		blDirectNetFoil,
	} {
		record := mtgban.InventoryRecord{}
		for code, price := range records {
			record[code] = append(record[code], mtgban.InventoryEntry{
				Price: price,
			})
		}
		// Keep the two key sets separate
		key := ""
		if i >= len(ProductKeys) {
			key = ProductFoilKeys[i%len(ProductKeys)]
		} else {
			key = ProductKeys[i]
		}
		Infos[key] = record
	}
}

func updateStaticData() {
	SealedEditionsSorted, SealedEditionsList = getSealedEditions()
	AllEditionsKeys, AllEditionsMap = getAllEditions()
	TreeEditionsKeys, TreeEditionsMap = getTreeEditions()
	ReprintsKeys, ReprintsMap = getReprintsGlobal()

	for _, code := range AllEditionsKeys {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		if set.IsFoilOnly {
			continue
		}
		if strings.HasSuffix(set.Name, "Promos") {
			continue
		}
		AllEditionsKeysNoFoilOrPromos = append(AllEditionsKeysNoFoilOrPromos, code)
	}

	TotalSets = len(AllEditionsKeys)
	TotalUnique = len(mtgmatcher.GetUUIDs())
	var totalCards int
	for _, key := range AllEditionsKeys {
		totalCards += AllEditionsMap[key].Size
	}
	TotalCards = totalCards
}
