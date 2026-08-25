package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/magic"
	"github.com/mtgban/mtgban-website/internal/notify"
)

var Country2flag = map[string]string{
	"EU": "🇪🇺",
	"JP": "🇯🇵",
}

// colorRarityMap paints the rarity badge. The Lorcana entries are sampled
// from the rarity symbols the cards actually carry: a grey ink drop, a copper
// triangle, a silver diamond, a gold pentagon.
//
// The three tiers above those share one prismatic symbol, differing in shape
// rather than color, so each takes a different arc of that one wheel: its
// crimson, its cyan, its violet. Enchanted keeps the cyan it has always had.
//
// Uncommon is the one tier not taken from its symbol. That symbol is white,
// and the set code inside the badge is drawn in the page color, so a white
// badge on a light page is a blank shape holding an invisible number. It
// keeps the slate it always had, which reads against either page and is the
// value Riftbound gives the tier too.
//
// Illumineer's Quest and promo cards are "special", which carries the gold
// Lorcana emblem rather than a rarity gem; the invented purple stays, since
// the emblem's gold is legendary's.
var colorRarityMap = map[string]map[string]string{
	"lorcana": {
		"common":    "var(--normal)",
		"uncommon":  "#707883",
		"rare":      "#B06435",
		"superrare": "#919495",
		"legendary": "#CDB55E",
		"epic":      "#C63A4D",
		"enchanted": "#1FA7C9",
		"iconic":    "#B45A96",
		"special":   "#652978",
	},
	// Riftbound prints its rarity as a gem under the text box, and these are
	// sampled from those gems: a teal pyramid, a magenta octahedron, an amber
	// gem, a gold cube. Common's sphere is white, and a white badge on a light
	// page holds an invisible set code, so it takes the theme's neutral the
	// same way Lorcana's does.
	//
	// A promo carries a banner over whatever gem the card already had rather
	// than one of its own, so its purple stays invented. The "none" rarity,
	// held by twelve tokens, is left out so those cards render no badge.
	"riftbound": {
		"common":   "var(--normal)",
		"uncommon": "#187870",
		"rare":     "#BF287F",
		"epic":     "#B66204",
		"showcase": "#BA9900",
		"promo":    "#652978",
	},
	// One Piece prints no gem: every rarity is the same lettered box beside
	// the card number, so there is nothing to sample and nothing to shape.
	// The badge climbs the same ladder the other games do, and only SEC is
	// taken from the card, whose box is a brass plate rather than the white
	// every other tier carries.
	//
	// SP, TR and PR are treatments rather than tiers — a TR card's own box
	// still reads C — so they sit off the end in the colors the other games
	// give their treatments.
	"onepiece": {
		"C":   "var(--normal)",
		"UC":  "#707883",
		"R":   "#B06435",
		"SR":  "#919495",
		"L":   "#C63A4D",
		"SEC": "#A88A3C",
		"SP":  "#B45A96",
		"TR":  "#1FA7C9",
		"PR":  "#652978",
	},
	// Flesh and Blood prints its rarity as a letter in a colored glyph at the
	// bottom left, and these are sampled from those glyphs: a blue R, a
	// crimson M, a bronze L, a green P, an amber diamond for fabled, gold for
	// the treasures. Gold and Marvel sit on artwork rather than the black
	// bar, so those two are read by eye rather than measured.
	//
	// Basic, common and token all carry the same grey, and super rare carries
	// no glyph at all on the frame that has it, so those four are placed
	// rather than sampled: common takes the theme's neutral like every other
	// game, and the rest take neighbouring tiers' colors. The 139 cards with
	// no rarity are left out and draw no badge.
	"fleshandblood": {
		"Common":       "var(--normal)",
		"Basic":        "#707883",
		"Token":        "#919495",
		"Rare":         "#156FA6",
		"Super Rare":   "#1FA7C9",
		"Majestic":     "#821A1E",
		"Legendary":    "#937131",
		"Fabled":       "#8F6330",
		"Marvel":       "#7B5BC0",
		"Gold":         "#E0B84A",
		"Pirate Booty": "#D4B055",
		"Promo":        "#298233",
	},
	// Yu-Gi-Oh marks no rarity on the card at all: it is a finish, the name
	// foiled silver or gold and the art holographic, so there is nothing to
	// sample and no shape to cut. What it does have is 35 rarities, most of
	// them a treatment of another one, which no palette could tell apart by
	// hue. They group by the tier their name claims — a Prismatic Secret Rare
	// is a secret rare, a Duel Terminal Normal Parallel Rare is a rare — and
	// each group climbs the ladder the other games already use.
	"yugioh": {
		"Common":                          "var(--normal)",
		"Duel Terminal Technology Common": "var(--normal)",

		"Duel Terminal Normal Parallel Rare": "#707883",
		"Duel Terminal Rare Parallel Rare":   "#707883",
		"Mosaic Rare":                        "#707883",
		"Parallel Rare":                      "#707883",
		"Rare":                               "#707883",
		"Shatterfoil Rare":                   "#707883",
		"Starfoil Rare":                      "#707883",

		"Duel Terminal Super Parallel Rare": "#919495",
		"Platinum Rare":                     "#919495",
		"Super Rare":                        "#919495",

		"Duel Terminal Technology Ultra Rare": "#B06435",
		"Duel Terminal Ultra Parallel Rare":   "#B06435",
		"Emblazoned Ultra Rare":               "#B06435",
		"Ultra Pharaoh’s Rare":                "#B06435",
		"Ultra Rare":                          "#B06435",

		"Prismatic Ultimate Rare": "#C63A4D",
		"Ultimate Rare":           "#C63A4D",

		"10000 Secret Rare":           "#1FA7C9",
		"Emblazoned Secret Rare":      "#1FA7C9",
		"Gold Secret Rare":            "#1FA7C9",
		"Platinum Secret Rare":        "#1FA7C9",
		"Prismatic Secret Rare":       "#1FA7C9",
		"Quarter Century Secret Rare": "#1FA7C9",
		"Secret Pharaoh’s Rare":       "#1FA7C9",
		"Secret Rare":                 "#1FA7C9",

		"Collector's Rare":           "#B45A96",
		"Prismatic Collector's Rare": "#B45A96",

		"Ghost Rare":      "#6F75AA",
		"Ghost/Gold Rare": "#6F75AA",
		"Starlight Rare":  "#6F75AA",

		"Gold Rare":         "#BA9900",
		"Premium Gold Rare": "#BA9900",

		"Promo": "#652978",
	},
}

// badgeFont is the size the shapes are cut at, and the ceiling a set code is
// ever drawn at however short it is.
const badgeFont = 10

// rarityBadge is the badge one rarity draws. Path is the outline, and Font
// and TextY place the set code inside it: a triangle only has room low down
// and a fan only high up, and both need a smaller code than a circle does.
// Chars is how long a code that size was cut for, so fitCode can shrink it
// for a longer one.
type rarityBadge struct {
	Path  string
	Font  float64
	TextY float64
	Chars int
}

// fitCode sizes the set code to the badge it has to sit inside. Past three
// characters a shape's room runs out almost exactly in proportion to the
// length — the largest size times the count holds steady within a few percent
// across a circle's four-to-nine character fits — so scaling by the ratio
// lands where measuring would.
func fitCode(badge rarityBadge, code string) rarityBadge {
	if badge.Chars > 0 && len(code) > 0 {
		badge.Font = badge.Font * float64(badge.Chars) / float64(len(code))
	}
	if badge.Font > badgeFont {
		badge.Font = badgeFont
	}
	// one decimal is all the drawings carry, and all that reaches the markup
	badge.Font = math.Round(badge.Font*10) / 10

	return badge
}

// badgeFile is an img/setsymbol drawing: one path, plus the fitting the shape
// needs recorded on the root element.
type badgeFile struct {
	Font  float64 `xml:"data-code-size,attr"`
	TextY float64 `xml:"data-code-y,attr"`
	Chars int     `xml:"data-code-chars,attr"`
	Path  struct {
		D string `xml:"d,attr"`
	} `xml:"path"`
}

func readBadge(path string) (rarityBadge, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return rarityBadge{}, err
	}

	var file badgeFile
	err = xml.Unmarshal(blob, &file)
	if err != nil {
		return rarityBadge{}, err
	}
	if file.Path.D == "" || file.Font == 0 || file.TextY == 0 || file.Chars == 0 {
		return rarityBadge{}, fmt.Errorf("%s: incomplete badge", path)
	}

	return rarityBadge{file.Path.D, file.Font, file.TextY, file.Chars}, nil
}

// rarityBadges holds the drawings, keyed by rarity, with the default circle
// under the empty key. loadRarityBadges fills it at startup, before anything
// renders, so nothing reads a file per card.
var rarityBadges = map[string]rarityBadge{}

// loadRarityBadges reads the game's own shapes from its directory, and the
// circle beside them. A game with no directory draws that circle throughout.
// Magic draws keyrune glyphs instead and never asks for a badge, so it reads
// nothing.
func loadRarityBadges() {
	if Config.Game == DefaultGame {
		return
	}

	fallback, err := readBadge("img/setsymbol/default.svg")
	if err != nil {
		log.Println("no default set symbol:", err)
	}
	rarityBadges[""] = fallback

	entries, _ := os.ReadDir("img/setsymbol/" + Config.Game)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".svg") {
			continue
		}
		badge, err := readBadge("img/setsymbol/" + Config.Game + "/" + entry.Name())
		if err != nil {
			log.Println("skipping set symbol:", err)
			continue
		}
		rarityBadges[strings.TrimSuffix(entry.Name(), ".svg")] = badge
	}
}

type GenericCard struct {
	UUID string
	// ChartID is the id the UI passes to the chart system. uuid2card leaves it
	// as the mtgmatcher card id; chart-capable pages override it with ban:<id>
	// via chartIDForCard, so chartless pages (upload, arbit, news, ...) don't
	// pay the variant-cache lookup for every card they render.
	ChartID      string
	Name         string
	FlavorName   string
	Edition      string
	SetCode      string
	Number       string
	Variant      string
	VariantShort string
	Keyrune      string
	ImageURL     string
	Foil         bool
	Etched       bool
	FinishTag    string
	FinishClass  string
	Treatments   []string
	Reserved     bool
	Title        string
	SearchURL    string
	SypList      bool
	Stocks       bool
	StocksURL    string
	Printings    string
	Products     string
	NumProducts  int
	TCGId        string
	Date         string
	Sealed       bool
	Booster      bool
	HasDeck      bool
	Flag         string
	LangTag      string

	Rarity            string
	RarityColor       string
	ScryfallURL       string
	DeckboxURL        string
	CKRestockURL      string
	SourceSealed      []string
	HotlistStore      string
	GoodBuylist       float64
	HighestBuylist    float64
	Newspaper         bool
	HasContentWarning bool
	CropURL           string
}

// altFoilChipLabels overrides the default title-cased chip label for
// altFoilTags whose names are too long to render cleanly as a chip.
var altFoilChipLabels = map[string]string{
	"doublerainbow": "DblRnbw",
}

func fileExists(filename string) bool {
	fi, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		link, err := os.Readlink(filename)
		if err != nil {
			return false
		}
		fi, err = os.Stat(link)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		return !fi.IsDir()
	}
	return !fi.IsDir()
}

func keyruneForCardSet(cardId string) string {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return ""
	}

	set, err := mtgmatcher.GetSet(co.Card.SetCode)
	if err != nil {
		// Try again if token is under a related set
		if co.Card.Rarity == "token" {
			set, err = mtgmatcher.GetSet(strings.TrimPrefix(co.Card.SetCode, "T"))
		}
		if err != nil {
			return ""
		}
	}

	keyrune := set.KeyruneCode
	if keyrune == "" {
		return ""
	}

	out := "ss-" + strings.ToLower(keyrune)
	rarity := co.Card.Rarity
	if rarity == "special" || co.Etched {
		rarity = "timeshifted"
	} else if rarity == "token" || rarity == "oversize" {
		rarity = "common"
	}

	// Skip setting rarity for common, so that a color is not forcefully set
	// on the symbol, and can become white on a dark theme
	// Also skip setting rarity on any foil cards due to rendering issues
	// https://github.com/andrewgioia/keyrune/issues/228
	if rarity != "common" && !co.Foil {
		out += " ss-" + rarity
	}

	if co.Foil {
		out += " ss-foil ss-grad"
	}

	return out
}

// getSetKeyrunes returns a map of set code -> bare "ss-CODE" keyrune class.
// Used by the search landing page to render set-search recent-search items.
func getSetKeyrunes() map[string]string {
	codes := mtgmatcher.GetAllSets()
	out := make(map[string]string, len(codes))
	for _, code := range codes {
		set, err := mtgmatcher.GetSet(code)
		if err != nil || set.KeyruneCode == "" {
			continue
		}
		out[code] = keyruneClass(set.KeyruneCode)
	}
	return out
}

func editionTitle(cardId string) string {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return ""
	}

	edition := co.Edition
	tag := ""
	if co.OriginalReleaseDate != "" {
		tag = co.OriginalReleaseDate
	}
	if co.Subsets != nil {
		tag = strings.Join(co.Subsets, " ")
	}
	if tag != "" {
		edition = fmt.Sprintf("%s (%s)", edition, tag)
	}

	finish := ""
	if co.Etched {
		finish = " Etched"
	} else if co.Foil {
		finish = " Foil"
	}

	extra := ""
	if co.Sealed {
		extra = ": "
		if co.Side != "" {
			subtype := strings.Replace(co.Side, "_", " ", -1)
			extra += mtgmatcher.Title(" " + subtype + ", ")
		}
		category := strings.Replace(co.Layout, "_", " ", -1)
		extra += mtgmatcher.Title(category)
	} else {
		extra = " #" + co.Card.Number
	}

	return fmt.Sprintf("%s -%s %s%s", edition, finish, mtgmatcher.Title(co.Card.Rarity), extra)
}

const (
	// 9 per line for default size, otherwise 19-21 depending on size
	MaxBeforeShrink = 18

	// After this amount just stop adding symbols
	MaxRuneSymbols = 57
)

// filterSellers returns the shorthand of every loaded seller for which
// predicate(info) is true.
func filterSellers(predicate func(mtgban.ScraperInfo) bool) []string {
	var out []string
	for _, s := range GetSellers() {
		info := s.Info()
		if predicate(info) {
			out = append(out, info.Shorthand)
		}
	}
	return out
}

// filterVendors is the vendor analog of filterSellers.
func filterVendors(predicate func(mtgban.ScraperInfo) bool) []string {
	var out []string
	for _, v := range GetVendors() {
		info := v.Info()
		if predicate(info) {
			out = append(out, info.Shorthand)
		}
	}
	return out
}

// canAccessMode reports whether the caller is allowed to read the given
// API mode (retail/buylist/sealed). Access is granted if the mode is in
// the signed enabledModes list, the list contains "all", or signature
// checks are disabled in dev mode.
func canAccessMode(enabledModes []string, target string) bool {
	return slices.Contains(enabledModes, target) ||
		slices.Contains(enabledModes, "all") ||
		(DevMode && !SigCheck)
}

// errorResponse writes a JSON error body with the given status code and
// the Content-Type header set to application/json. The message is encoded
// via json.NewEncoder so embedded quotes/backslashes are escaped properly.
func errorResponse(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: msg})
}

// Return the CreditMultiplier for any given vendor
func findCredit(shorthand string) float64 {
	for _, vendor := range GetVendors() {
		if strings.EqualFold(vendor.Info().Shorthand, shorthand) {
			return vendor.Info().CreditMultiplier
		}
	}
	return 0
}

// Look up a seller and return its inventory
func findSellerInventory(shorthand string) (mtgban.InventoryRecord, error) {
	for _, seller := range GetSellers() {
		if strings.EqualFold(seller.Info().Shorthand, shorthand) {
			return seller.Inventory(), nil
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor and return its buylist
func findVendorBuylist(shorthand string) (mtgban.BuylistRecord, error) {
	for _, vendor := range GetVendors() {
		if strings.EqualFold(vendor.Info().Shorthand, shorthand) {
			return vendor.Buylist(), nil
		}
	}
	return nil, errors.New("vendor not found")
}

// Look up a seller with its name and return its inventory
func findSellerInventoryByName(name string, sealed bool) (mtgban.InventoryRecord, error) {
	for _, seller := range GetSellers() {
		if seller.Info().SealedMode == sealed && strings.EqualFold(seller.Info().Name, name) {
			return seller.Inventory(), nil
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor with its name and return its inventory
func findVendorBuylistByName(name string, sealed bool) (mtgban.BuylistRecord, error) {
	for _, vendor := range GetVendors() {
		if vendor.Info().SealedMode == sealed && strings.EqualFold(vendor.Info().Name, name) {
			return vendor.Buylist(), nil
		}
	}
	return nil, errors.New("vendor not found")
}

// Look for a TCGproductId in all available places
func findTCGproductId(cardId string) string {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return ""
	}

	tcgId := co.Identifiers["tcgplayerProductId"]
	if co.Etched {
		id, found := co.Identifiers["tcgplayerEtchedProductId"]
		if found {
			tcgId = id
		}
	}
	if tcgId == "" {
		tcgLow, _ := findSellerInventory("TCGLow")
		entries, found := tcgLow[cardId]
		if !found {
			tcgMarket, _ := findSellerInventory("TCGMarket")
			entries, found = tcgMarket[co.UUID]
		}
		if found {
			tcgId = entries[0].OriginalId
		}
	}

	return tcgId
}

// Look for the instance id (sku) of a card in a given inventory
func findInstanceId(sellerName, cardId, cond string) string {
	tcgplayer, _ := findSellerInventory(sellerName)
	for _, entry := range tcgplayer[cardId] {
		if entry.Conditions == cond {
			return entry.InstanceId
		}
	}
	return ""
}

// uuid2TCGSKU is the reverse of tcgSKU2UUID: it returns the TCGplayer SKU of
// a card in a given condition, picking the inventory the product lives in.
// Sources that carry no condition are assumed to be NM, the same way the
// TCGplayer CSV export does. Returns "" when the card has no SKU on file.
func uuid2TCGSKU(cardId string, sealed bool, cond string) string {
	if cond == "" {
		cond = "NM"
	}
	if sealed {
		return findInstanceId("TCGSealed", cardId, cond)
	}
	return findInstanceId("TCGPlayer", cardId, cond)
}

// tcgSKU2UUID resolves a TCGplayer SKU (instance id) to a card uuid using the
// precomputed "tcgskuid" index from runSealedAnalysis (O(1)), where the uuid is
// stored in each entry's OriginalId. Returns "" if the SKU is unknown.
func tcgSKU2UUID(sku string) string {
	entries := GetInfos()["tcgskuid"][sku]
	if len(entries) == 0 {
		return ""
	}
	return entries[0].OriginalId
}

// tcgSKU2Condition resolves a TCGplayer SKU (instance id) to the condition it
// encodes (NM/SP/MP/HP/PO) via the same "tcgskuid" index as tcgSKU2UUID, where
// each entry's Conditions is preserved. Returns "" if the SKU is unknown.
func tcgSKU2Condition(sku string) string {
	entries := GetInfos()["tcgskuid"][sku]
	if len(entries) == 0 {
		return ""
	}
	return entries[0].Conditions
}

// Look for the original id (product id) of a card in a given inventory
func findOriginalId(sellerName, cardId string) string {
	tcgplayer, _ := findSellerInventory(sellerName)
	entries, found := tcgplayer[cardId]
	if found {
		return entries[0].OriginalId
	}
	return ""
}

var allLanguageFlags = map[string]string{
	"Chinese Simplified":  "🇨🇳",
	"Chinese Traditional": "🇹🇼",
	"French":              "🇫🇷",
	"German":              "🇩🇪",
	"Italian":             "🇮🇹",
	"Japanese":            "🇯🇵",
	"Korean":              "🇰🇷",
	"Portuguese (Brazil)": "🇧🇷",
	"Russian":             "🇷🇺",
	"Spanish":             "🇪🇸",
}

func showVariant(cardId string) bool {
	setDate, err := mtgmatcher.CardReleaseDate(cardId)
	if err != nil {
		return false
	}
	return setDate.After(mtgmatcher.PromosForEverybodyYay)
}

func uuid2card(cardId string, useThumbs, genPrints, preferFlavorName bool) GenericCard {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return GenericCard{}
	}

	var stocksURL string
	var sypList bool

	syp, err := findVendorBuylist("SYP")
	if err == nil {
		_, sypList = syp[cardId]
	}

	inv, _ := findSellerInventory("STKS")
	entries, stocks := inv[co.UUID]
	if stocks {
		stocksURL = entries[0].URL
	}

	var newspaper bool
	if uuids := GetNewspaperUUIDs(); uuids != nil {
		_, newspaper = uuids[cardId]
	}

	variant := ""
	if showVariant(cardId) {
		switch {
		case co.HasFrameEffect(magic.FrameEffectShowcase):
			variant = "Showcase "
		case co.HasFrameEffect(magic.FrameEffectExtendedArt):
			variant = "Extended Art "
		case co.BorderColor == magic.BorderColorBorderless:
			variant = "Borderless "
		case co.FrameVersion == "1997":
			variant = "Retro Frame "
		}
	}

	// Build the finish chip: defaults to Foil/Etched, overridden by alt foil type
	var treatments []string
	finishTag := ""
	finishClass := ""
	if co.Etched {
		finishTag = "Etched"
		finishClass = "etched"
	} else if co.Foil {
		finishTag = "Foil"
		finishClass = "foil"
	}

	// Loop through the supported promo types, skipping Boosterfun already processed above
	altFoilWord := ""
	for _, promoType := range co.PromoTypes {
		if slices.Contains(mtgmatcher.AllPromoTypes(), promoType) && promoType != magic.PromoTypeBoosterfun {
			if slices.Contains(altFoilTags, promoType) {
				if co.Foil || co.Etched {
					// Foiling variant replaces the generic Foil/Etched chip
					if short, ok := altFoilChipLabels[promoType]; ok {
						finishTag = short
					} else {
						finishTag = mtgmatcher.Title(strings.TrimSuffix(promoType, "foil"))
					}
					finishClass = "altfoil"
					altFoilWord = mtgmatcher.Title(promoType)
				} else {
					// Non-foil card with a foiling-style treatment — show as chip
					treatments = append(treatments, mtgmatcher.Title(promoType))
				}
			}
			if strings.HasPrefix(promoType, "ff") {
				variant += strings.ToUpper(promoType) + " "
				continue
			}
			// The promo type is a token so that it can be typed into a
			// search, which cost it the spaces: title-casing it back gives
			// "Bestof" where the storefront wrote "Best Of". Ask the game
			// how it is spelled - Magic keeps no fuller spelling and falls
			// back to the same title-casing, so nothing there moves.
			variant += mtgmatcher.PromoTypeLabel(promoType) + " "
		}
	}
	variant = strings.TrimSpace(variant)

	name, flavor := co.Name, co.FlavorName
	if flavor != "" {
		// Use allLanguageFlags to check whether the card should always
		// be displayed with the alternative name (ie for different fonts)
		if preferFlavorName || allLanguageFlags[co.Language] == "" {
			name, flavor = co.FlavorName, co.Name
		}

		if variant != "" {
			variant = " - " + variant
		}
		variant = fmt.Sprintf("\"%s\" %s", flavor, variant)
	}

	// Append Etched information to the tag
	if co.Etched {
		if variant != "" {
			variant += " "
		}
		variant += "Etched"
	}

	// Build variantShort: drop the quoted flavor prefix (mobile shows it on
	// its own line) and any terms already surfaced as chips.
	variantShort := variant
	if flavor != "" {
		variantShort = strings.TrimPrefix(variantShort, fmt.Sprintf("\"%s\"", flavor))
		variantShort = strings.TrimSpace(variantShort)
		variantShort = strings.TrimPrefix(variantShort, "-")
	}
	for _, t := range treatments {
		variantShort = strings.ReplaceAll(variantShort, t, "")
	}
	if altFoilWord != "" {
		variantShort = strings.ReplaceAll(variantShort, altFoilWord, "")
	}
	if co.Etched {
		variantShort = strings.ReplaceAll(variantShort, "Etched", "")
	}
	variantShort = strings.Join(strings.Fields(variantShort), " ")

	query := genQuery(co)

	imgURL := co.Images["full"]
	if useThumbs {
		imgURL = co.Images["thumbnail"]
	}
	cropURL := co.Images["crop"]

	printings := ""
	if genPrints {
		if co.Sealed {
			printings = genSealedPrintings(co)
		} else {
			printings = genCardPrintings(co)
		}
	}

	var canBoosterGen bool
	var hasDecklist bool
	path := "search"
	if co.Sealed {
		path = "sealed"
		canBoosterGen = mtgmatcher.SealedIsRandom(co.SetCode, co.UUID)
		hasDecklist = mtgmatcher.SealedHasDecklist(co.SetCode, co.UUID)
	}

	sourceSealed := cardobject2sources(co)

	var products string
	var numProducts int
	if len(sourceSealed) > 0 {
		products += "<h4>"
		for _, sealed := range sourceSealed {
			// The sealed uuids while known might have changed and we need to
			// make sure they don't crash the system here
			sealedCo, err := mtgmatcher.GetUUID(sealed)
			if err != nil {
				continue
			}
			products += "<a href=/sealed?q=" + sealed + ">" + sealedCo.Name + "</a>"
			numProducts++
		}
		products += "</h4>"
		if len(sourceSealed) > 5 {
			products = strings.Replace(products, "h4>", "h6>", -1)
		} else if len(sourceSealed) > 3 {
			products = strings.Replace(products, "h4>", "h5>", -1)
		}
	}

	tcgId := findTCGproductId(co.UUID)

	// Retrieve the CK URL from the in memory api list, which uses mtgjson ids
	var restockURL string
	ckInv, _ := findSellerInventory("CK")
	if co.Sealed {
		ckInv, _ = findSellerInventory("CKSealed")
	}
	entries, found := ckInv[co.UUID]
	if found {
		restockURL = strings.Replace(entries[0].URL, "mtg", "catalog/restock_notice", 1)
	}

	scryfallURL := ""
	_, found = co.Identifiers["scryfallId"]
	if found {
		scryfallURL = "https://scryfall.com/card/" + strings.ToLower(co.SetCode) + "/" + co.Number
	}

	deckboxURL := "https://deckbox.org/mtg/" + url.QueryEscape(co.Name) + "?fromqs=true"
	deckboxId, found := co.Identifiers["deckboxId"]
	if found {
		deckboxURL += "&printing=" + deckboxId
	}

	var rarityColor string
	keyrune := keyruneForCardSet(cardId)
	if keyrune == "" {
		rarityColor = colorRarityMap[Config.Game][co.Rarity]
	}

	var hotlistStore string
	_, found = GetInfos()["hotlist"][cardId]
	if found {
		hotlistStore = "CK"
	}
	goodBuylist := getGoodBuylistPrice(cardId)
	highestBuylist := getHighestBuylistPrice(cardId)

	return GenericCard{
		UUID:         co.UUID,
		ChartID:      cardId,
		Name:         name,
		FlavorName:   flavor,
		Edition:      co.Edition,
		SetCode:      co.Card.SetCode,
		Number:       co.Card.Number,
		Variant:      variant,
		VariantShort: variantShort,
		Foil:         co.Foil,
		Etched:       co.Etched,
		FinishTag:    finishTag,
		FinishClass:  finishClass,
		Treatments:   treatments,
		Keyrune:      keyrune,
		ImageURL:     imgURL,
		Title:        editionTitle(cardId),
		Reserved:     co.Card.IsReserved,
		SearchURL:    fmt.Sprintf("/%s?q=%s", path, url.QueryEscape(query)),
		SypList:      sypList,
		Stocks:       stocks,
		StocksURL:    stocksURL,
		Printings:    printings,
		Products:     products,
		NumProducts:  numProducts,
		TCGId:        tcgId,
		Date:         co.OriginalReleaseDate,
		Sealed:       co.Sealed,
		Booster:      canBoosterGen,
		HasDeck:      hasDecklist,
		Flag:         allLanguageFlags[co.Language],
		LangTag:      mtgmatcher.LanguageTag2LanguageCode[co.Language],

		Rarity:            co.Rarity,
		RarityColor:       rarityColor,
		ScryfallURL:       scryfallURL,
		DeckboxURL:        deckboxURL,
		CKRestockURL:      restockURL,
		SourceSealed:      sourceSealed,
		HotlistStore:      hotlistStore,
		GoodBuylist:       goodBuylist,
		HighestBuylist:    highestBuylist,
		Newspaper:         newspaper,
		HasContentWarning: co.Card.HasContentWarning,
		CropURL:           cropURL,
	}
}

func genQuery(co *mtgmatcher.CardObject) string {
	query := co.Name
	if !co.Sealed {
		query = fmt.Sprintf("%s s:%s cn:%s", co.Name, co.SetCode, co.Number)
		if co.Etched {
			query += " f:etched"
		} else if co.Foil {
			query += " f:foil"
		} else if !co.Etched && !co.Foil {
			query += " f:nonfoil"
		}
	}
	return query
}

func genCardPrintings(co *mtgmatcher.CardObject) string {
	var b strings.Builder
	// Hack to generate HTML in the template
	for i, setCode := range co.Printings {
		set, err := mtgmatcher.GetSet(setCode)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, `<a class="pagination" title="%s" href="/search?q=%s">`, set.Name, url.QueryEscape(co.Name+" s:"+setCode))

		keyruneCode := strings.ToLower(set.KeyruneCode)
		if keyruneCode == "" {
			// Monospace advances about 0.6em a character and the circle is
			// 30px across, so three characters is all 16px holds. A One Piece
			// code like ST-01 is five, and at a fixed size it ran off both
			// sides of the badge.
			fontSize := 16.0
			if len(setCode) > 3 {
				fontSize = 16.0 * 3 / float64(len(setCode))
			}
			fmt.Fprintf(&b, `
                    <svg width="32" height="32" xmlns="http://www.w3.org/2000/svg">
                        <circle r="15" cx="16" cy="16" fill="var(--normal)"/>
                        <text font-size="%.1f" font-family="monospace" font-weight="bold" x="50%%" y="50%%" text-anchor="middle" dominant-baseline="central" fill="var(--background)">%s</text>
                    </svg>`, fontSize, setCode)
		} else {
			fmt.Fprintf(&b, `<i class="ss ss-%s ss-2x"></i>`, keyruneCode)
		}
		b.WriteString(`</a>`)

		if i == MaxRuneSymbols && len(co.Printings) > MaxRuneSymbols {
			b.WriteString("<br>and many more (too many to list)...")
			break
		}
	}
	return b.String()
}

func genSealedPrintings(co *mtgmatcher.CardObject) string {
	var b strings.Builder
	// A hover/focus trigger with the tables in a panel that opens upward,
	// overlaying the picture, so the products list below stays visible.
	b.WriteString("<div class='sidebar-setvalue' tabindex='0'>")
	b.WriteString("<h6 class='sidebar-setvalue-trigger'>Set Value &#9662;</h6>")
	b.WriteString("<div class='sidebar-setvalue-panel'>")
	// The first chunk is always present, even for foil-only sets
	b.WriteString("<h6>Set Value</h6><table class='setValue'>")

	infos := GetInfos()
	for i, title := range ProductTitles {
		entries, found := infos[ProductKeys[i]][co.SetCode]
		if found {
			fmt.Fprintf(&b, "<tr class='setValue'><td class='setValue'><h5>%s</h5></td><td>$ %.02f</td></tr>", title, entries[0].Price)
		}
	}
	b.WriteString("</table>")

	// The second chunk is optional, check for the first key
	if len(infos[ProductFoilKeys[0]][co.SetCode]) > 0 {
		b.WriteString("<br>")
		b.WriteString("<h6>Foil Set Value</h6><table class='setValue'>")

		for i, title := range ProductTitles {
			entries, found := infos[ProductFoilKeys[i]][co.SetCode]
			if found {
				fmt.Fprintf(&b, "<tr class='setValue'><td class='setValue'><h5>%s</h5></td><td>$ %.02f</td></tr>", title, entries[0].Price)
			}
		}
		b.WriteString("</table>")
	}
	b.WriteString("</div></div>")
	return b.String()
}

// Log and send the notification for a user action
func ServerNotify(kind, message string, flags ...bool) {
	log.Println(message)
	if Config.DiscordNotifHook == "" {
		return
	}
	if len(flags) > 0 && flags[0] {
		message = "@here " + message
	}
	go notify.Post(Config.DiscordNotifHook, kind, message, DevMode)
}

// Only send the notification for a user action
func UserNotify(kind, message string, flags ...bool) {
	if Config.DiscordHook == "" {
		return
	}
	if len(flags) > 0 && flags[0] {
		message = "@here " + message
		log.Println(kind, "-", message)
	}
	go notify.Post(Config.DiscordHook, kind, message, DevMode)
}

// Only send the notification for a user action
func APINotify(message string, flags ...bool) {
	kind := Config.Game
	log.Println(kind, "-", message)
	if Config.DiscordAPINotifHook == "" {
		return
	}
	if len(flags) > 0 && flags[0] {
		message = "@here " + message
	}
	go notify.Post(Config.DiscordAPINotifHook, kind, message, DevMode)
}

// Read the query parameter, if present set a cookie that will be
// used as default preference, otherwise retrieve the said cookie
func readSetFlag(w http.ResponseWriter, r *http.Request, queryParam, cookieName string) bool {
	val := r.FormValue(queryParam)
	flag, err := strconv.ParseBool(val)
	if err != nil {
		flag, _ = strconv.ParseBool(readCookie(r, cookieName))
		return flag
	}
	setForeverCookie(w, cookieName, val)
	return flag
}

// Read a cookie from the request
func readCookie(r *http.Request, cookieName string) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// There is no forever in cookies, so pick a really large interval
func setForeverCookie(w http.ResponseWriter, cookieName, value string) {
	tenYears := time.Now().Add(10 * 365 * 24 * 60 * 60 * time.Second)
	setCookie(w, cookieName, value, tenYears, false)
}

// Set a cookie in the response with no expiration at the default root
func setCookie(w http.ResponseWriter, cookieName, value string, expires time.Time, global bool) {
	u, err := url.Parse(ServerURL)
	if err != nil {
		ServerNotify("cookie", "unable to parse ServerURL", true)
		return
	}

	domain := u.Hostname()
	if global {
		fields := strings.Split(domain, ".")
		// Guard against hostname being "mtgban.com"
		if fields[0] != "mtgban" {
			domain = strings.Join(fields[1:], ".")
		}
	}

	cookie := http.Cookie{
		Name:    cookieName,
		Domain:  domain,
		Path:    "/",
		Expires: expires,
		Value:   value,
		// Only mark Secure when the site itself is served over HTTPS,
		// otherwise the cookie would be dropped during local HTTP dev.
		Secure: u.Scheme == "https",
	}

	if !global {
		// Enforce first party cookies only
		cookie.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &cookie)
}

// isSecureRequest reports whether the request reached us over HTTPS,
// accounting for a TLS-terminating proxy that sets X-Forwarded-Proto.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// dataReady reports whether the datastore and scrapers are loaded enough to
// serve real answers (the same predicate /healthz uses). Cacheable endpoints
// must not let degraded warmup responses into caches: an empty payload with
// a public max-age poisons every client behind the CDN for its lifetime.
func dataReady() bool {
	return len(mtgmatcher.GetUUIDs()) != 0 && len(GetSellers()) != 0 && len(GetVendors()) != 0
}

// storeEligible reports whether a store may appear in a price surface under
// the given policy: an explicit allowlist is the entire policy (a sig's own
// store list bypasses blocklists by design), otherwise the store just must
// not be blocklisted. Both the API's store list construction and the search
// default blocklists express this precedence rule.
func storeEligible(shorthand string, allowlist, blocklist []string) bool {
	if allowlist != nil {
		return slices.Contains(allowlist, shorthand)
	}
	return !slices.Contains(blocklist, shorthand)
}

// Retrieve default blocklists according to the signature contents
func getDefaultBlocklists(sig string) ([]string, []string) {
	var blocklistRetail, blocklistBuylist []string
	blocklistRetailOpt := GetParamFromSig(sig, "SearchDisabled")
	if blocklistRetailOpt == "" {
		blocklistRetail = Config.SearchRetailBlockList
	} else if blocklistRetailOpt != "NONE" {
		blocklistRetail = strings.Split(blocklistRetailOpt, ",")
	}
	blocklistBuylistOpt := GetParamFromSig(sig, "SearchBuylistDisabled")
	if blocklistBuylistOpt == "" {
		blocklistBuylist = Config.SearchBuylistBlockList
	} else if blocklistBuylistOpt != "NONE" {
		blocklistBuylist = strings.Split(blocklistBuylistOpt, ",")
	}
	return blocklistRetail, blocklistBuylist
}

// Return a random uuid from the pool of singles or sealed uuids
func randomUUID(sealed bool) string {
	uuids := mtgmatcher.GetUUIDs()
	if sealed {
		uuids = mtgmatcher.GetSealedUUIDs()
	}
	if len(uuids) == 0 {
		return ""
	}
	index := rand.Intn(len(uuids))
	return uuids[index]
}

type Pagination struct {
	TotalIndex   int
	CurrentIndex int
	PrevIndex    int
	NextIndex    int
}

// Divide results in sub pages
// slice - input results
// pageIndex - the current page being viewed
// maxResults - how many items can be present in a single page
// maxTotalResults - how many items can be present in all results
func Paginate[T any](slice []T, pageIndex, maxResults, maxTotalResults int) ([]T, Pagination) {
	var page Pagination

	if len(slice) == 0 {
		return slice, page
	}

	page.TotalIndex = (len(slice) + maxResults - 1) / maxResults
	if page.TotalIndex > maxTotalResults/maxResults {
		page.TotalIndex = maxTotalResults / maxResults
	}

	// Make sure there is at least one page
	if page.TotalIndex < 1 {
		page.TotalIndex = 1
	}

	// Validate the requested input page
	if pageIndex <= 1 {
		pageIndex = 1
	} else if pageIndex > page.TotalIndex {
		pageIndex = page.TotalIndex
	}

	// Assign the current page index to enable pagination
	page.CurrentIndex = pageIndex

	// Initialize previous and next pagination links
	if page.CurrentIndex > 1 {
		page.PrevIndex = page.CurrentIndex - 1
	}
	if page.CurrentIndex < page.TotalIndex {
		page.NextIndex = page.CurrentIndex + 1
	}

	// Chop results where needed
	head := maxResults * (pageIndex - 1)
	if head > len(slice) {
		head = len(slice)
	}
	tail := maxResults * pageIndex
	if tail > len(slice) {
		tail = len(slice)
	}

	return slice[head:tail], page
}

// Retrieve the TCGplayer Market price of any given card
func getTCGMarketPrice(cardId string) float64 {
	inv, err := findSellerInventory("TCGMarket")
	if err != nil {
		return 0
	}
	return tcgMarketPriceIn(inv, cardId)
}

// tcgMarketPriceIn probes an already-resolved TCGMarket inventory, so
// per-row loops resolve the seller once instead of per card.
func tcgMarketPriceIn(inv mtgban.InventoryRecord, cardId string) float64 {
	entries, found := inv[cardId]
	if !found {
		return 0
	}
	return entries[0].Price
}

// getGoodBuylistPrice returns the "good" buylist threshold for a card — Card
// Kingdom's latest 90-day P90 buylist price (goodP90) — or 0 when unavailable.
// A buylist offer at or above this is worth flagging to the user.
func getGoodBuylistPrice(cardId string) float64 {
	entries, found := GetInfos()["goodP90"][cardId]
	if !found || len(entries) == 0 {
		return 0
	}
	return entries[0].Price
}

// getHighestBuylistPrice returns Card Kingdom's peak buylist price for a card
// over the last 90 days (the "highest" metric), or 0 when unavailable.
func getHighestBuylistPrice(cardId string) float64 {
	entries, found := GetInfos()["highest"][cardId]
	if !found || len(entries) == 0 {
		return 0
	}
	return entries[0].Price
}

// Retrieve the IQR of the simulation using TCGplayer Low as base
func getTCGSimulationIQR(productId string) float64 {
	inv, err := findSellerInventory("TCGLowSim")
	if err != nil {
		return 0
	}
	entries, found := inv[productId]
	if !found {
		return 0
	}
	return entries[0].ExtraValues["iqr"]
}

// Return the full display name displayed from the input shorthand
func scraperName(shorthand string) string {
	for _, seller := range GetSellers() {
		if shorthand == seller.Info().Shorthand {
			name := seller.Info().Name
			override, found := Config.ScraperConfig.NameOverride[seller.Info().Name]
			if found {
				name = override
			}
			return name
		}
	}
	for _, vendor := range GetVendors() {
		if shorthand == vendor.Info().Shorthand {
			name := vendor.Info().Name
			override, found := Config.ScraperConfig.NameOverride[vendor.Info().Name]
			if found {
				name = override
			}
			return name
		}
	}

	// If nothing is found, check if there is a custom override for the shorthand itself
	return Config.ScraperConfig.NameOverride[shorthand]
}

// sortKeysByScraperName returns a new slice of shorthand keys sorted alphabetically
// by their resolved display name (case-insensitive). Stable for equal names.
func sortKeysByScraperName(keys []string) []string {
	out := make([]string, len(keys))
	copy(out, keys)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(scraperName(out[i])) < strings.ToLower(scraperName(out[j]))
	})
	return out
}

// Special function to detect if the input price is bigger than
// twice as much the market price on TCGplayer - used to detect
// invalid Direct prices. Ignored for anything lower than $1
// since Direct minimum is $0.40.
func invalidDirect(id string, price float64) bool {
	inv, _ := findSellerInventory("TCGMarket")
	return invalidDirectIn(inv, id, price)
}

// invalidDirectIn is invalidDirect over an already-resolved TCGMarket
// inventory; a nil inventory reads as no market price.
func invalidDirectIn(inv mtgban.InventoryRecord, id string, price float64) bool {
	if price < 1 {
		return false
	}

	marketPrice := tcgMarketPriceIn(inv, id)
	return price > marketPrice*2
}

// keyruneClass turns a set's keyrune code into the class the font wants, and
// gives nothing at all to a game whose sets carry no keyrune.
func keyruneClass(code string) string {
	if code == "" {
		return ""
	}
	return "ss-" + strings.ToLower(code)
}
