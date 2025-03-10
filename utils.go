package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/exp/slices"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/mtgjson"
)

var Country2flag = map[string]string{
	"EU": "🇪🇺",
	"JP": "🇯🇵",
}

var colorRarityMap = map[string]map[string]string{
	"Lorcana": {
		"common":    "var(--normal)",
		"uncommon":  "#707883",
		"rare":      "#CD7F32",
		"superrare": "#C0C0C0",
		"legendary": "#FFD700",
		"special":   "#652978",
		"enchanted": "#03A9FC",
	},
}

type GenericCard struct {
	UUID      string
	Name      string
	Edition   string
	SetCode   string
	Number    string
	Variant   string
	Keyrune   string
	ImageURL  string
	Foil      bool
	Etched    bool
	Reserved  bool
	Title     string
	SearchURL string
	SypList   bool
	Stocks    bool
	StocksURL string
	Printings string
	Products  string
	TCGId     string
	Date      string
	Sealed    bool
	Booster   bool
	HasDeck   bool
	Flag      string

	RarityColor  string
	ScryfallURL  string
	DeckboxURL   string
	CKRestockURL string
	SourceSealed []string
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

func mkDirIfNotExisting(dirName string) error {
	_, err := os.Stat(dirName)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(dirName, 0700)
	}
	return err
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
		subtype := strings.Replace(co.Side, "_", " ", -1)
		category := strings.Replace(co.Layout, "_", " ", -1)
		extra = mtgmatcher.Title(": " + subtype + ", " + category)
	} else {
		extra = " #" + co.Card.Number
	}

	return fmt.Sprintf("%s -%s %s%s", edition, finish, mtgmatcher.Title(co.Card.Rarity), extra)
}

func insertNavBar(page string, nav []NavElem, extra []NavElem) []NavElem {
	out := make([]NavElem, len(nav)+len(extra))
	var j int
	for i := range nav {
		out[j] = nav[i]
		if out[j].Name == page {
			for e := range extra {
				j++
				out[j] = extra[e]
			}
		}
		j++
	}
	return out
}

const (
	// 9 per line for default size, otherwise 19-21 depending on size
	MaxBeforeShrink = 18

	// After this amount just stop adding symbols
	MaxRuneSymbols = 57
)

// Look up a seller and return its inventory
func findSellerInventory(shorthand string) (mtgban.InventoryRecord, error) {
	for _, seller := range Sellers {
		if seller == nil {
			continue
		}
		if strings.ToLower(seller.Info().Shorthand) == strings.ToLower(shorthand) {
			return seller.Inventory()
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor and return its buylist
func findVendorBuylist(shorthand string) (mtgban.BuylistRecord, error) {
	for _, vendor := range Vendors {
		if vendor == nil {
			continue
		}
		if strings.ToLower(vendor.Info().Shorthand) == strings.ToLower(shorthand) {
			return vendor.Buylist()
		}
	}
	return nil, errors.New("vendor not found")
}

// Look up a seller with its name and return its inventory
func findSellerInventoryByName(name string, sealed bool) (mtgban.InventoryRecord, error) {
	for _, seller := range Sellers {
		if seller == nil {
			continue
		}
		if seller.Info().SealedMode == sealed && strings.ToLower(seller.Info().Shorthand) == strings.ToLower(name) {
			return seller.Inventory()
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor with its name and return its inventory
func findVendorBuylistByName(name string, sealed bool) (mtgban.BuylistRecord, error) {
	for _, vendor := range Vendors {
		if vendor == nil {
			continue
		}
		if vendor.Info().SealedMode == sealed && strings.ToLower(vendor.Info().Name) == strings.ToLower(name) {
			return vendor.Buylist()
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

// Look for a the SKU of a tcgplayer listing
func findTCGproductSKU(cardId string, cond string) string {
	tcgplayer, _ := findSellerInventory("TCGPlayer")
	for _, entry := range tcgplayer[cardId] {
		if entry.Conditions == cond {
			return entry.InstanceId
		}
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
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return false
	}
	set, err := mtgmatcher.GetSet(co.SetCode)
	if err != nil {
		return false
	}
	releaseDate := set.ReleaseDate
	if co.OriginalReleaseDate != "" {
		releaseDate = co.OriginalReleaseDate
	}
	setDate, err := time.Parse("2006-01-02", releaseDate)
	if err != nil {
		return false
	}
	return setDate.After(mtgmatcher.PromosForEverybodyYay)
}

func uuid2card(cardId string, flags ...bool) GenericCard {
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

	variant := ""
	if showVariant(cardId) {
		switch {
		case co.HasFrameEffect(mtgjson.FrameEffectShowcase):
			variant = "Showcase "
		case co.HasFrameEffect(mtgjson.FrameEffectExtendedArt):
			variant = "Extended Art "
		case co.BorderColor == mtgjson.BorderColorBorderless:
			variant = "Borderless "
		case co.FrameVersion == "1997":
			variant = "Retro Frame "
		}
	}
	// Loop through the supported promo types, skipping Boosterfun already processed above
	for _, promoType := range co.PromoTypes {
		if slices.Contains(mtgmatcher.AllPromoTypes(), promoType) && promoType != mtgjson.PromoTypeBoosterfun {
			variant += mtgmatcher.Title(promoType) + " "
		}
	}
	variant = strings.TrimSpace(variant)

	name := co.Name
	if co.FlavorName != "" {
		if variant != "" {
			variant = " - " + variant
		}
		variant = fmt.Sprintf("\"%s\" %s", co.FlavorName, variant)
	}

	query := co.Name
	if !co.Sealed {
		query = fmt.Sprintf("%s s:%s cn:%s", co.Name, co.SetCode, co.Number)
		if co.Etched {
			query += " f:etched"

			// Append Etched information to the tag
			if variant != "" {
				variant += " "
			}
			variant += "Etched"
		} else if co.Foil {
			query += " f:foil"
		} else if !co.Etched && !co.Foil {
			query += " f:nonfoil"
		}
	}

	imgURL := co.Images["full"]
	if len(flags) > 0 && flags[0] {
		imgURL = co.Images["thumbnail"]
	}
	printings := ""
	if len(flags) > 1 && flags[1] {
		// Hack to generate HTML in the template
		for i, setCode := range co.Printings {
			set, err := mtgmatcher.GetSet(setCode)
			if err != nil {
				continue
			}
			printings += fmt.Sprintf(`<a class="pagination" title="%s" href="/search?q=%s">`, set.Name, url.QueryEscape(co.Name+" s:"+setCode))

			keyruneCode := strings.ToLower(set.KeyruneCode)
			if keyruneCode == "" {
				printings += fmt.Sprintf(`
                    <svg width="32" height="32" xmlns="http://www.w3.org/2000/svg">
                        <circle r="15" cx="16" cy="16" fill="var(--normal)"/>
                        <text font-size="20" x="50%%" y="60%%" text-anchor="middle" fill="var(--background)">%s</text>
                    </svg>`, setCode)
			} else {
				printings += fmt.Sprintf(`<i class="ss ss-%s ss-2x"></i>`, keyruneCode)
			}
			printings += fmt.Sprintf(`</a>`)

			if i == MaxRuneSymbols && len(co.Printings) > MaxRuneSymbols {
				printings += "<br>and many more (too many to list)..."
				break
			}
		}
		// Shrink icons to fit more of them
		if len(co.Printings) > MaxBeforeShrink {
			// Make sure not to capture the 2X2 set code
			printings = strings.Replace(printings, "ss-2x\"", "ss-1x\"", -1)
		}
	}

	if co.Sealed {
		// The first chunk is always present, even for foil-only sets
		printings = "<h6>Set Value</h6><table class='setValue'>"

		for i, title := range ProductTitles {
			entries, found := Infos[ProductKeys[i]][co.SetCode]
			if found {
				printings += fmt.Sprintf("<tr class='setValue'><td class='setValue'><h5>%s</h5></td><td>$ %.02f</td></tr>", title, entries[0].Price)
			}
		}
		printings += "</table>"

		// The second chunk is optional, check for the first key
		if len(Infos[ProductFoilKeys[0]][co.SetCode]) > 0 {
			printings += "<br>"
			printings += "<h6>Foil Set Value</h6><table class='setValue'>"

			for i, title := range ProductTitles {
				entries, found := Infos[ProductFoilKeys[i]][co.SetCode]
				if found {
					printings += fmt.Sprintf("<tr class='setValue'><td class='setValue'><h5>%s</h5></td><td>$ %.02f</td></tr>", title, entries[0].Price)
				}
			}
			printings += "</table>"
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
	if len(sourceSealed) > 0 {
		products += "<h4>"
		for _, sealed := range sourceSealed {
			// The sealed uuids while known might have changed and we need to
			// make sure they don't crash the system here
			sealedCo, err := mtgmatcher.GetUUID(sealed)
			if err != nil {
				continue
			}
			products += "<a href=/sealed?q=" + sealed + ">" + sealedCo.Name + "</a><br>"
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
	CKAPIMutex.RLock()
	restock, found := CKAPIOutput[co.Identifiers["mtgjsonId"]]
	CKAPIMutex.RUnlock()
	if found {
		if co.Etched && restock.Etched != nil {
			restockURL = restock.Etched.URL
		} else if co.Foil && restock.Foil != nil {
			restockURL = restock.Foil.URL
		} else if !co.Etched && !co.Foil && restock.Normal != nil {
			restockURL = restock.Normal.URL
		}
		if restockURL != "" {
			restockURL = strings.Replace(restockURL, "mtg", "catalog/restock_notice", 1)
			restockURL += "?partner=" + Config.Affiliate["CK"]
		}
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

	return GenericCard{
		UUID:      co.UUID,
		Name:      name,
		Edition:   co.Edition,
		SetCode:   co.Card.SetCode,
		Number:    co.Card.Number,
		Variant:   variant,
		Foil:      co.Foil,
		Etched:    co.Etched,
		Keyrune:   keyruneForCardSet(cardId),
		ImageURL:  imgURL,
		Title:     editionTitle(cardId),
		Reserved:  co.Card.IsReserved,
		SearchURL: fmt.Sprintf("/%s?q=%s", path, url.QueryEscape(query)),
		SypList:   sypList,
		Stocks:    stocks,
		StocksURL: stocksURL,
		Printings: printings,
		Products:  products,
		TCGId:     tcgId,
		Date:      co.OriginalReleaseDate,
		Sealed:    co.Sealed,
		Booster:   canBoosterGen,
		HasDeck:   hasDecklist,
		Flag:      allLanguageFlags[co.Language],

		RarityColor:  rarityColor,
		ScryfallURL:  scryfallURL,
		DeckboxURL:   deckboxURL,
		CKRestockURL: restockURL,
		SourceSealed: sourceSealed,
	}
}

type Notification struct {
	Username string `json:"username"`
	Content  string `json:"content"`
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
	go notify(kind, message, Config.DiscordNotifHook)
}

// Only send the notification for a user action
func UserNotify(kind, message string, flags ...bool) {
	if DevMode {
		log.Println(kind, "-", message)
	}
	if Config.DiscordHook == "" {
		return
	}
	if len(flags) > 0 && flags[0] {
		message = "@here " + message
	}
	go notify(kind, message, Config.DiscordHook)
}

func notify(kind, message, hook string) {
	var payload Notification
	payload.Username = kind
	if DevMode {
		payload.Content = "[DEV] "
	}
	payload.Content += message

	reqBody, err := json.Marshal(&payload)
	if err != nil {
		log.Println(err)
		return
	}

	resp, err := cleanhttp.DefaultClient().Post(hook, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Println(err)
		return
	}
	resp.Body.Close()
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
	setCookie(w, r, cookieName, val)
	return flag
}

// Read a cookie from the request
func readCookie(r *http.Request, cookieName string) string {
	for _, cookie := range r.Cookies() {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}

// Set a cookie in the response with no expiration at the default root
func setCookie(w http.ResponseWriter, r *http.Request, cookieName, value string) {
	domain := "mtgban.com"
	if strings.Contains(getBaseURL(r), "localhost") {
		domain = "localhost"
	}
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Domain: domain,
		Path:   "/",
		// No expiration
		Expires: time.Now().Add(10 * 365 * 24 * 60 * 60 * time.Second),
		Value:   value,
		// Enforce first party cookies only
		SameSite: http.SameSiteStrictMode,
	})
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

	page.TotalIndex = len(slice)/maxResults + 1
	if page.TotalIndex > maxTotalResults/maxResults {
		page.TotalIndex = maxTotalResults / maxResults
	}

	// Parse the requested input page
	if pageIndex <= 1 {
		pageIndex = 1
	} else if pageIndex > page.TotalIndex {
		pageIndex = page.TotalIndex
	}

	// Assign the current page index to enable pagination
	page.CurrentIndex = pageIndex

	// Initialize previous and next pagination links
	if page.CurrentIndex > 0 {
		page.PrevIndex = page.CurrentIndex - 1
	}
	if page.CurrentIndex < page.TotalIndex {
		page.NextIndex = page.CurrentIndex + 1
	}

	// Chop results where needed
	head := maxResults * (pageIndex - 1)
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
	entries, found := inv[cardId]
	if !found {
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
