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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

var Country2flag = map[string]string{
	"EU": "🇪🇺",
	"JP": "🇯🇵",
}

var colorRarityMap = map[string]map[string]string{
	"lorcana": {
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
	LangTag   string

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
		if strings.ToLower(seller.Info().Shorthand) == strings.ToLower(shorthand) {
			return seller.Inventory(), nil
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor and return its buylist
func findVendorBuylist(shorthand string) (mtgban.BuylistRecord, error) {
	for _, vendor := range Vendors {
		if strings.ToLower(vendor.Info().Shorthand) == strings.ToLower(shorthand) {
			return vendor.Buylist(), nil
		}
	}
	return nil, errors.New("vendor not found")
}

// Look up a seller with its name and return its inventory
func findSellerInventoryByName(name string, sealed bool) (mtgban.InventoryRecord, error) {
	for _, seller := range Sellers {
		if seller.Info().SealedMode == sealed && strings.ToLower(seller.Info().Name) == strings.ToLower(name) {
			return seller.Inventory(), nil
		}
	}
	return nil, errors.New("seller not found")
}

// Look up a vendor with its name and return its inventory
func findVendorBuylistByName(name string, sealed bool) (mtgban.BuylistRecord, error) {
	for _, vendor := range Vendors {
		if vendor.Info().SealedMode == sealed && strings.ToLower(vendor.Info().Name) == strings.ToLower(name) {
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

	variant := ""
	if showVariant(cardId) {
		switch {
		case co.HasFrameEffect(mtgmatcher.FrameEffectShowcase):
			variant = "Showcase "
		case co.HasFrameEffect(mtgmatcher.FrameEffectExtendedArt):
			variant = "Extended Art "
		case co.BorderColor == mtgmatcher.BorderColorBorderless:
			variant = "Borderless "
		case co.FrameVersion == "1997":
			variant = "Retro Frame "
		}
	}
	// Loop through the supported promo types, skipping Boosterfun already processed above
	for _, promoType := range co.PromoTypes {
		if slices.Contains(mtgmatcher.AllPromoTypes(), promoType) && promoType != mtgmatcher.PromoTypeBoosterfun {
			if strings.HasPrefix(promoType, "ff") {
				variant += strings.ToUpper(promoType) + " "
				continue
			}
			variant += mtgmatcher.Title(promoType) + " "
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

	query := genQuery(co)

	imgURL := co.Images["full"]
	if useThumbs {
		imgURL = co.Images["thumbnail"]
	}

	printings := ""
	if genPrints {
		printings = genPrintings(co)
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
		LangTag:   mtgmatcher.LanguageTag2LanguageCode[co.Language],

		RarityColor:  rarityColor,
		ScryfallURL:  scryfallURL,
		DeckboxURL:   deckboxURL,
		CKRestockURL: restockURL,
		SourceSealed: sourceSealed,
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

func genPrintings(co *mtgmatcher.CardObject) string {
	printings := ""
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
	return printings
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
	if Config.DiscordHook == "" {
		return
	}
	if len(flags) > 0 && flags[0] {
		message = "@here " + message
		log.Println(kind, "-", message)
	}
	go notify(kind, message, Config.DiscordHook)
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
	setForeverCookie(w, cookieName, val)
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
	}

	if !global {
		// Enforce first party cookies only
		cookie.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &cookie)
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

// Return the full display name displayed from the input shorthand
func scraperName(shorthand string) string {
	for _, seller := range Sellers {
		if shorthand == seller.Info().Shorthand {
			return seller.Info().Name
		}
	}
	for _, vendor := range Vendors {
		if shorthand == vendor.Info().Shorthand {
			return vendor.Info().Name
		}
	}
	return ""
}
