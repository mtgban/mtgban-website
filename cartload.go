package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/starcitygames"
)

// cartStores are the stores whose carts the BAN-to-Cart bookmarklet fills,
// keyed by the prefix their splits' shorthands share, with the page each
// side's button opens. An empty page gets no button: SCG's retail side and
// CK's buylist have their own imports on the upload page. SCG's page is its
// CSV uploads, where the bookmarklet hands SCG the list to match. Strike Zone
// buys and sells through one cart page, so a retail link also says
// side=retail.
var cartStores = []cartStore{
	{"ABU", "ABU", "https://abugames.com/cartview/buylist", "https://abugames.com/cartview/shop"},
	{"CSI", "CSI", "https://www.coolstuffinc.com/buylist_cart.php", "https://www.coolstuffinc.com/main_view_cart.php"},
	{"SCG", "SCG", "https://sellyourcards.starcitygames.com/mtg/uploads", ""},
	{"MMC", "MTG Mint Card", "https://www.mtgmintcard.com/buylist-cart", "https://www.mtgmintcard.com/shopping-cart"},
	{"SZ", "Strike Zone", "http://shop.strikezoneonline.com/TUser?MC=CUVC&MF=B&BUID=637", "http://shop.strikezoneonline.com/TUser?MC=CUVC&MF=B&BUID=637"},
	{"HA", "Hareruya", "https://www.hareruyamtg.com/ja/purchase/cart", "https://www.hareruyamtg.com/en/cart"},
	{"ML", "Manaleak", "https://www.manaleak.com/index.php?route=buylist/cart", "https://www.manaleak.com/index.php?route=checkout/cart"},
	// Mana Pool buys nothing; its store cart is filled through its optimizer
	{"MP", "Mana Pool", "", "https://manapool.com/cart"},
	// Both buylists run on StorePass, whose page keeps the cart; Game
	// Nerdz's store is a BigCommerce one
	{"GN", "Game Nerdz", "https://buylist.gamenerdz.com/retailer/buylist", "https://www.gamenerdz.com/cart.php"},
	{"VS", "Vegas Singles", "https://buylist.vegas.singles/retailer/buylist", ""},
	// Card Trader buys nothing; its store cart is filled from the listings
	// live at load time
	{"CT", "Card Trader", "", "https://www.cardtrader.com/cart/edit"},
	{"CK", "Card Kingdom", "", "https://www.cardkingdom.com/cart"},
}

// cartRetailIDs name a store row the way a store's cart takes it, for a store
// whose cart is not keyed by the entry's InstanceID, by the splits it was
// measured on.
var cartRetailIDs = map[string]func(mtgban.InventoryEntry) string{
	"CK":    ckCartID,
	"CSI":   csiCartID,
	"CT":    ctCartID,
	"CT0":   ctCartID,
	"CT1DR": ctCartID,
}

// ctSplits name Card Trader's storefronts the way its loader tells their
// listings apart: everyone, Zero's sellers, and the 1-Day Ready groups.
var ctSplits = map[string]string{
	"Card Trader":      "m",
	"Card Trader Zero": "z",
	"Card Trader 1DR":  "d",
}

// ctCartID names a Card Trader row by what its loader looks the card's live
// listings up with, as <blueprint>-<grade>-<price cents><currency>-<split>-
// <properties>: the price as Card Trader quotes the one BAN shows, and the
// properties_hash keys and values that tell the game's listings apart, as a
// query, base64url so any value fits the id.
func ctCartID(entry mtgban.InventoryEntry) string {
	fields := entry.CustomFields
	split := ctSplits[entry.SellerName]
	if split == "" || entry.OriginalID == "" || entry.Conditions == "" ||
		fields["PriceCents"] == "" || fields["PriceCurrency"] == "" || fields["Properties"] == "" {
		return ""
	}
	return strings.Join([]string{
		entry.OriginalID,
		string(entry.Conditions),
		fields["PriceCents"] + fields["PriceCurrency"],
		split,
		base64.RawURLEncoding.EncodeToString([]byte(fields["Properties"])),
	}, "-")
}

// cartBuylistIDs name a buylist row the way a store's cart takes it, for a
// store whose cart is not keyed by the entry's InstanceID, by its splits.
var cartBuylistIDs = map[string]func(mtgban.BuylistEntry) string{
	"GN": storePassCartID,
	"VS": storePassCartID,
}

// storePassCartID names a StorePass buylist row as <product id>-<variant
// id>: the product its page looks up, and the variant, one per condition
// where the store prices each, that the row is offered in.
func storePassCartID(entry mtgban.BuylistEntry) string {
	if entry.OriginalID == "" || entry.InstanceID == "" {
		return ""
	}
	return entry.OriginalID + "-" + entry.InstanceID
}

// csiCartID names a CSI store row as <product id>-<row id>, the pair its
// cart's add takes.
func csiCartID(entry mtgban.InventoryEntry) string {
	if entry.OriginalID == "" || entry.InstanceID == "" {
		return ""
	}
	return entry.OriginalID + "-" + entry.InstanceID
}

// cartAffiliates are how a store's own links from us credit our partner
// account, by the prefix its splits share, applied to the cart page a "Load
// at" button opens so that the cart it fills is credited the same way.
var cartAffiliates = map[string]func(code, page string) string{
	"CK": func(code, page string) string {
		return withQuery(page, url.Values{"partner": {code}, "utm_source": {code}, "utm_campaign": {code}, "utm_medium": {"affiliate"}})
	},
	"MMC": func(code, page string) string {
		return withQuery(page, url.Values{"utm_source": {code}, "utm_campaign": {code}, "utm_medium": {"referral"}})
	},
	"CSI": func(code, page string) string {
		return withQuery(page, url.Values{"utm_referrer": {code}})
	},
	"CT": func(code, page string) string {
		return withQuery(page, url.Values{"share_code": {code}})
	},
	// Mana Pool's own ref query, as its product links carry it
	"MP": func(code, page string) string {
		return withQuery(page, url.Values{"ref": {code}})
	},
	// Through the partner redirector, with the list inside its u query: a
	// privacy tool that skips the redirect opens u alone. The redirector
	// refuses a link past about 8 KB, so a longer list goes after it.
	"SCG": func(code, page string) string {
		redirect := fmt.Sprintf(starcitygames.PartnerProductURL, url.PathEscape(code)) + "?u="
		link := redirect + url.QueryEscape(page)
		target, list, found := strings.Cut(page, "#")
		if len(link) <= scgRedirectMax || !found {
			return link
		}
		return redirect + url.QueryEscape(target) + "#" + list
	},
}

// scgRedirectMax is the longest link SCG's partner redirector is sent with
// the list inside it, under the 8,000 or so characters past which it answers
// 400, with room for the longest SKUs.
const scgRedirectMax = 7000

// affiliated is the cart page, its fragment included, as a store's links
// from us carry it, where an affiliate code is configured for the store.
func affiliated(prefix, page string) string {
	credit, found := cartAffiliates[prefix]
	code := Affiliates().Codes[prefix]
	if !found || code == "" {
		return page
	}
	return credit(code, page)
}

// withQuery is page with the values added to its query.
func withQuery(page string, add url.Values) string {
	u, err := url.Parse(page)
	if err != nil {
		return page
	}
	values := u.Query()
	for name, value := range add {
		values[name] = value
	}
	u.RawQuery = values.Encode()
	return u.String()
}

// ckStyles are Card Kingdom's names for the grades its store cart sells.
var ckStyles = map[mtgban.Condition]string{
	mtgban.NM: "NM",
	mtgban.SP: "EX",
	mtgban.MP: "VG",
	mtgban.HP: "G",
}

// ckCartID names a Card Kingdom row by the product id and style its cart's
// add call takes, as <product id>-<style>.
func ckCartID(entry mtgban.InventoryEntry) string {
	style := ckStyles[entry.Conditions]
	if entry.OriginalID == "" || style == "" {
		return ""
	}
	return entry.OriginalID + "-" + style
}

type cartStore struct {
	prefix  string
	name    string
	buylist string
	retail  string
}

// page is the cart page a split's button opens on the side buylist says.
func (cs cartStore) page(buylist bool) string {
	if buylist {
		return cs.buylist
	}
	return cs.retail
}

// cartLoad is what a split's "Load at" button needs: the store's name, its
// cart page with the split's rows in the fragment, and each row's store item
// id in row order, empty where the store lists none, for js/load-lists.js to
// rebuild the fragment from the rows left ticked. Quantities, where set, are
// each row's quantity in the same order, for a link whose rows ask for
// other than the page's.
type cartLoad struct {
	Store      string
	Link       string
	Items      string
	Quantities string
}

// cartLoadFor builds the button for a store split, or nothing for a store the
// bookmarklet does not fill or a split with no row it can load. See
// docs/store-carts.md.
func cartLoadFor(key string, buylist bool, entries []OptimizedUploadEntry) cartLoad {
	for _, cs := range cartStores {
		if !strings.HasPrefix(key, cs.prefix) {
			continue
		}
		page := cs.page(buylist)
		if page == "" {
			return cartLoad{}
		}
		items := cartItems(key, buylist, entries)
		rows := cartRows(items, entries)
		if rows == "" {
			return cartLoad{}
		}
		page += "#ban=" + rows + "&v=" + cartVersion()
		if !buylist {
			page += "&side=retail"
		}
		// Rows with no item the loader can take, for it to say were left out
		skipped := 0
		for _, id := range items {
			if id == "" {
				skipped++
			}
		}
		if skipped > 0 {
			page += "&skip=" + strconv.Itoa(skipped)
		}
		return cartLoad{Store: cs.name, Link: affiliated(cs.prefix, page), Items: strings.Join(items, ",")}
	}
	return cartLoad{}
}

// cartAsksMost are the splits whose feed does not give their stock: Mint's
// caps it at 8, and Card Trader's is gone by the time a listing is loaded,
// which is filled from every listing at or under the price BAN shows. Mana
// Pool's gives none, but its optimizer fills a line from the cheapest
// listings up, at rising prices, so it asks for the row's own.
var cartAsksMost = []string{"MMC", "CT", "CT0", "CT1DR"}

// cartMostQuantity is what a cart is asked for to get as many as the store
// has, for a store whose cart trims a quantity to its stock.
const cartMostQuantity = 999

// cartLoadForArbit is cartLoadFor over an arbit section's rows, each in the
// condition the store sells it in. A store whose feed does not give its stock
// (cartAsksMost) asks its store cart for what the buylist takes, or as many
// as it has where the buylist names no amount, and the store trims it to
// what it has.
func cartLoadForArbit(key string, buylist bool, entries []mtgban.ArbitEntry) cartLoad {
	most := !buylist && slices.Contains(cartAsksMost, key)
	rows := make([]OptimizedUploadEntry, 0, len(entries))
	quantities := make([]string, 0, len(entries))
	for _, entry := range entries {
		qty := max(entry.Quantity, 1)
		if most {
			qty = entry.BuylistEntry.Quantity
			if qty <= 0 {
				qty = cartMostQuantity
			}
		}
		rows = append(rows, OptimizedUploadEntry{
			CardID:    entry.CardID,
			Condition: entry.InventoryEntry.Conditions,
			Quantity:  qty,
		})
		quantities = append(quantities, strconv.Itoa(qty))
	}
	load := cartLoadFor(key, buylist, rows)
	if most && load.Link != "" {
		load.Quantities = strings.Join(quantities, ",")
	}
	return load
}

// cartStoresIn answers whether any of the splits keys names is one a store
// cart button can open, on the side buylist says.
func cartStoresIn(keys []string, buylist bool) bool {
	for _, key := range keys {
		for _, cs := range cartStores {
			if cartTakes(cs, key, buylist) {
				return true
			}
		}
	}
	return false
}

// cartTakes reports whether a store's cart takes key's split on the side
// buylist says. A store whose rows go by its own ids (cartRetailIDs) was
// measured on the splits named there alone, not its graded or sealed ones.
func cartTakes(cs cartStore, key string, buylist bool) bool {
	if !strings.HasPrefix(key, cs.prefix) || cs.page(buylist) == "" {
		return false
	}
	_, own := cartRetailIDs[cs.prefix]
	_, named := cartRetailIDs[key]
	return buylist || !own || named
}

// cartItems is the store item id of each of a split's rows, empty for a card
// the store lists no id for. A buylist row goes in as NM, a store row in the
// condition it was priced at.
func cartItems(key string, buylist bool, entries []OptimizedUploadEntry) []string {
	var lookup func(cardID string, cond mtgban.Condition) string
	if buylist {
		bl, err := findVendorBuylist(key)
		if err != nil {
			return nil
		}
		name := func(entry mtgban.BuylistEntry) string {
			return entry.InstanceID
		}
		named, found := cartBuylistIDs[key]
		if found {
			name = named
		}
		// Sold as NM whatever the row says: the store grades what arrives.
		// Sealed product carries no grade at all.
		lookup = func(cardID string, _ mtgban.Condition) string {
			entries := bl[cardID]
			grade := mtgban.NM
			if len(entries) > 0 && entries[0].Conditions == "" {
				grade = ""
			}
			i := pricedEntry(entries, grade)
			if i < 0 {
				return ""
			}
			return name(entries[i])
		}
	} else {
		inv, err := findSellerInventory(key)
		if err != nil {
			return nil
		}
		name := func(entry mtgban.InventoryEntry) string {
			return entry.InstanceID
		}
		for _, cs := range cartStores {
			_, own := cartRetailIDs[cs.prefix]
			if !own || !strings.HasPrefix(key, cs.prefix) {
				continue
			}
			if !cartTakes(cs, key, false) {
				return nil
			}
			name = cartRetailIDs[key]
			break
		}
		lookup = func(cardID string, cond mtgban.Condition) string {
			entries := inv[cardID]
			i := pricedEntry(entries, cond)
			if i < 0 {
				return ""
			}
			return name(entries[i])
		}
	}

	items := make([]string, len(entries))
	for i, entry := range entries {
		id := lookup(entry.CardID, entry.Condition)
		if cartItemID.MatchString(id) {
			items[i] = id
		}
	}
	return items
}

// cartItemID is the store item id js/ban-to-cart.js takes. Another would be
// dropped there, and a comma would shift the button's ids out of row order.
var cartItemID = regexp.MustCompile(`^[\w-]+$`)

// cartRows lists a store split's cards the way js/ban-to-cart.js reads them
// from the fragment of the cart page: "id:qty" pairs joined by commas, one
// per store item id, with the quantities of rows sharing an id added up.
// items holds each row's id, as cartItems finds them.
func cartRows(items []string, entries []OptimizedUploadEntry) string {
	var ids []string
	quantities := map[string]int{}
	for i, id := range items {
		if id == "" {
			continue
		}
		if _, found := quantities[id]; !found {
			ids = append(ids, id)
		}
		quantities[id] += entries[i].Quantity
	}

	pairs := make([]string, 0, len(ids))
	for _, id := range ids {
		pairs = append(pairs, id+":"+strconv.Itoa(quantities[id]))
	}
	return strings.Join(pairs, ",")
}

// pricedEntry is the index of the entry the optimizer priced a row from: the
// one in the row's condition, or for a row naming none the first priced
// entry, as processEntry picks its base. -1 when there is none.
func pricedEntry[T mtgban.GenericEntry](entries []T, cond mtgban.Condition) int {
	for i := range entries {
		if cond == "" && entries[i].Pricing() != 0 {
			return i
		}
		if cond != "" && entries[i].Condition() == cond {
			return i
		}
	}
	return -1
}

// cartLoader is js/ban-to-cart.js as a link a user drags to their bookmarks
// bar, read once and stripped (stripLoader), and the version stamped into
// it: the start of the stripped code's hash, which every cart link carries
// too, so a bookmark saved from other code can tell it is out of date.
var cartLoader = sync.OnceValues(func() (template.URL, string) {
	source, err := os.ReadFile("js/ban-to-cart.js")
	if err != nil {
		log.Println("cart bookmarklet:", err)
		return "", ""
	}
	code := stripLoader(string(source))
	sum := sha256.Sum256([]byte(code))
	version := hex.EncodeToString(sum[:4])
	code = strings.Replace(code, cartVersionMark, version, 1)
	// void keeps the browser from replacing the page with the script's result
	return template.URL("javascript:void%20" + url.PathEscape(code)), version
})

// stripLoader is the loader's code without its indentation, blank lines and
// whole-line comments, to keep the bookmark well under Firefox's limit of
// 65,536 characters on its URL. Only whole lines go, so a comment after
// code on its line stays in.
func stripLoader(source string) string {
	var lines []string
	for line := range strings.Lines(source) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// cartVersionMark is where js/ban-to-cart.js takes its version.
const cartVersionMark = "__BAN_VERSION__"

func cartBookmarklet() template.URL {
	link, _ := cartLoader()
	return link
}

func cartVersion() string {
	_, version := cartLoader()
	return version
}
