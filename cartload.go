package main

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgban"
)

// cartStores are the stores whose carts the BAN-to-Cart bookmarklet fills,
// keyed by the prefix their splits' shorthands share, with the page each
// side's button opens. An empty page gets no button: CSI's and SCG's retail
// sides have their own imports on the upload page, and Mint's store cart is
// not filled. SCG's page is its CSV uploads, where the bookmarklet hands SCG
// the list to match.
var cartStores = []cartStore{
	{"ABU", "ABU", "https://abugames.com/cartview/buylist", "https://abugames.com/cartview/shop"},
	{"CSI", "CSI", "https://www.coolstuffinc.com/buylist_cart.php", ""},
	{"SCG", "SCG", "https://sellyourcards.starcitygames.com/mtg/uploads", ""},
	{"MMC", "MTG Mint Card", "https://www.mtgmintcard.com/buylist-cart", ""},
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

// cartLoad is what a split's "Load at" button needs: the store's name, and
// its cart page with the split's rows in the fragment.
type cartLoad struct {
	Store string
	Link  string
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
		rows := cartRows(key, buylist, entries)
		if rows == "" {
			return cartLoad{}
		}
		return cartLoad{Store: cs.name, Link: page + "#ban=" + rows + "&v=" + cartVersion()}
	}
	return cartLoad{}
}

// cartLoadForArbit is cartLoadFor over an arbit section's rows, each in the
// condition the store sells it in.
func cartLoadForArbit(key string, buylist bool, entries []mtgban.ArbitEntry) cartLoad {
	rows := make([]OptimizedUploadEntry, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, OptimizedUploadEntry{
			CardID:    entry.CardID,
			Condition: entry.InventoryEntry.Conditions,
			Quantity:  max(entry.Quantity, 1),
		})
	}
	return cartLoadFor(key, buylist, rows)
}

// cartStoresIn answers whether any of the splits keys names is one a store
// cart button can open, on the side buylist says.
func cartStoresIn(keys []string, buylist bool) bool {
	for _, key := range keys {
		for _, cs := range cartStores {
			if strings.HasPrefix(key, cs.prefix) && cs.page(buylist) != "" {
				return true
			}
		}
	}
	return false
}

// cartRows lists a store split's cards the way js/ban-to-cart.js reads them
// from the fragment of the cart page: "id:qty" pairs joined by commas, one
// per store item id, with the quantities of rows sharing an id added up. A
// buylist row goes in as NM, a store row in the condition it was priced at.
// A card the store lists no id for is left out.
func cartRows(key string, buylist bool, entries []OptimizedUploadEntry) string {
	var lookup func(cardID string, cond mtgban.Condition) string
	if buylist {
		bl, err := findVendorBuylist(key)
		if err != nil {
			return ""
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
			return entries[i].InstanceID
		}
	} else {
		inv, err := findSellerInventory(key)
		if err != nil {
			return ""
		}
		lookup = func(cardID string, cond mtgban.Condition) string {
			entries := inv[cardID]
			i := pricedEntry(entries, cond)
			if i < 0 {
				return ""
			}
			return entries[i].InstanceID
		}
	}

	var ids []string
	quantities := map[string]int{}
	for _, entry := range entries {
		id := lookup(entry.CardID, entry.Condition)
		if id == "" {
			continue
		}
		if _, found := quantities[id]; !found {
			ids = append(ids, id)
		}
		quantities[id] += entry.Quantity
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
// bar, read once, and the version stamped into it: the start of the file's
// hash, which every cart link carries too, so a bookmark saved from an older
// file can tell it is out of date.
var cartLoader = sync.OnceValues(func() (template.URL, string) {
	source, err := os.ReadFile("js/ban-to-cart.js")
	if err != nil {
		log.Println("cart bookmarklet:", err)
		return "", ""
	}
	sum := sha256.Sum256(source)
	version := hex.EncodeToString(sum[:4])
	code := strings.Replace(strings.TrimSpace(string(source)), cartVersionMark, version, 1)
	// void keeps the browser from replacing the page with the script's result
	return template.URL("javascript:void%20" + url.PathEscape(code)), version
})

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
