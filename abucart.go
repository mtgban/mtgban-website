package main

import (
	"html/template"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgban"
)

// abuCartRows lists a store split's cards the way js/abu-cart.js reads them
// from the fragment of the ABU cart page: "id:qty" pairs joined by commas,
// one per ABU item id, with the quantities of rows sharing an id added up.
// A buylist row goes in as NM, a store row in the condition it was priced
// at. key is the split's store; a store that is not ABU, and a card ABU
// lists no id for, give nothing. See docs/abu-carts.md.
func abuCartRows(key string, buylist bool, entries []OptimizedUploadEntry) string {
	if !strings.HasPrefix(key, "ABU") {
		return ""
	}

	var lookup func(cardID string, cond mtgban.Condition) string
	if buylist {
		bl, err := findVendorBuylist(key)
		if err != nil {
			return ""
		}
		// Sold as NM whatever the row says: ABU grades what arrives
		lookup = func(cardID string, _ mtgban.Condition) string {
			entries := bl[cardID]
			i := pricedEntry(entries, mtgban.NM)
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

// abuBookmarklet is js/abu-cart.js as a link a user drags to their bookmarks
// bar, read once.
var abuBookmarklet = sync.OnceValue(func() template.URL {
	source, err := os.ReadFile("js/abu-cart.js")
	if err != nil {
		log.Println("abu bookmarklet:", err)
		return ""
	}
	// void keeps the browser from replacing the page with the script's result
	return template.URL("javascript:void%20" + url.PathEscape(strings.TrimSpace(string(source))))
})
