package main

import (
	"slices"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/banprice"
)

// The v2 price maps are built straight from the stores' records, not from
// v1's, so a store's every grade is kept. They follow v1 in what they read:
// the same stores, filters and id modes.

// v2Finish is the finish a card's prices are filed under in v2.
func v2Finish(co *mtgmatcher.CardObject) string {
	if co.Sealed {
		return banprice.FinishSealed
	}
	return co.Finish
}

// v2Cards is the cards a filtered request asks for, kept to its finish and
// to singles or sealed, and whether the request is filtered at all.
func v2Cards(b *mtgmatcher.Backend, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool) ([]string, bool) {
	if filterByEdition == "" && filterByHash == nil {
		return nil, false
	}
	uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
	config := apiSearchConfig(b, uuids, nil, filterByFinish, sealed)
	return filterUUIDs(b, config.UUIDs, config.CardFilters), true
}

func getSellerPricesV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool, tagName string) banprice.V2 {
	cardIDs, filtered := v2Cards(b, filterByEdition, filterByHash, filterByFinish, sealed)
	var finishFilter []string
	if filterByFinish != "" && !filtered {
		finishFilter = fixupFinishNG(filterByFinish)
	}

	out := banprice.V2{}
	for _, seller := range GetSellers() {
		info := seller.Info()
		if info.SealedMode != sealed || !slices.Contains(enabledStores, info.Shorthand) {
			continue
		}

		withQty := !info.MetadataOnly && !info.NoQuantityInventory
		stock := v2Stock(info.Shorthand)

		tag := info.Shorthand
		if tagName == "names" {
			tag = info.Name
		}
		inventory := seller.Inventory()
		if !filtered {
			for cardID, entries := range inventory {
				addV2Entries(b, out, entries, mode, cardID, tag, finishFilter, withQty, !info.MetadataOnly, false, stock)
			}
			continue
		}
		for _, cardID := range cardIDs {
			entries, found := inventory[cardID]
			if found {
				addV2Entries(b, out, entries, mode, cardID, tag, nil, withQty, !info.MetadataOnly, false, stock)
			}
		}
	}
	return out
}

func getVendorPricesV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool, tagName string) banprice.V2 {
	cardIDs, filtered := v2Cards(b, filterByEdition, filterByHash, filterByFinish, sealed)
	var finishFilter []string
	if filterByFinish != "" && !filtered {
		finishFilter = fixupFinishNG(filterByFinish)
	}

	out := banprice.V2{}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if info.SealedMode != sealed || !slices.Contains(enabledStores, info.Shorthand) {
			continue
		}

		// An index vendor's quantity is a want-count where it says so
		withQty := !info.MetadataOnly || info.QuantityPriority

		tag := info.Shorthand
		if tagName == "names" {
			tag = info.Name
		}
		buylist := vendor.Buylist()
		if !filtered {
			for cardID, entries := range buylist {
				addV2Entries(b, out, entries, mode, cardID, tag, finishFilter, withQty, !info.MetadataOnly, true, nil)
			}
			continue
		}
		for _, cardID := range cardIDs {
			entries, found := buylist[cardID]
			if found {
				addV2Entries(b, out, entries, mode, cardID, tag, nil, withQty, !info.MetadataOnly, true, nil)
			}
		}
	}
	return out
}

// v2Stock is where a store with no quantities of its own reads its
// Available from: TCGplayer Direct its own stock, and TCGplayer its
// listings' copies.
func v2Stock(store string) func(cardID string, grade mtgban.Condition) (int, bool) {
	switch store {
	case tcgDirectStore:
		return tcgDirectStock
	case tcgListingsStore:
		return tcgListingsCopies
	}
	return nil
}

// addV2Entries files every priced entry a store has for one card. Its
// Available is read from stock where that is not nil, once per grade since
// the stock covers every entry of it, and otherwise from the entry.
func addV2Entries[T mtgban.GenericEntry](b *mtgmatcher.Backend, out banprice.V2, entries []T, idMode, cardID, store string, finishFilter []string, withQty, graded, buying bool, stock func(string, mtgban.Condition) (int, bool)) {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return
	}
	id := getIDFromMode(b, idMode, co)
	if id == "" {
		return
	}
	if len(finishFilter) > 0 && applyCardFilter(b, "finish", finishFilter, co) {
		return
	}

	finish := v2Finish(co)
	var stocked mtgban.Condition
	for i := range entries {
		price := entries[i].Pricing()
		if price == 0 {
			continue
		}
		entry := banprice.Entry{Price: price}
		if graded && !co.Sealed {
			entry.Grade = string(entries[i].Condition())
		}
		if withQty {
			entry.Qty = entries[i].Qty()
		}
		inv, isInventory := any(entries[i]).(mtgban.InventoryEntry)
		if stock != nil && entries[i].Condition() != stocked {
			stocked = entries[i].Condition()
			entry.Available, _ = stock(cardID, stocked)
		} else if stock == nil && isInventory {
			entry.Available = inv.Available
		}
		out.Add(id, finish, store, entry, buying)
	}
}
