package main

import (
	"slices"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/banprice"
)

// The v2 price maps are built straight from the records, not from v1's, so
// a store's every grade is kept. They follow v1 in what they read: the
// same stores, filters and id modes, and filtered requests walk the search
// rows while full dumps scan the records.

// v2Finish is the finish a card's prices are filed under in v2.
func v2Finish(co *mtgmatcher.CardObject) string {
	if co.Sealed {
		return banprice.FinishSealed
	}
	return co.Finish
}

func getSellerPricesV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool, tagName string) banprice.V2 {
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(b, uuids, enabledStores, filterByFinish, sealed)
		cardIDs := filterUUIDs(b, config.UUIDs, config.CardFilters)
		return v2PricesFromRows(b, cardIDs, searchSellersNG(cardIDs, config), mode, tagName, false)
	}

	var finishFilter []string
	if filterByFinish != "" {
		finishFilter = fixupFinishNG(filterByFinish)
	}

	out := banprice.V2{}
	for _, seller := range GetSellers() {
		info := seller.Info()
		if info.SealedMode != sealed || !slices.Contains(enabledStores, info.Shorthand) {
			continue
		}

		inventory := seller.Inventory()
		withQty := !info.MetadataOnly && !info.NoQuantityInventory
		if info.Shorthand == tcgDirectStore {
			inventory = tcgDirectStockOnly(inventory)
			withQty = true
		}

		tag := info.Shorthand
		if tagName == "names" {
			tag = info.Name
		}
		for cardID, entries := range inventory {
			addV2Entries(b, out, entries, mode, cardID, tag, finishFilter, withQty, !info.MetadataOnly, false)
		}
	}
	return out
}

func getVendorPricesV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool, tagName string) banprice.V2 {
	if filterByEdition != "" || filterByHash != nil {
		uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
		config := apiSearchConfig(b, uuids, enabledStores, filterByFinish, sealed)
		cardIDs := filterUUIDs(b, config.UUIDs, config.CardFilters)
		return v2PricesFromRows(b, cardIDs, searchVendorsNG(cardIDs, config), mode, tagName, true)
	}

	var finishFilter []string
	if filterByFinish != "" {
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
		for cardID, entries := range buylist {
			addV2Entries(b, out, entries, mode, cardID, tag, finishFilter, withQty, !info.MetadataOnly, true)
		}
	}
	return out
}

// addV2Entries files every priced entry a store has for one card.
func addV2Entries[T mtgban.GenericEntry](b *mtgmatcher.Backend, out banprice.V2, entries []T, idMode, cardID, store string, finishFilter []string, withQty, graded, buying bool) {
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
		out.Add(id, finish, store, entry, buying)
	}
}

// v2PricesFromRows files the search walk's rows as addV2Entries files the
// records: INDEX rows are an index store's, and carry no grade.
func v2PricesFromRows(b *mtgmatcher.Backend, cardIDs []string, found map[string]map[mtgban.Condition][]SearchEntry, idMode, tagName string, vendorSide bool) banprice.V2 {
	names, metadata := apiStoreInfo(vendorSide)

	out := banprice.V2{}
	for _, cardID := range cardIDs {
		buckets := found[cardID]
		if len(buckets) == 0 {
			continue
		}
		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}
		id := getIDFromMode(b, idMode, co)
		if id == "" {
			continue
		}

		finish := v2Finish(co)
		for _, cond := range AllConditions {
			for _, row := range buckets[cond] {
				if row.Price == 0 {
					continue
				}
				entry := banprice.Entry{Price: row.Price}
				if cond != "INDEX" && !co.Sealed {
					entry.Grade = string(cond)
				}

				if vendorSide {
					if !metadata[row.Shorthand] || row.PriceUnit == PriceUnitCount {
						entry.Qty = row.Quantity
					}
				} else {
					quantity, noQuantity := row.Quantity, row.NoQuantity
					if row.Shorthand == tcgDirectStore {
						stock, found := tcgDirectStock(cardID, cond)
						if found {
							quantity, noQuantity = stock, false
						}
					}
					if !noQuantity {
						entry.Qty = quantity
					}
				}

				tag := row.Shorthand
				if tagName == "names" && names[row.Shorthand] != "" {
					tag = names[row.Shorthand]
				}
				out.Add(id, finish, tag, entry, vendorSide)
			}
		}
	}
	return out
}
