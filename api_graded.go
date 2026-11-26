package main

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/banprice"
)

// The graded endpoints: v2's prices of slabs, which every other price
// endpoint leaves out, listed under the grades the Graded page lists them
// under. They are v2's alone, since v1's conditions are a fixed set.

// gradedStores is the shorthand of every loaded seller of slabs.
func gradedStores(p *prices) []string {
	return p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return info.GradedMode
	})
}

// onlyGraded keeps the stores that sell slabs, or the ones that do not.
func onlyGraded(p *prices, stores []string, graded bool) []string {
	slabs := gradedStores(p)
	return slices.DeleteFunc(slices.Clone(stores), func(shorthand string) bool {
		return slices.Contains(slabs, shorthand) != graded
	})
}

// compareSlabs orders slabs as the Graded page does.
func compareSlabs(a, b banprice.Entry) int {
	grader := func(e banprice.Entry) int {
		if e.Grader == "" {
			return len(slabGraders)
		}
		return slices.Index(slabGraders, e.Grader)
	}
	return cmp.Or(
		cmp.Compare(grader(a), grader(b)),
		cmp.Compare(b.Score, a.Score),
		cmp.Compare(slabLabelRank(a.Label), slabLabelRank(b.Label)),
		strings.Compare(a.Label, b.Label),
	)
}

// mergeSlab files e into a store's slabs. One of the same grade and label
// already there keeps the lower price and the sums of their Qty and
// Available.
func mergeSlab(entries []banprice.Entry, e banprice.Entry) []banprice.Entry {
	i, found := slices.BinarySearchFunc(entries, e, compareSlabs)
	if !found {
		return slices.Insert(entries, i, e)
	}
	entries[i].Price = min(entries[i].Price, e.Price)
	entries[i].Qty += e.Qty
	entries[i].Available += e.Available
	return entries
}

// newGradedStore reads a slab seller's record, one entry per grade and label.
func newGradedStore(info mtgban.ScraperInfo, record map[string][]mtgban.InventoryEntry) v2Store {
	return v2Store{
		name: info.Shorthand,
		cards: func(yield func(string) bool) {
			for cardID := range record {
				if !yield(cardID) {
					return
				}
			}
		},
		file: func(list []banprice.Entry, cardID string, co *matcher.CardObject) []banprice.Entry {
			for _, listed := range record[cardID] {
				price := math.Round(listed.Price*100) / 100
				if unpriced(price) {
					continue
				}
				group, _ := slabGroup(listed.Slab)
				entry := banprice.Entry{Condition: string(group), Price: price, Available: listed.Available}
				if listed.Slab != nil {
					entry.Grader, entry.Score, entry.Label = listed.Slab.Grader, listed.Slab.Score, listed.Slab.Label
				}
				if !info.NoQuantityInventory {
					entry.Qty = listed.Quantity
				}
				list = mergeSlab(list, entry)
			}
			return list
		},
	}
}

// gradedSectionV2 is the retail section of a graded request.
func gradedSectionV2(b *matcher.Backend, p *prices, mode, lang string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string) *v2Section {
	sellers := p.sellers
	section := newV2Section(b, p, mode, lang, filterByEdition, filterByHash, filterByFinish, false, sellers)
	for _, seller := range sellers {
		info := seller.Info()
		if info.GradedMode && slices.Contains(enabledStores, info.Shorthand) {
			section.stores = append(section.stores, newGradedStore(info, seller.Inventory()))
		}
	}
	return section
}

// gradedSearchV2 is the retail section of a graded search.
func gradedSearchV2(b *matcher.Backend, p *prices, mode, lang string, cardIDs []string, config SearchConfig) *v2Section {
	sellers := p.sellers
	section := searchSectionV2(b, p, mode, lang, cardIDs, false, sellers)
	for _, seller := range sellers {
		info := seller.Info()
		if !info.GradedMode || shouldSkipStoreNG(seller, config.StoreFilters) {
			continue
		}
		inventory := seller.Inventory()
		found := map[string][]mtgban.InventoryEntry{}
		for _, cardID := range section.cardIDs {
			for _, entry := range inventory[cardID] {
				if sellerEntryFound(p, info, cardID, entry, &config) {
					found[cardID] = append(found[cardID], entry)
				}
			}
		}
		if len(found) > 0 {
			section.stores = append(section.stores, newGradedStore(info, found))
		}
	}
	return section
}
