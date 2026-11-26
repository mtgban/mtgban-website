package main

import (
	"time"

	"github.com/mtgban/go-mtgban/matcher"

	"github.com/mtgban/mtgban-website/internal/offline"
)

// condMap flattens the closed-vocabulary conditions struct into the payload map.
func condMap(c *BanConditions) map[string]float64 {
	var out map[string]float64
	for _, tag := range conditionTags {
		if v := c.Get(tag); v != 0 {
			if out == nil {
				out = make(map[string]float64)
			}
			out[tag] = v
		}
	}
	return out
}

// qtyMap is the quantity counterpart of condMap.
func qtyMap(q *BanQuantities) map[string]int {
	var out map[string]int
	for _, tag := range conditionTags {
		if v := q.Get(tag); v != 0 {
			if out == nil {
				out = make(map[string]int)
			}
			out[tag] = v
		}
	}
	return out
}

// banprice2offline maps the BanPrice shape 1:1 onto the payload shape.
func banprice2offline(setCode string, snapshot time.Time, retail, buylist map[string]map[string]*BanPrice) *offline.SetPayload {
	conv := func(section map[string]map[string]*BanPrice) map[string]map[string]*offline.PriceEntry {
		out := make(map[string]map[string]*offline.PriceEntry, len(section))
		for uuid, byStore := range section {
			entries := make(map[string]*offline.PriceEntry, len(byStore))
			for store, bp := range byStore {
				entries[store] = &offline.PriceEntry{
					Regular:    bp.Regular,
					Foil:       bp.Foil,
					Etched:     bp.Etched,
					Sealed:     bp.Sealed,
					Cond:       bp.Cond,
					Qty:        bp.Qty,
					QtyFoil:    bp.QtyFoil,
					QtyEtched:  bp.QtyEtched,
					QtySealed:  bp.QtySealed,
					Conditions: condMap(bp.Conditions),
					Quantities: qtyMap(bp.Quantities),
				}
			}
			out[uuid] = entries
		}
		return out
	}
	return &offline.SetPayload{
		SetCode:  setCode,
		Snapshot: snapshot,
		Retail:   conv(retail),
		Buylist:  conv(buylist),
	}
}

// addSlabTags gives each graded store among sellers its slabs' own condition
// tags in a set's retail section: the tag the slab folds to, then "|" and the
// slab's name, so "NM|PSA 9". Only entries the payload already holds change.
// The base price, watermarked under Cond, may then differ by a cent from the
// slab tag it came from, which the page does not show beside it.
func addSlabTags(b *matcher.Backend, p *prices, setCode string, sellers []string, retail map[string]map[string]*offline.PriceEntry) {
	graded := onlyGraded(p, sellers, true)
	if len(graded) == 0 {
		return
	}
	config := apiSearchConfig(b, resolveEditionFilter(b, setCode, nil, false), graded, "", false)
	cardIDs := filterUUIDs(b, p, config.UUIDs, config.CardFilters)
	found := searchSellers(p, cardIDs, config)
	for cardID, buckets := range found {
		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}
		rewritten := map[string]bool{}
		for _, cond := range AllConditions {
			for _, row := range buckets[cond] {
				entry := retail[cardID][row.Shorthand]
				if entry == nil || row.Price == 0 {
					continue
				}
				if !rewritten[row.Shorthand] {
					rewritten[row.Shorthand] = true
					entry.Conditions, entry.Quantities = map[string]float64{}, nil
				}
				tag := string(cond) + finishSuffix(co)
				if row.Slab != nil {
					tag += "|" + slabName(row.Slab)
				}
				best, ok := entry.Conditions[tag]
				if !ok || row.Price < best {
					entry.Conditions[tag] = row.Price
				}
				if !row.NoQuantity && row.Quantity > 0 {
					if entry.Quantities == nil {
						entry.Quantities = map[string]int{}
					}
					entry.Quantities[tag] += row.Quantity
				}
			}
		}
	}
}
