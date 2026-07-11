package main

import (
	"time"

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
