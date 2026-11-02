// Package tcgskuparser resolves a TCGplayer SKU to the card it names and the
// condition it encodes.
//
// The TCGplayer scrapers publish inventories keyed by uuid, one offer per
// condition, each carrying its SKU. An upload carrying a SKU column asks the
// other direction, so Build reads the two TCGplayer sellers the other way
// round, once, into an Index the upload resolves from.
//
// The Index is built wherever the sellers are published, beside the other
// indexes over them, so it always describes the sellers published with it:
// the site stores it on its prices snapshot beside the Cardmarket id map,
// and carries it across while the sellers Sellers picks are the ones it
// was built from.
package tcgskuparser

import (
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
)

// SKU is what an upload asks of a TCGplayer SKU: the card it names and
// the condition it encodes.
type SKU struct {
	UUID      string
	Condition mtgban.Condition
}

// Index is, for each SKU the TCGplayer singles and sealed sellers price,
// the card it names and the condition it encodes. A nil Index resolves
// nothing, which is what a snapshot with neither seller has.
type Index map[string]SKU

// sellerNames are the TCGplayer scrapers that carry a SKU on every offer,
// singles first; the sealed one is read too, since a box's SKU is
// published there and nowhere else.
var sellerNames = []string{"TCGPlayer", "TCGSealed"}

// Sellers picks the TCGplayer sellers out of a sellers snapshot, by
// shorthand, case-insensitively, singles before sealed, leaving out one
// that is not loaded. Two snapshots whose Sellers are equal share an Index.
func Sellers(sellers []mtgban.Seller) []mtgban.Seller {
	var picked []mtgban.Seller
	for _, name := range sellerNames {
		for _, seller := range sellers {
			if strings.EqualFold(seller.Info().Shorthand, name) {
				picked = append(picked, seller)
				break
			}
		}
	}
	return picked
}

// Build walks the TCGplayer sellers among sellers once and records, for
// each SKU they price, the card it names and the condition it encodes.
// First wins on a SKU priced twice, singles before sealed. Every other
// seller is left alone, and with no TCGplayer seller loaded there is no
// Index.
func Build(sellers []mtgban.Seller) Index {
	sources := Sellers(sellers)
	if len(sources) == 0 {
		return nil
	}
	size := 0
	for _, seller := range sources {
		for _, entries := range seller.Inventory() {
			size += len(entries)
		}
	}
	index := make(Index, size)
	for _, seller := range sources {
		for uuid, entries := range seller.Inventory() {
			for i := range entries {
				sku := entries[i].InstanceID
				if sku == "" {
					continue
				}
				if _, dup := index[sku]; dup {
					continue
				}
				index[sku] = SKU{UUID: uuid, Condition: entries[i].Conditions}
			}
		}
	}
	return index
}

// Resolve answers with the card a TCGplayer SKU names, or "" if the SKU is
// unknown.
func (idx Index) Resolve(sku string) string {
	return idx[sku].UUID
}

// Condition answers with the condition a TCGplayer SKU encodes, or "" if
// the SKU is unknown.
func (idx Index) Condition(sku string) mtgban.Condition {
	return idx[sku].Condition
}
