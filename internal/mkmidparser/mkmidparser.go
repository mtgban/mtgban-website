// Package mkmidparser resolves a Cardmarket product id to the card it names.
//
// The Cardmarket scrapers publish inventories keyed by uuid, with the
// product each entry priced carried alongside it. An upload carrying a
// Cardmarket id column asks the other direction, so Build reads the shelves
// the other way round, once, into an Index the upload resolves from.
//
// The Index is built wherever the sellers are published, beside the other
// indexes over them, so it always describes the shelves published with it:
// the site stores it on its prices snapshot the way the TCGplayer SKU index
// sits on the set analysis.
package mkmidparser

import (
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Index is, for each product id the Cardmarket shelves price, the card it
// names: the base uuid, or "" where the shelves file the id under two
// cards. A nil Index resolves nothing, which is what a game Cardmarket does
// not sell has.
type Index map[string]string

// shelfNames are the Cardmarket scrapers that publish the product they
// priced, which is what makes this direction possible at all.
//
// The sealed shelf is one of them. A seller's offers are not all singles,
// and a sealed product's id is published by the sealed scraper rather than
// the two singles indexes, so leaving it out would resolve every card on a
// mixed page and none of the boxes.
var shelfNames = []string{"MKMTrend", "MKMLow", "MKMSealed"}

// shelvesOf picks the Cardmarket shelves out of a sellers snapshot.
func shelvesOf(sellers []mtgban.Seller) []mtgban.Seller {
	var shelves []mtgban.Seller
	for _, seller := range sellers {
		if slices.ContainsFunc(shelfNames, func(shelf string) bool {
			return strings.EqualFold(seller.Info().Shorthand, shelf)
		}) {
			shelves = append(shelves, seller)
		}
	}
	return shelves
}

// Build walks the Cardmarket shelves among sellers once and records, for
// each product id they price, the card it names. Every other seller is
// left alone: only the shelves publish the product they priced.
//
// One product is routinely several uuids, and which ones decides whether
// the id names a card at all. Cardmarket sells a printing's finishes as one
// product, so the foil and the plain entry answer to the same id and differ
// only by the suffix the datastore files a finish under: half of the
// 103,611 ids on the Magic shelves are shared that way, and the upload's
// own foil column says which finish is meant. Those agree, and the base
// uuid is the answer - the finish is re-resolved from the flag, not from
// which shelf was read first. Only a disagreement about the card itself -
// 1,525 ids, where the base uuids differ - names nothing.
func Build(sellers []mtgban.Seller) Index {
	shelves := shelvesOf(sellers)
	if len(shelves) == 0 {
		return nil
	}

	ids := Index{}
	for _, seller := range shelves {
		for uuid, entries := range seller.Inventory() {
			base := baseUUID(uuid)
			for _, entry := range entries {
				if entry.OriginalID == "" {
					continue
				}
				found, seen := ids[entry.OriginalID]
				if !seen {
					ids[entry.OriginalID] = base
					continue
				}
				if found != base {
					// Names nothing, and stays that way: "" is not a base
					// uuid, so a later shelf agreeing with either of them
					// cannot talk it back round.
					ids[entry.OriginalID] = ""
				}
			}
		}
	}
	return ids
}

// Resolve answers with the card a Cardmarket product id names, or "" if
// the id is unknown, and "" as well if it names more than one card.
//
// An id the shelves do not price is unknown, and one they disagree about
// names more than one card, which is the same answer: the row falls back
// to its name and edition.
func (ids Index) Resolve(mkmID string) string {
	return ids[mkmID]
}

// baseUUID drops the suffix the datastore files a non-default finish under,
// so two finishes of one printing are recognised as the one card they are.
func baseUUID(uuid string) string {
	for _, suffix := range []string{"_f", "_e"} {
		if strings.HasSuffix(uuid, suffix) {
			return strings.TrimSuffix(uuid, suffix)
		}
	}
	return uuid
}
