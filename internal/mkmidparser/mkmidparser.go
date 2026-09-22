// Package mkmidparser resolves a Cardmarket product id to the card it
// names, for the upload's mcm_id column.
//
// It is the one direction the Cardmarket scrapers do not publish. Their
// inventories are keyed by uuid, with the product each entry priced
// carried alongside it, so uuid-to-product is a map lookup and
// product-to-uuid is not.
package mkmidparser

import (
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Parser answers the id-to-card question for a sellers snapshot.
//
// Sellers is how it reaches the current one. A function rather than a
// value, because the answer has to be about what is published now; passed
// in rather than reached for, because the snapshot belongs to whoever
// loaded it - the same reason docparse takes Resolve as a hook instead of
// importing what holds it.
type Parser struct {
	Sellers func() *[]mtgban.Seller
}

// shelfNames are the Cardmarket scrapers that publish the product they
// priced, which is what makes this direction possible at all.
var shelfNames = []string{"MKMTrend", "MKMLow", "MKMSealed"}

// inventoryOf finds one of those shelves in a snapshot.
func inventoryOf(sellers []mtgban.Seller, shorthand string) mtgban.InventoryRecord {
	for _, seller := range sellers {
		if strings.EqualFold(seller.Info().Shorthand, shorthand) {
			return seller.Inventory()
		}
	}
	return nil
}

// Resolve answers with the card a Cardmarket product id names, by walking the
// inventories the Cardmarket scrapers publish, where each entry carries the
// product it priced in OriginalID. Returns "" if the id is unknown.
//
// The walk is the lookup. findOriginalID goes the other way for free because
// an inventory is keyed by uuid; this direction has no such key, so the scan
// is the whole of it and it runs per uploaded row rather than off an index
// built at load time. That suits a column almost no upload carries.
//
// The sealed shelves are walked too. A seller's offers are not all singles,
// and a sealed product's id is published by the sealed scraper rather than
// the two singles indexes, so leaving it out would resolve every card on a
// mixed page and none of the boxes.
//
// One product is routinely several uuids, and which ones decides whether the
// id names a card. Cardmarket sells a printing's finishes as one product, so
// the foil and the plain entry answer to the same id and differ only by the
// suffix the datastore files a finish under: half of the 103,611 ids on the
// Magic shelves are shared that way, and the upload's own foil column says
// which finish is meant. Those agree, and the base uuid is the answer - the
// finish is re-resolved from the flag, not from which index was read first.
// Only a disagreement about the card itself - 1,525 ids, where the base uuids
// differ - names nothing, and returns "" so the row falls back to its name
// and edition.
func (p *Parser) Resolve(mkmID string) string {
	if mkmID == "" || p.Sellers == nil {
		return ""
	}
	snapshot := p.Sellers()
	if snapshot == nil {
		return ""
	}

	var found string
	for _, shorthand := range shelfNames {
		inv := inventoryOf(*snapshot, shorthand)
		if inv == nil {
			continue
		}
		for uuid, entries := range inv {
			base := baseUUID(uuid)
			if base == found {
				continue
			}
			for _, entry := range entries {
				if entry.OriginalID != mkmID {
					continue
				}
				if found != "" {
					return ""
				}
				found = base
				break
			}
		}
	}
	return found
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
