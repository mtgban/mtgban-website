// Package csiidparser resolves a Cool Stuff Inc product id to the card it
// names.
//
// The id in a coolstuffinc.com/p/<pid> link is the storefront's own, not a
// TCGplayer or scryfall one, and mtgmatcher indexes no such id space - so
// nothing can look it up. What can answer is the inventory already loaded:
// the scrapers stamp the product each entry priced alongside it, and this
// is that read the other way round.
//
// Built the same way as mkmidparser, for the same reason: the answer has to
// be about the shelves published now, and the walk is worth doing once.
package csiidparser

import (
	"reflect"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Parser answers the id-to-card question, holding the index it answers from.
//
// Sellers is how it reaches the current snapshot - a function rather than a
// value because the answer has to be about what is published now, and rather
// than a global because the snapshot belongs to whoever loaded it.
type Parser struct {
	Sellers func() *[]mtgban.Seller

	cached atomic.Pointer[built]
}

// shelfNames are the Cool Stuff Inc scrapers.
//
// The singles scraper is a market and reaches the snapshot split in two,
// under the shorthands its sub-sellers carry rather than the "CSI" the
// scraper itself reports. The sealed shelf is read too: a link to a booster
// box is a link like any other, and no singles index prices one.
var shelfNames = []string{"CSI", "CSIUnique", "CSISealed"}

// built is the reverse of what those shelves publish.
//
// It carries the sellers snapshot it was built from, because that is what
// says whether it is still true. The inventories are replaced by
// updateSellers, which does not touch the datastore stamp, so an index keyed
// on that would go on describing the previous snapshot after a scrapers-only
// refresh - and would say so silently, by resolving ids to cards that had
// moved.
type built struct {
	// The snapshot this was last matched against, which is the cheap
	// question: if the sellers have not been republished at all, nothing
	// this describes can have changed.
	builtFrom *[]mtgban.Seller

	// The Cool Stuff Inc shelves it was actually built from. Every other
	// seller's refresh republishes the snapshot with these copied across
	// untouched, and rebuilding for one of those is a walk spent arriving
	// at the same map.
	shelves []mtgban.Seller

	ids map[string]string
}

// shelvesOf picks the Cool Stuff Inc shelves out of a sellers snapshot.
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

// sameShelves reports whether two lists hold the same sellers.
//
// By identity, and by reflection rather than ==, because a seller is an
// interface: comparing two of them panics if what is inside is a struct
// holding a map, and an inventory is a map. Anything that is not a pointer
// is reported as changed, which costs a rebuild and never a wrong answer.
func sameShelves(was, now []mtgban.Seller) bool {
	if len(was) != len(now) || len(was) == 0 {
		return false
	}
	for i := range was {
		a, b := reflect.ValueOf(was[i]), reflect.ValueOf(now[i])
		if a.Kind() != reflect.Pointer || b.Kind() != reflect.Pointer {
			return false
		}
		if a.Pointer() != b.Pointer() {
			return false
		}
	}
	return true
}

// publish installs an index, unless the inventories it describes have already
// been replaced.
//
// The check narrows the window rather than closing it: the snapshot can still
// move between the load here and the store below. What makes that harmless is
// the same key check on the read, not this.
func (p *Parser) publish(snapshot *[]mtgban.Seller, ids map[string]string) {
	if p.Sellers() != snapshot {
		return
	}
	// The shelves are read off the snapshot rather than handed in beside it.
	// They are a fact about it, and a second argument is a second chance to
	// pass one that describes something else.
	p.cached.Store(&built{
		builtFrom: snapshot,
		shelves:   shelvesOf(*snapshot),
		ids:       ids,
	})
}

// ids answers with the index for the sellers currently published, building it
// if what is cached was built from an older snapshot.
//
// Nothing here is ordered against anything else, and it does not need to be:
// what makes an answer correct is that its key matches the snapshot being
// asked about, and that is checked on every read. Two readers arriving
// together on the same snapshot may both build one, and either may be the one
// that lands - they were built from the same inventories, so the duplicate
// work is all it costs.
func (p *Parser) ids() map[string]string {
	if p.Sellers == nil {
		return nil
	}
	snapshot := p.Sellers()
	if snapshot == nil {
		return nil
	}

	cached := p.cached.Load()
	if cached != nil && cached.builtFrom == snapshot {
		return cached.ids
	}

	// The snapshot moved. Whether that matters is a different question:
	// sellers are republished whole, so a refresh of any one of them hands
	// out a new slice with these shelves unchanged inside it.
	shelves := shelvesOf(*snapshot)
	if cached != nil && sameShelves(cached.shelves, shelves) {
		// Re-keyed to the snapshot in hand so the next read asks the cheap
		// question again instead of this one.
		p.publish(snapshot, cached.ids)
		return cached.ids
	}

	// Built from the shelves that were loaded, not from whatever the source
	// answers by the time the walk reaches them: the key has to name what the
	// index actually describes.
	ids := build(shelves)
	p.publish(snapshot, ids)

	// Answered from what was asked about, whether or not it was published.
	return ids
}

// build walks the Cool Stuff Inc shelves once and records, for each product
// id they price, the card it names.
//
// A product is the storefront's page, and a page carries an offer row per
// condition and per finish - the scraper reads the finish off the row and the
// id off the page, so a printing's plain and foil entries answer to the one
// id. They are the same card, which is what a link's title is asking about,
// so the finish suffix is dropped and they agree. Only a disagreement about
// the card itself names nothing.
func build(shelves []mtgban.Seller) map[string]string {
	ids := map[string]string{}

	for _, seller := range shelves {
		for uuid, entries := range seller.Inventory() {
			base := baseUUID(uuid)
			for _, entry := range entries {
				pid := productID(entry)
				if pid == "" {
					continue
				}
				found, seen := ids[pid]
				if !seen {
					ids[pid] = base
					continue
				}
				if found != base {
					// Names nothing, and stays that way: "" is not a base
					// uuid, so a later shelf agreeing with either of them
					// cannot talk it back round.
					ids[pid] = ""
				}
			}
		}
	}

	return ids
}

// productID answers with the storefront id an entry was priced under.
//
// OriginalID is where the scrapers put it, but not all of them do: the sealed
// shelf's Magic path builds its entries from a listing page and stamps only
// the link. That is the path Magic actually loads, and Magic is the only game
// the bot reads links for, so the link is read too rather than left to a
// field that happens to be empty exactly where it is needed.
func productID(entry mtgban.InventoryEntry) string {
	if entry.OriginalID != "" {
		return entry.OriginalID
	}
	return productIDFromURL(entry.URL)
}

// productIDFromURL picks the id out of a coolstuffinc.com/p/<pid> address.
//
// The scrapers write the host both with and without the www and may append an
// affiliate tag, but the id is always the one segment after /p/, so the cut is
// made there rather than by parsing an address already known to be one.
func productIDFromURL(link string) string {
	_, after, found := strings.Cut(link, "/p/")
	if !found {
		return ""
	}
	end := strings.IndexAny(after, "?/#")
	if end >= 0 {
		after = after[:end]
	}
	return after
}

// Resolve answers with the card a Cool Stuff Inc product id names, or "" if
// the id is unknown, and "" as well if it names more than one card.
func (p *Parser) Resolve(csiID string) string {
	if csiID == "" {
		return ""
	}
	return p.ids()[csiID]
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
