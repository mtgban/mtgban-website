// Package mkmidparser resolves a Cardmarket product id to the card it names,
// and a card to the Cardmarket product it is priced under.
//
// The Cardmarket scrapers publish inventories keyed by uuid, with the
// product each entry priced carried alongside it. Nothing had ever needed
// the other direction, so the upload used to walk all three shelves per
// row looking for one id - which suited a column almost no upload carried,
// and stopped suiting it when the cm-banner extension began writing that
// column on every row.
//
// This is that walk, done once and kept, for as long as the shelves it was
// built from are the ones still published. The same walk reads the shelves
// the way they were written as well, for the price API's Cardmarket ids:
// the datastore carries a Cardmarket id for only a fraction of most games'
// cards, while the shelves name the product for every card they price.
package mkmidparser

import (
	"strings"
	"sync/atomic"
	"weak"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Parser answers the id-to-card question, holding the index it answers
// from.
//
// Sellers is how it reaches the current snapshot. It is a function rather
// than a value because the answer has to be about what is published now,
// and rather than a global because the snapshot belongs to whoever loaded
// it - the same reason docparse takes this package's Resolve as a hook
// instead of importing it.
type Parser struct {
	Sellers func() *[]mtgban.Seller

	cached atomic.Pointer[built]
}

// shelfNames are the Cardmarket scrapers that publish the product they
// priced, which is what makes this direction possible at all.
//
// The sealed shelf is one of them. A seller's offers are not all singles,
// and a sealed product's id is published by the sealed scraper rather than
// the two singles indexes, so leaving it out would resolve every card on a
// mixed page and none of the boxes.
var shelfNames = []string{"MKMTrend", "MKMLow", "MKMSealed"}

// built is the reverse of what those shelves publish - their entries
// carry the product they priced, and this is that read the other way round.
//
// It carries the sellers snapshot it was built from, because that is what
// says whether it is still true. The inventories are replaced by
// updateSellers, which does not touch the datastore stamp, so an index
// keyed on that would go on describing the previous snapshot after a
// scrapers-only refresh - and would say so silently, by resolving ids to
// cards that had moved.
type built struct {
	// The snapshot this was last matched against, which is the cheap
	// question: if the sellers have not been republished at all, nothing
	// this describes can have changed. Held weakly, or every seller in it
	// would stay alive after a refresh replaced them.
	builtFrom weak.Pointer[[]mtgban.Seller]

	// The Cardmarket shelves it was actually built from. Every other
	// seller's refresh republishes the snapshot with these copied across
	// untouched, and rebuilding for one of those is a walk spent arriving
	// at the same map. Held weakly too, or a refresh of the shelves
	// themselves would keep the replaced ones alive until the next upload.
	shelves []weak.Pointer[mtgban.BaseSeller]

	index
}

// index is what one walk of the shelves learns, read in both directions.
type index struct {
	// Product id to the base uuid it names, "" when it names several.
	ids map[string]string

	// Uuid to the product id the shelves price it under.
	products map[string]string
}

// shelvesOf picks the Cardmarket shelves out of a sellers snapshot, in
// shelfNames order, so which shelf answers first does not depend on the
// order the snapshot happens to list them in.
func shelvesOf(sellers []mtgban.Seller) []mtgban.Seller {
	var shelves []mtgban.Seller
	for _, name := range shelfNames {
		for _, seller := range sellers {
			if strings.EqualFold(seller.Info().Shorthand, name) {
				shelves = append(shelves, seller)
			}
		}
	}
	return shelves
}

// weakShelves points at shelves without keeping them alive.
//
// Every loaded scraper is a *mtgban.BaseSeller, as ReadSellerFromJSON
// builds them. Anything else gets a pointer to nothing, which sameShelves
// reports as changed: that costs a rebuild and never a wrong answer.
func weakShelves(shelves []mtgban.Seller) []weak.Pointer[mtgban.BaseSeller] {
	held := make([]weak.Pointer[mtgban.BaseSeller], len(shelves))
	for i, shelf := range shelves {
		base, ok := shelf.(*mtgban.BaseSeller)
		if ok {
			held[i] = weak.Make(base)
		}
	}
	return held
}

// sameShelves reports whether now holds the very sellers was points at.
//
// By identity. A shelf that has been replaced and collected since reads
// as nil, so it can never be mistaken for whatever took its place.
func sameShelves(was []weak.Pointer[mtgban.BaseSeller], now []mtgban.Seller) bool {
	if len(was) != len(now) || len(was) == 0 {
		return false
	}
	for i := range was {
		shelf, ok := now[i].(*mtgban.BaseSeller)
		if !ok || shelf == nil || was[i].Value() != shelf {
			return false
		}
	}
	return true
}

// publish installs an index, unless the inventories it describes have
// already been replaced.
//
// A walk takes milliseconds, which is long enough for a scrapers refresh
// to land in the middle of one. Without this check a build that started
// on the older snapshot would install itself on top of a newer one
// already published, and the cache would be keyed to inventories that are
// no longer live.
//
// Nothing would be resolved wrongly from it - ids compares the key
// against the current snapshot on every read, so a superseded index is
// never served - but the next reader would pay for a rebuild that need
// not have happened, and a cache describing replaced inventories is close
// enough to the thing this whole package exists to avoid that it is worth
// not leaving lying around.
//
// The check narrows the window rather than closing it: the snapshot can
// still move between the load here and the store below. What makes that
// harmless is the same key check on the read, not this.
func (p *Parser) publish(snapshot *[]mtgban.Seller, idx index) {
	if p.Sellers() != snapshot {
		return
	}
	// The shelves are read off the snapshot rather than handed in beside
	// it. They are a fact about it, and a second argument is a second
	// chance to pass one that describes something else.
	p.cached.Store(&built{
		builtFrom: weak.Make(snapshot),
		shelves:   weakShelves(shelvesOf(*snapshot)),
		index:     idx,
	})
}

// current answers with the index for the sellers currently published,
// building it if what is cached was built from an older snapshot.
//
// Nothing here is ordered against anything else, and it does not need to
// be: what makes an answer correct is that its key matches the snapshot
// being asked about, and that is checked on every read. Two uploads
// arriving together on the same snapshot may both build one, and either
// may be the one that lands - they were built from the same inventories,
// so the duplicate work is all it costs.
//
// The alternative was a lock held across the build, which buys a walk
// saved and every other upload waiting behind it.
func (p *Parser) current() index {
	if p.Sellers == nil {
		return index{}
	}
	snapshot := p.Sellers()
	if snapshot == nil {
		return index{}
	}

	cached := p.cached.Load()
	if cached != nil && cached.builtFrom.Value() == snapshot {
		return cached.index
	}

	// The snapshot moved. Whether that matters is a different question:
	// sellers are republished whole, so a refresh of any one of them - a
	// buylist, a storefront nothing here reads - hands out a new slice
	// with the Cardmarket shelves unchanged inside it.
	shelves := shelvesOf(*snapshot)
	if cached != nil && sameShelves(cached.shelves, shelves) {
		// Re-keyed to the snapshot in hand so the rows after this one ask
		// the cheap question again instead of this one.
		p.publish(snapshot, cached.index)
		return cached.index
	}

	// Built from the shelves that were loaded, not from whatever the
	// source answers by the time the walk reaches them: the key has to
	// name what the index actually describes.
	idx := build(shelves)
	p.publish(snapshot, idx)

	// Answered from what was asked about, whether or not it was published.
	// A caller that started under an older snapshot finishes under it,
	// which is steadier than changing its mind about the inventories half
	// way down a list.
	return idx
}

// build walks the Cardmarket shelves once and records, for each
// product id they price, the card it names.
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
//
// The other direction needs no such care: each index prices a uuid from
// one product, so a uuid has one product per shelf, and the first shelf in
// shelfNames order to price it is the answer.
func build(shelves []mtgban.Seller) index {
	ids := map[string]string{}
	products := map[string]string{}

	for _, seller := range shelves {

		for uuid, entries := range seller.Inventory() {
			base := baseUUID(uuid)
			for _, entry := range entries {
				if entry.OriginalID == "" {
					continue
				}
				if _, seen := products[uuid]; !seen {
					products[uuid] = entry.OriginalID
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

	return index{ids: ids, products: products}
}

// Resolve answers with the card a Cardmarket product id names, or "" if
// the id is unknown, and "" as well if it names more than one card.
//
// An id the shelves do not price is unknown, and one they disagree about
// names more than one card, which is the same answer: the row falls back
// to its name and edition.
func (p *Parser) Resolve(mkmID string) string {
	if mkmID == "" {
		return ""
	}
	return p.current().ids[mkmID]
}

// ProductID answers with the Cardmarket product a card is priced under, or
// "" if there is none to give.
//
// The shelves are the authority: they are what the site prices from, and
// they name a product for every card they price. own is the id the
// datastore files the card under, which is complete for Magic and sparse
// for most other games, and it answers for a card the shelves do not
// price, or price under a product they also price another card under.
//
// Whatever answers has to name this card and no other, or the card's
// prices would merge into another card's under the one id: a product the
// shelves price onto several printings names none of them, from the
// shelves or from the datastore.
//
// A finish the shelves do not price on its own, a foil with no foil
// trend, is sold as its printing's product, so that answers last.
func (p *Parser) ProductID(uuid, own string) string {
	idx := p.current()
	base := baseUUID(uuid)

	namesThisCard := func(id string) bool {
		if id == "" {
			return false
		}
		named, priced := idx.ids[id]
		return !priced || named == base
	}

	for _, id := range []string{idx.products[uuid], own, idx.products[base]} {
		if namesThisCard(id) {
			return id
		}
	}
	return ""
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
