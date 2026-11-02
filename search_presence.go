package main

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

// offerPresence is what the post filters read of a card's offers on one side
// of the market: whether any is listed under a condition other than INDEX,
// and which stores list one, by lower-case shorthand. It is gathered without
// building the offers, so the post filters judge every card a search found
// while the offers are built for the page shown.
type offerPresence struct {
	offer  bool
	stores map[string]struct{}
}

// offerPresences is each card's presence by id; a card nothing offers on the
// side has no entry.
type offerPresences map[string]*offerPresence

// add records an offer for cardID that shorthand lists under cond.
func (p offerPresences) add(cardID string, cond mtgban.Condition, shorthand string) {
	pr := p[cardID]
	if pr == nil {
		pr = &offerPresence{}
		p[cardID] = pr
	}
	if cond != "INDEX" {
		pr.offer = true
	}
	// The any filter reads the known conditions alone
	if slices.Contains(AllConditions, cond) {
		if pr.stores == nil {
			pr.stores = map[string]struct{}{}
		}
		pr.stores[strings.ToLower(shorthand)] = struct{}{}
	}
}

// searchOfferPresence walks the stores a search reads, as searchParallelNG
// does, and records of each card only what the post filters ask: the same
// store, condition and price filters judge each entry, and nothing is built
// for one that passes. The custom buylist counts on the vendor side when the
// reader has one.
func searchOfferPresence(b *matcher.Backend, r *http.Request, cardIDs []string, config SearchConfig) (sellers, vendors offerPresences) {
	sellers = offerPresences{}
	vendors = offerPresences{}

	cardIDs = dedupeKeys(cardIDs)

	// Each walk recovers its own panic, which then costs only its side: the
	// presence it would have filled stays empty.
	var wg sync.WaitGroup
	wg.Go(func() {
		defer recoverJob("search sellers presence")
		if !config.SkipRetail {
			sellerPresence(cardIDs, config, sellers)
		}
	})
	wg.Go(func() {
		defer recoverJob("search vendors presence")
		if config.SkipBuylist {
			return
		}
		vendorPresence(cardIDs, config, vendors)
		if config.CustomBuylist {
			for _, offer := range customBuylistOffers(b, r, cardIDs) {
				vendors.add(offer.cardID, offer.condition, "CUSTOM")
			}
		}
	})
	wg.Wait()

	return sellers, vendors
}

// sellerPresence records which sellers offer each card, judged as
// searchSellersNG judges an entry.
func sellerPresence(cardIDs []string, config SearchConfig, presence offerPresences) {
	for _, seller := range GetSellers() {
		if shouldSkipStoreNG(seller, config.StoreFilters) {
			continue
		}

		inventory := seller.Inventory()
		info := seller.Info()

		for _, cardID := range cardIDs {
			for _, entry := range inventory[cardID] {
				if sellerEntryFound(info, cardID, entry, config) {
					presence.add(cardID, sellerOfferCondition(info, entry), info.Shorthand)
				}
			}
		}
	}
}

// vendorPresence records which vendors offer each card, judged as
// searchVendorsNG judges an entry.
func vendorPresence(cardIDs []string, config SearchConfig, presence offerPresences) {
	for _, vendor := range GetVendors() {
		if shouldSkipStoreNG(vendor, config.StoreFilters) {
			continue
		}

		buylist := vendor.Buylist()
		info := vendor.Info()

		for _, cardID := range cardIDs {
			for _, entry := range buylist[cardID] {
				if vendorEntryFound(info, cardID, entry, config) {
					presence.add(cardID, vendorOfferCondition(info, entry), info.Shorthand)
				}
			}
		}
	}
}
