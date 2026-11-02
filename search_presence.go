package main

import (
	"cmp"
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

// postSeller is a seller the post filters ask about a card.
type postSeller struct {
	info      mtgban.ScraperInfo
	inventory mtgban.InventoryRecord
}

// postVendor is a vendor the post filters ask about a card.
type postVendor struct {
	info    mtgban.ScraperInfo
	buylist mtgban.BuylistRecord
}

// postStores holds the stores a search reads, as the post filters ask them
// about the cards found: each side by lower-case shorthand, as the any
// filter names them, and the stores that can offer biggest first, for the
// empty filter. Each store is asked only about the cards no store before it
// answered, so the post filters judge every card a search found without
// building the offers, which are built for the page shown.
type postStores struct {
	config          SearchConfig
	sellers         map[string]*postSeller
	vendors         map[string]*postVendor
	offeringSellers []*postSeller
	offeringVendors []*postVendor
	// custom holds the conditions the custom buylist prices each card at
	custom map[string][]mtgban.Condition
}

// newPostStores reads the stores the search's store filters keep, and the
// custom buylist's offers for cardIDs when a filter asks about them.
func newPostStores(b *matcher.Backend, r *http.Request, cardIDs []string, config SearchConfig) *postStores {
	s := &postStores{
		config:  config,
		sellers: map[string]*postSeller{},
		vendors: map[string]*postVendor{},
	}

	if !config.SkipRetail {
		for _, seller := range GetSellers() {
			if shouldSkipStoreNG(seller, config.StoreFilters) {
				continue
			}
			store := &postSeller{info: seller.Info(), inventory: seller.Inventory()}
			s.sellers[strings.ToLower(store.info.Shorthand)] = store
			// An index lists everything under INDEX, which is no offer
			if !store.info.MetadataOnly {
				s.offeringSellers = append(s.offeringSellers, store)
			}
		}
	}
	if !config.SkipBuylist {
		for _, vendor := range GetVendors() {
			if shouldSkipStoreNG(vendor, config.StoreFilters) {
				continue
			}
			store := &postVendor{info: vendor.Info(), buylist: vendor.Buylist()}
			s.vendors[strings.ToLower(store.info.Shorthand)] = store
			// A sealed index keeps its conditions
			if !store.info.MetadataOnly || store.info.SealedMode {
				s.offeringVendors = append(s.offeringVendors, store)
			}
		}
	}
	slices.SortFunc(s.offeringSellers, func(a, b *postSeller) int {
		return cmp.Compare(len(b.inventory), len(a.inventory))
	})
	slices.SortFunc(s.offeringVendors, func(a, b *postVendor) int {
		return cmp.Compare(len(b.buylist), len(a.buylist))
	})

	if config.CustomBuylist && !config.SkipBuylist && asksCustom(config.PostFilters) {
		s.custom = map[string][]mtgban.Condition{}
		for _, offer := range customBuylistOffers(b, r, cardIDs) {
			s.custom[offer.cardID] = append(s.custom[offer.cardID], offer.condition)
		}
	}

	return s
}

// asksCustom reports whether a filter reading the vendor side asks about the
// custom buylist: an empty filter does, and an any filter naming it.
func asksCustom(filters []FilterPostElem) bool {
	for _, filter := range filters {
		if filter.OnlyForSeller {
			continue
		}
		if filter.Name == "empty" || slices.Contains(filter.Values, "custom") {
			return true
		}
	}
	return false
}

// offersUnder reports whether an entry listed under cond counts as an offer
// for the empty filter: an INDEX quote does not.
func offersUnder(cond mtgban.Condition) bool {
	return cond != "INDEX"
}

// listsUnder reports whether an entry listed under cond counts for the any
// filter, which reads the known conditions alone.
func listsUnder(cond mtgban.Condition) bool {
	return slices.Contains(AllConditions, cond)
}

// withoutSellerOffers returns the cards in pending no seller offers under a
// condition other than INDEX, judged as searchSellersNG judges an entry. The
// biggest inventories go first, and each seller is asked only about the
// cards the ones before it did not offer. pending is reused.
func (s *postStores) withoutSellerOffers(pending []string) []string {
	for _, store := range s.offeringSellers {
		if len(pending) == 0 {
			break
		}
		pending = slices.DeleteFunc(pending, func(cardID string) bool {
			return store.offers(cardID, &s.config)
		})
	}
	return pending
}

// withoutVendorOffers is withoutSellerOffers for the vendors and the custom
// buylist.
func (s *postStores) withoutVendorOffers(pending []string) []string {
	for _, store := range s.offeringVendors {
		if len(pending) == 0 {
			break
		}
		pending = slices.DeleteFunc(pending, func(cardID string) bool {
			return store.offers(cardID, &s.config)
		})
	}
	if s.custom != nil {
		pending = slices.DeleteFunc(pending, func(cardID string) bool {
			return slices.ContainsFunc(s.custom[cardID], offersUnder)
		})
	}
	return pending
}

// withoutSellerListings returns the cards in pending none of the named
// sellers lists under a known condition, each seller asked only about the
// cards the ones before it did not list. pending is reused.
func (s *postStores) withoutSellerListings(pending []string, names []string) []string {
	for _, name := range names {
		store, found := s.sellers[name]
		if !found || len(pending) == 0 {
			continue
		}
		pending = slices.DeleteFunc(pending, func(cardID string) bool {
			return store.lists(cardID, &s.config)
		})
	}
	return pending
}

// withoutVendorListings is withoutSellerListings for the vendors, the custom
// buylist named as custom.
func (s *postStores) withoutVendorListings(pending []string, names []string) []string {
	for _, name := range names {
		store, found := s.vendors[name]
		if found && len(pending) > 0 {
			pending = slices.DeleteFunc(pending, func(cardID string) bool {
				return store.lists(cardID, &s.config)
			})
		}
		if name == "custom" && s.custom != nil {
			pending = slices.DeleteFunc(pending, func(cardID string) bool {
				return slices.ContainsFunc(s.custom[cardID], listsUnder)
			})
		}
	}
	return pending
}

// offers reports whether the seller offers the card under a condition other
// than INDEX.
func (store *postSeller) offers(cardID string, config *SearchConfig) bool {
	for _, entry := range store.inventory[cardID] {
		if sellerEntryFound(store.info, cardID, entry, *config) && offersUnder(sellerOfferCondition(store.info, entry)) {
			return true
		}
	}
	return false
}

// lists reports whether the seller lists the card under a known condition.
func (store *postSeller) lists(cardID string, config *SearchConfig) bool {
	for _, entry := range store.inventory[cardID] {
		if sellerEntryFound(store.info, cardID, entry, *config) && listsUnder(sellerOfferCondition(store.info, entry)) {
			return true
		}
	}
	return false
}

// offers reports whether the vendor buys the card under a condition other
// than INDEX.
func (store *postVendor) offers(cardID string, config *SearchConfig) bool {
	for _, entry := range store.buylist[cardID] {
		if vendorEntryFound(store.info, cardID, entry, *config) && offersUnder(vendorOfferCondition(store.info, entry)) {
			return true
		}
	}
	return false
}

// lists reports whether the vendor buys the card under a known condition.
func (store *postVendor) lists(cardID string, config *SearchConfig) bool {
	for _, entry := range store.buylist[cardID] {
		if vendorEntryFound(store.info, cardID, entry, *config) && listsUnder(vendorOfferCondition(store.info, entry)) {
			return true
		}
	}
	return false
}
