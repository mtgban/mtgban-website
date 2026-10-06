package main

import (
	"encoding/csv"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/banprice"
)

// The v2 price maps are built straight from the stores' records, not from
// v1's, so every condition a store prices is kept. They follow v1 in what they read:
// the same stores, filters and id modes.

// v2Finish is the finish a card's prices are filed under in v2.
func v2Finish(co *mtgmatcher.CardObject) string {
	if co.Sealed {
		return banprice.FinishSealed
	}
	return co.Finish
}

// v2IDModes are the id systems v2 keys cards by. v1 reads any other value
// as the default, mtgban; v2 refuses it, so a misspelt one is not mistaken
// for a request for MTGBAN ids.
var v2IDModes = []string{"mtgban", "tcg", "scryfall", "mtgjson", "mkm", "ck", "name"}

// v2CardmarketShelves are the Cardmarket shelves v2 reads a card's product
// off, in the order they answer. Low and Trend name the same product for a
// card they both price, and Low prices a few more.
func v2CardmarketShelves(sealed bool) []string {
	if sealed {
		return []string{"MKMSealed"}
	}
	return []string{"MKMLow", "MKMTrend"}
}

// v2Keyer is how a request keys its cards: by mode, as v1 does, but for
// Cardmarket by the product the shelves price a card under, where they price
// it, since the datastore's Cardmarket ids are incomplete. The shelves come
// from the one sellers snapshot handed in, so one response keys every card
// from the same shelves.
func v2Keyer(b *mtgmatcher.Backend, mode string, sealed bool, sellers []mtgban.Seller) func(*mtgmatcher.CardObject) string {
	if mode != "mkm" {
		return func(co *mtgmatcher.CardObject) string { return getIDFromMode(b, mode, co) }
	}
	var shelves []mtgban.InventoryRecord
	for _, name := range v2CardmarketShelves(sealed) {
		for _, seller := range sellers {
			if strings.EqualFold(seller.Info().Shorthand, name) {
				shelves = append(shelves, seller.Inventory())
			}
		}
	}
	return func(co *mtgmatcher.CardObject) string {
		for _, shelf := range shelves {
			entries := shelf[co.UUID]
			if len(entries) > 0 && entries[0].OriginalID != "" {
				return entries[0].OriginalID
			}
		}
		return getIDFromMode(b, mode, co)
	}
}

// v2Cards is the cards a filtered request asks for, kept to its finish and
// to singles or sealed, and whether the request is filtered at all.
func v2Cards(b *mtgmatcher.Backend, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool) ([]string, bool) {
	if filterByEdition == "" && filterByHash == nil {
		return nil, false
	}
	uuids := resolveEditionFilter(b, filterByEdition, filterByHash, sealed)
	config := apiSearchConfig(b, uuids, nil, filterByFinish, sealed)
	return filterUUIDs(b, config.UUIDs, config.CardFilters), true
}

// v2Section is one price section of a v2 response, retail or buylist: the
// stores it reads and the cards it covers, walked card by card as the
// response is written rather than gathered first.
type v2Section struct {
	stores []v2Store
	keyOf  func(*mtgmatcher.CardObject) string
	// The cards a filtered request asks for; a full dump walks every card
	// a store prices.
	cardIDs  []string
	filtered bool
	// A full dump's finish filter, which a filtered request has applied to
	// cardIDs already.
	finishFilter []string
}

// v2Store is one store of a section: the cards it prices, and how it files
// one card's entries into a list.
type v2Store struct {
	name  string
	cards func(yield func(string) bool)
	file  func(list []banprice.Entry, cardID string, co *mtgmatcher.CardObject) []banprice.Entry
}

// newV2Store reads a store's record: every priced entry it has for a card,
// with Available from stock where that is not nil, once per condition since
// the stock covers every entry of it, and otherwise from the entry.
func newV2Store[T mtgban.GenericEntry](name string, record map[string][]T, withQty, withCondition, buying bool, stock func(string, mtgban.Condition) (int, bool)) v2Store {
	return v2Store{
		name: name,
		cards: func(yield func(string) bool) {
			for cardID := range record {
				if !yield(cardID) {
					return
				}
			}
		},
		file: func(list []banprice.Entry, cardID string, co *mtgmatcher.CardObject) []banprice.Entry {
			entries := record[cardID]
			var stocked mtgban.Condition
			for i := range entries {
				// To the cent, dropping the offers too small to make one
				price := math.Round(entries[i].Pricing()*100) / 100
				if price == 0 {
					continue
				}
				entry := banprice.Entry{Price: price}
				if withCondition && !co.Sealed {
					entry.Condition = string(entries[i].Condition())
				}
				if withQty {
					entry.Qty = entries[i].Qty()
				}
				inv, isInventory := any(entries[i]).(mtgban.InventoryEntry)
				if stock != nil && entries[i].Condition() != stocked {
					stocked = entries[i].Condition()
					entry.Available, _ = stock(cardID, stocked)
				} else if stock == nil && isInventory {
					entry.Available = inv.Available
				}
				if list == nil {
					// Merge folds the rows into one entry per condition
					size := min(len(entries)-i, len(banprice.ConditionOrder))
					if entry.Condition == "" {
						size = 1
					}
					list = make([]banprice.Entry, 0, size)
				}
				list = banprice.Merge(list, entry, buying)
			}
			return list
		},
	}
}

// sellerSectionV2 is the retail section of a request.
func sellerSectionV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool) *v2Section {
	sellers := GetSellers()
	section := newV2Section(b, mode, filterByEdition, filterByHash, filterByFinish, sealed, sellers)
	for _, seller := range sellers {
		info := seller.Info()
		if info.SealedMode != sealed || !slices.Contains(enabledStores, info.Shorthand) {
			continue
		}
		withQty := !info.MetadataOnly && !info.NoQuantityInventory
		section.stores = append(section.stores, newV2Store(info.Shorthand, seller.Inventory(), withQty, !info.MetadataOnly, false, v2Stock(info.Shorthand)))
	}
	return section
}

// vendorSectionV2 is the buylist section of a request.
func vendorSectionV2(b *mtgmatcher.Backend, mode string, enabledStores []string, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool) *v2Section {
	section := newV2Section(b, mode, filterByEdition, filterByHash, filterByFinish, sealed, GetSellers())
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if info.SealedMode != sealed || !slices.Contains(enabledStores, info.Shorthand) {
			continue
		}
		// An index vendor's quantity is a want-count where it says so
		withQty := !info.MetadataOnly || info.QuantityPriority
		section.stores = append(section.stores, newV2Store(info.Shorthand, vendor.Buylist(), withQty, !info.MetadataOnly, true, nil))
	}
	return section
}

func newV2Section(b *mtgmatcher.Backend, mode, filterByEdition string, filterByHash []string, filterByFinish string, sealed bool, sellers []mtgban.Seller) *v2Section {
	section := &v2Section{keyOf: v2Keyer(b, mode, sealed, sellers)}
	section.cardIDs, section.filtered = v2Cards(b, filterByEdition, filterByHash, filterByFinish, sealed)
	if filterByFinish != "" && !section.filtered {
		section.finishFilter = fixupFinishNG(filterByFinish)
	}
	return section
}

// v2Printing is one card a section prices, under the id it is keyed by.
type v2Printing struct {
	id, cardID, finish string
	co                 *mtgmatcher.CardObject
}

// walk hands emit each card of the section in id order, with every store's
// prices for it: the entries of every printing the id covers, merged. The
// map emit is handed is reused for the next card, so emit must not keep it.
func (section *v2Section) walk(b *mtgmatcher.Backend, emit func(id string, finishes map[string]map[string][]banprice.Entry) error) error {
	cardIDs := section.cardIDs
	if !section.filtered {
		priced := map[string]struct{}{}
		for _, store := range section.stores {
			for cardID := range store.cards {
				priced[cardID] = struct{}{}
			}
		}
		cardIDs = make([]string, 0, len(priced))
		for cardID := range priced {
			cardIDs = append(cardIDs, cardID)
		}
	}

	printings := make([]v2Printing, 0, len(cardIDs))
	for _, cardID := range cardIDs {
		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}
		id := section.keyOf(co)
		if id == "" {
			continue
		}
		if len(section.finishFilter) > 0 && applyCardFilter(b, "finish", section.finishFilter, co) {
			continue
		}
		printings = append(printings, v2Printing{id: id, cardID: cardID, finish: v2Finish(co), co: co})
	}
	slices.SortFunc(printings, func(a, b v2Printing) int {
		return strings.Compare(a.id, b.id)
	})

	card := map[string]map[string][]banprice.Entry{}
	var spare []map[string][]banprice.Entry
	for start := 0; start < len(printings); {
		end := start + 1
		for end < len(printings) && printings[end].id == printings[start].id {
			end++
		}
		for _, stores := range card {
			clear(stores)
			spare = append(spare, stores)
		}
		clear(card)

		for _, p := range printings[start:end] {
			stores := card[p.finish]
			for _, store := range section.stores {
				var list []banprice.Entry
				if stores != nil {
					list = stores[store.name]
				}
				list = store.file(list, p.cardID, p.co)
				if list == nil {
					continue
				}
				if stores == nil {
					if len(spare) > 0 {
						stores = spare[len(spare)-1]
						spare = spare[:len(spare)-1]
					} else {
						stores = map[string][]banprice.Entry{}
					}
					card[p.finish] = stores
				}
				stores[store.name] = list
			}
		}
		if len(card) > 0 {
			err := emit(printings[start].id, card)
			if err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}

// v2Stock is where a store with no quantities of its own reads its
// Available from: TCGplayer Direct its own stock, and TCGplayer its
// listings' copies.
func v2Stock(store string) func(cardID string, condition mtgban.Condition) (int, bool) {
	switch store {
	case tcgDirectStore:
		return tcgDirectStock
	case tcgListingsStore:
		return tcgListingsCopies
	}
	return nil
}

// v2FinishList is every finish v2 keys the game's prices by, commonest
// first: the singles' finishes, and sealed. It walks the whole catalog, so
// newDatastore builds it once per load.
func v2FinishList(b *mtgmatcher.Backend) []banprice.Finish {
	counts := map[string]int{}
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed || co.Finish == "" {
			continue
		}
		counts[co.Finish]++
	}
	if len(b.GetSealedUUIDs()) > 0 {
		counts[banprice.FinishSealed] = len(b.GetSealedUUIDs())
	}

	out := make([]banprice.Finish, 0, len(counts))
	for value, count := range counts {
		label := "Sealed"
		if value != banprice.FinishSealed {
			label = finishListLabel(b, value)
		}
		out = append(out, banprice.Finish{Value: value, Label: label, Count: count})
	}
	slices.SortFunc(out, func(a, b banprice.Finish) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Value, b.Value)
	})
	return out
}

// v2StoreName is the name v2's stores.json shows a store by: the site's
// display name. v2's prices are keyed by shorthand alone.
func v2StoreName(info mtgban.ScraperInfo) string {
	override, found := Config().ScraperConfig.NameOverride[info.Name]
	if found {
		return override
	}
	return info.Name
}

// filterV2Finishes keeps the singles' finishes for filter=singles, sealed
// for filter=sealed, and every finish otherwise, in a list never nil, so
// that before the first load too it encodes as an empty array.
func filterV2Finishes(finishes []banprice.Finish, filter string) []banprice.Finish {
	out := []banprice.Finish{}
	for _, finish := range finishes {
		sealed := finish.Value == banprice.FinishSealed
		if filter == "singles" && sealed || filter == "sealed" && !sealed {
			continue
		}
		out = append(out, finish)
	}
	return out
}

// v2StoreList is the stores among enabledStores, as stores.json lists them.
// filter=singles or filter=sealed keeps one kind of store. qty is listed as
// v2's prices carry it.
func v2StoreList(enabledStores []string, filter string) banprice.Stores {
	keep := func(info mtgban.ScraperInfo) bool {
		if filter == "singles" && info.SealedMode || filter == "sealed" && !info.SealedMode {
			return false
		}
		return slices.Contains(enabledStores, info.Shorthand)
	}
	store := func(info mtgban.ScraperInfo) banprice.Store {
		return banprice.Store{
			Shorthand: info.Shorthand,
			Name:      v2StoreName(info),
			Country:   info.CountryFlag,
			Sealed:    info.SealedMode,
			Index:     info.MetadataOnly,
		}
	}

	out := banprice.Stores{Sellers: []banprice.Store{}, Vendors: []banprice.Store{}}
	seen := map[string]bool{}
	for _, seller := range GetSellers() {
		info := seller.Info()
		if !keep(info) || seen[info.Shorthand] {
			continue
		}
		seen[info.Shorthand] = true
		entry := store(info)
		entry.Quantities = !info.MetadataOnly && !info.NoQuantityInventory
		entry.Updated = info.InventoryTimestamp
		out.Sellers = append(out.Sellers, entry)
	}
	seen = map[string]bool{}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if !keep(info) || seen[info.Shorthand] {
			continue
		}
		seen[info.Shorthand] = true
		entry := store(info)
		entry.Quantities = !info.MetadataOnly || info.QuantityPriority
		entry.CreditMultiplier = info.CreditMultiplier
		entry.Updated = info.BuylistTimestamp
		out.Vendors = append(out.Vendors, entry)
	}
	byShorthand := func(a, b banprice.Store) int { return strings.Compare(a.Shorthand, b.Shorthand) }
	slices.SortFunc(out.Sellers, byShorthand)
	slices.SortFunc(out.Vendors, byShorthand)
	return out
}

// writeV2FinishesCSV writes the finish list one finish a row.
func writeV2FinishesCSV(w http.ResponseWriter, finishes []banprice.Finish) {
	w.Header().Set("Content-Type", "text/csv")
	csvWriter := csv.NewWriter(w)
	csvWriter.Write([]string{"Value", "Label", "Count"})
	for _, finish := range finishes {
		csvWriter.Write([]string{finish.Value, finish.Label, strconv.Itoa(finish.Count)})
	}
	csvWriter.Flush()
}

// writeV2StoresCSV writes the store list one store a row, sellers first.
func writeV2StoresCSV(w http.ResponseWriter, stores banprice.Stores) {
	w.Header().Set("Content-Type", "text/csv")
	csvWriter := csv.NewWriter(w)
	csvWriter.Write([]string{"Kind", "Shorthand", "Name", "Country", "Sealed", "Index", "Quantities", "Credit Multiplier", "Updated"})
	for _, side := range []struct {
		kind   string
		stores []banprice.Store
	}{{"seller", stores.Sellers}, {"vendor", stores.Vendors}} {
		for _, store := range side.stores {
			credit, updated := "", ""
			if store.CreditMultiplier != 0 {
				credit = strconv.FormatFloat(store.CreditMultiplier, 'f', -1, 64)
			}
			if store.Updated != nil {
				updated = store.Updated.UTC().Format(time.RFC3339)
			}
			csvWriter.Write([]string{side.kind, store.Shorthand, store.Name, store.Country,
				strconv.FormatBool(store.Sealed), strconv.FormatBool(store.Index), strconv.FormatBool(store.Quantities),
				credit, updated})
		}
	}
	csvWriter.Flush()
}
