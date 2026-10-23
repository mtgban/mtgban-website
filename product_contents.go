package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

// contentsLineLimit is how many lines a result shows of a product's contents.
const contentsLineLimit = 5

// ContentLine is one line of a product's contents list.
type ContentLine struct {
	Count int // copies the product holds; 0 for a line that is not a count
	Name  string
	Link  string  // a search for the entry, "" when there is none
	Price float64 // TCG Market, on a deck's notable card; 0 shows nothing
}

// contentKinds is the order the list runs: the one-line kinds first, the
// deck last since it alone expands and would spend the cap on its cards.
var contentKinds = []string{"card", "pack", "sealed", "variable", "deck"}

// productContents lists what a sealed product holds: up to limit lines in
// contentKinds order, and how many entries were left off. A lone booster is
// its own one pack and lists nothing.
func productContents(b *mtgmatcher.Backend, co *mtgmatcher.CardObject, limit int) ([]ContentLine, int) {
	if co == nil || !co.Sealed {
		return nil, 0
	}
	set, err := b.GetSet(co.SetCode)
	if err != nil {
		return nil, 0
	}
	var product *mtgmatcher.SealedProduct
	for i := range set.SealedProduct {
		if set.SealedProduct[i].UUID == co.UUID {
			product = &set.SealedProduct[i]
			break
		}
	}
	if product == nil {
		return nil, 0
	}
	entries := 0
	for _, kind := range product.Contents {
		entries += len(kind)
	}
	if entries == 0 {
		return nil, 0
	}
	if packs := product.Contents["pack"]; entries == 1 && len(packs) == 1 && packs[0].Count <= 1 {
		return nil, 0
	}
	return limitContents(contentLines(b, set, product), limit)
}

// contentLines turns a product's declared contents into lines, a deck
// expanded into its notable cards; an entry the backend cannot name is
// skipped rather than shown blank.
func contentLines(b *mtgmatcher.Backend, set *mtgmatcher.Set, product *mtgmatcher.SealedProduct) []ContentLine {
	var lines []ContentLine
	// The error is dropped on purpose: no TCG Market prices every card 0 and the deck order stands.
	inv, _ := findSellerInventory("TCGMarket")
	price := func(id string) float64 { return tcgMarketPriceIn(inv, id) }
	for _, kind := range contentKinds {
		for _, content := range product.Contents[kind] {
			switch kind {
			case "card":
				card, err := b.GetUUID(content.UUID)
				if err != nil {
					continue
				}
				lines = append(lines, ContentLine{Count: content.Count, Name: card.Name, Link: "/search?q=" + content.UUID})
			case "pack":
				lines = append(lines, ContentLine{Count: content.Count, Name: boosterName(set, content.Code)})
			case "deck":
				uuids, err := sealed.DeckCards(b, content.Set, content.Name)
				if err != nil {
					continue
				}
				var deck []ContentLine
				for _, id := range rankDeckCards(uuids, price) {
					card, err := b.GetUUID(id)
					if err != nil {
						continue
					}
					deck = append(deck, ContentLine{Name: card.Name, Link: "/search?q=" + id, Price: price(id)})
				}
				lines = append(lines, dedupeLinesByName(deck)...)
			case "sealed":
				inner, err := b.GetUUID(content.UUID)
				if err != nil {
					continue
				}
				lines = append(lines, ContentLine{Count: content.Count, Name: inner.Name, Link: "/sealed?q=" + content.UUID})
			case "variable":
				lines = append(lines, ContentLine{Name: fmt.Sprintf("One of %d configurations", len(content.Configs))})
			}
		}
	}
	return lines
}

// boosterName is the set's own name for a booster type, else the code
// spelled as a booster.
func boosterName(set *mtgmatcher.Set, code string) string {
	if booster, found := set.Booster[code]; found && booster.Name != "" {
		return booster.Name
	}
	if code == "" {
		return "Booster"
	}
	return strings.ToUpper(code[:1]) + code[1:] + " booster"
}

// rankDeckCards orders a deck's cards for the list: priciest first, ties
// and unpriced cards in the deck's order, each card once.
func rankDeckCards(uuids []string, price func(string) float64) []string {
	if len(uuids) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(uuids))
	out := make([]string, 0, len(uuids))
	for _, id := range uuids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.SliceStable(out, func(i, j int) bool { return price(out[i]) > price(out[j]) })
	return out
}

// limitContents keeps the first limit lines and counts the rest; a limit
// of zero or less keeps everything.
func limitContents(lines []ContentLine, limit int) ([]ContentLine, int) {
	if limit <= 0 || len(lines) <= limit {
		return lines, 0
	}
	return lines[:limit], len(lines) - limit
}

// dedupeLinesByName keeps the first line of each name, in order.
func dedupeLinesByName(lines []ContentLine) []ContentLine {
	seen := make(map[string]bool, len(lines))
	out := make([]ContentLine, 0, len(lines))
	for _, l := range lines {
		if seen[l.Name] {
			continue
		}
		seen[l.Name] = true
		out = append(out, l)
	}
	return out
}
