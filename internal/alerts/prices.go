package alerts

import (
	"errors"
	"slices"
	"strings"
)

// StorePrice is one store's offers for a card, by condition.
type StorePrice struct {
	Shorthand string             `json:"shorthand"`
	Name      string             `json:"name"`
	Prices    map[string]float64 `json:"prices"`
}

// bestStorePrice is the highest buylist or lowest retail offer in the
// condition, among the scoped stores (every store when scope is empty).
func bestStorePrice(prices []StorePrice, side Side, condition string, scope []string) (float64, string, bool) {
	var best float64
	var store string
	found := false
	for _, p := range prices {
		if len(scope) > 0 && !slices.ContainsFunc(scope, func(s string) bool { return strings.EqualFold(s, p.Shorthand) }) {
			continue
		}
		price, ok := p.Prices[condition]
		if !ok {
			continue
		}
		better := price > best
		if side == SideRetail {
			better = price < best
		}
		if !found || better {
			best, store, found = price, p.Shorthand, true
		}
	}
	return best, store, found
}

// withKeptStores appends an empty-priced entry for each of keep not
// already in visible, so a store an alert is scoped to stays listed and
// scopeStores-able after it stops offering the card.
func withKeptStores(visible []StorePrice, keep []string, label func(shorthand string) string) []StorePrice {
	for _, s := range keep {
		if slices.ContainsFunc(visible, func(p StorePrice) bool { return strings.EqualFold(p.Shorthand, s) }) {
			continue
		}
		visible = append(visible, StorePrice{Shorthand: s, Name: label(s), Prices: map[string]float64{}})
	}
	return visible
}

// scopeStores checks every requested store against the visible ones and
// returns the canonical shorthands.
func scopeStores(requested []string, visible []StorePrice) ([]string, error) {
	out := make([]string, 0, len(requested))
	for _, want := range requested {
		i := slices.IndexFunc(visible, func(p StorePrice) bool { return strings.EqualFold(p.Shorthand, want) })
		if i < 0 {
			return nil, errors.New("store not available: " + want)
		}
		if !slices.Contains(out, visible[i].Shorthand) {
			out = append(out, visible[i].Shorthand)
		}
	}
	return out, nil
}
