package main

import (
	"fmt"
	"math"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

// oddsLabel says how a random product yields a card: "1 in N" when it yields
// the card less than about two thirds of the time, "~X each" above, "" if none.
func oddsLabel(expected float64, random bool) string {
	if !random || expected <= 0 {
		return ""
	}
	if n := int(math.Round(1 / expected)); n >= 2 {
		return fmt.Sprintf("1 in %d", n)
	}
	return "~" + formatExpectedCount(expected) + " each"
}

// productOdds answers how a product yields each card, computed once per
// product for the request that holds it.
type productOdds struct {
	b      *mtgmatcher.Backend
	counts map[string]map[string]float64 // product uuid -> card uuid -> expected copies
	random map[string]bool
}

func newProductOdds(b *mtgmatcher.Backend) *productOdds {
	return &productOdds{
		b:      b,
		counts: map[string]map[string]float64{},
		random: map[string]bool{},
	}
}

// labelFor returns the odds function for one card, keyed by the card's
// finish-specific uuid, which is the id the product counts carry.
func (o *productOdds) labelFor(co *mtgmatcher.CardObject) func(productUUID string) string {
	return func(productUUID string) string {
		counts, random, ok := o.product(productUUID)
		if !ok {
			return ""
		}
		return oddsLabel(counts[co.UUID], random)
	}
}

// product reads a product's counts from the memo, filling it on first sight.
// A product the backend does not know is not memoised; one ProductCounts
// rejects is, as empty, so it logs once.
func (o *productOdds) product(productUUID string) (map[string]float64, bool, bool) {
	if counts, ok := o.counts[productUUID]; ok {
		return counts, o.random[productUUID], true
	}
	product, err := o.b.GetUUID(productUUID)
	if err != nil {
		return nil, false, false
	}
	counts := map[string]float64{}
	entries, err := sealed.ProductCounts(o.b, product.SetCode, product.UUID)
	if err != nil {
		if logger := LogPages["Search"]; logger != nil {
			logger.Println("productOdds:", product.Name, err)
		}
	}
	// Total counts every copy of the product the entry stands for, a box's
	// 36 packs included, the same figure the variable sort orders by.
	for _, entry := range entries {
		counts[entry.UUID] += entry.Total()
	}
	o.counts[productUUID] = counts
	o.random[productUUID] = sealed.IsRandom(o.b, product.SetCode, product.UUID)
	return counts, o.random[productUUID], true
}
