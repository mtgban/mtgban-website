package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

// eachFrom is the expected count from which the label is "~X each": one
// decimal of 1/0.95 is still 1.1, so "1 in 1" cannot print.
const eachFrom = 0.95

// oddsLabel says how a random product yields a card: "1 in N" below 0.95
// expected copies, to a decimal under 10, "~X each" from there, "" if none.
func oddsLabel(expected float64, random bool) string {
	if !random || expected <= 0 {
		return ""
	}
	if expected >= eachFrom {
		return "~" + formatExpectedCount(expected) + " each"
	}
	n := 1 / expected
	if n >= 10 {
		return fmt.Sprintf("1 in %d", int(math.Round(n)))
	}
	return "1 in " + strings.TrimSuffix(fmt.Sprintf("%.1f", n), ".0")
}

// expectedCopies words the label's number as what it is, expected copies
// per product, for the label's tooltip: a product with several chances at
// the card is not "1 in N" in the strict sense.
func expectedCopies(expected float64) string {
	if expected < 0.001 {
		return "under 0.001 copies expected"
	}
	count := formatExpectedCount(expected)
	if expected < 1 {
		count = strings.TrimRight(strings.TrimRight(strconv.FormatFloat(expected, 'f', 3, 64), "0"), ".")
	}
	if count == "1" {
		return "1 copy expected"
	}
	return count + " copies expected"
}

// productOdds answers how a product yields each card, computed once per
// product for the datastore that holds it, so a reload drops the memo.
type productOdds struct {
	b     *mtgmatcher.Backend
	yield sync.Map // product uuid -> *productYield
}

// productYield is one product's counts: card uuid -> expected copies.
type productYield struct {
	counts map[string]float64
	random bool
}

func newProductOdds(b *mtgmatcher.Backend) *productOdds {
	return &productOdds{b: b}
}

// labelFor returns the odds function for one card, keyed by the card's
// finish-specific uuid, which is the id the product counts carry. It is nil
// before the first load (no memo) and for a sealed product, which lists no
// odds of its own.
func (o *productOdds) labelFor(co *mtgmatcher.CardObject) func(productUUID string) (label, title string) {
	if o == nil || co.Sealed {
		return nil
	}
	return func(productUUID string) (string, string) {
		yield, ok := o.product(productUUID)
		if !ok {
			return "", ""
		}
		expected := yield.counts[co.UUID]
		label := oddsLabel(expected, yield.random)
		if label == "" {
			return "", ""
		}
		return label, expectedCopies(expected)
	}
}

// product reads a product's counts from the memo, filling it on first sight.
// A product the backend does not know is not memoised; one ProductCounts
// rejects is, as empty, so it logs once per load.
func (o *productOdds) product(productUUID string) (*productYield, bool) {
	if yield, ok := o.yield.Load(productUUID); ok {
		return yield.(*productYield), true
	}
	product, err := o.b.GetUUID(productUUID)
	if err != nil {
		return nil, false
	}
	yield := &productYield{counts: map[string]float64{}}
	entries, err := sealed.ProductCounts(o.b, product.SetCode, product.UUID)
	if err != nil {
		if logger := LogPages["Search"]; logger != nil {
			logger.Println("productOdds:", product.Name, err)
		}
	}
	// Total counts every copy of the product the entry stands for, a box's
	// 36 packs included, the same figure the variable sort orders by.
	for _, entry := range entries {
		yield.counts[entry.UUID] += entry.Total()
	}
	yield.random = sealed.IsRandom(o.b, product.SetCode, product.UUID)
	// Two first askers compute the same value; whichever stored first wins.
	stored, _ := o.yield.LoadOrStore(productUUID, yield)
	return stored.(*productYield), true
}
