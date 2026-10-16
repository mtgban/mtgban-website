package main

import (
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/matcher/sealed"
)

// eachFrom is the expected count from which the label is "~X each": one
// decimal of 1/0.95 is still 1.1, so "1 in 1" cannot print.
const eachFrom = 0.95

// moreFrom is how far the expected count must pass the copies a product
// holds for the label to say its boosters can add more.
const moreFrom = 0.05

// oddsLabel says how a random product yields a card: the copies every one
// holds if any, "N+" when its boosters can add more, else "1 in N" below
// 0.95 expected copies, to a decimal under 10, "~X each" from there, ""
// if none.
func oddsLabel(expected float64, guaranteed int, random bool) string {
	if !random || expected <= 0 {
		return ""
	}
	if guaranteed > 0 {
		held := strconv.Itoa(guaranteed)
		if expected-float64(guaranteed) >= moreFrom {
			return held + "+"
		}
		return held
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

// productOdds is how each product some card lists as its source yields
// its cards, built with the datastore that holds it.
type productOdds struct {
	yield map[string]*productYield // product uuid -> counts
}

// productYield is one product's counts: card uuid -> expected copies, and
// for a random product the copies of a card that every one of it holds.
type productYield struct {
	counts     map[string]float64
	guaranteed map[string]int
	random     bool
}

// newProductOdds counts every product in sources. A product ProductCounts
// rejects is left out, and one line names how many and the first.
func newProductOdds(b *matcher.Backend, sources *sourcesSnapshot) *productOdds {
	odds := &productOdds{yield: make(map[string]*productYield, len(sources.byProduct))}
	var failed int
	var firstErr error
	for productUUID := range sources.byProduct {
		product, err := b.GetUUID(productUUID)
		if err != nil {
			continue
		}
		yield, err := newProductYield(b, product)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", product.Name, err)
			}
			continue
		}
		odds.yield[productUUID] = yield
	}
	if failed > 0 {
		log.Printf("product odds: %d of %d products unreadable, first %v", failed, len(sources.byProduct), firstErr)
	}
	return odds
}

// newProductYield sums one product's counts by card.
func newProductYield(b *matcher.Backend, product *matcher.CardObject) (*productYield, error) {
	entries, err := sealed.ProductCounts(b, product.SetCode, product.UUID)
	if err != nil {
		return nil, err
	}
	yield := &productYield{
		counts: map[string]float64{},
		random: sealed.IsRandom(b, product.SetCode, product.UUID),
	}
	// Total counts every copy of the product the entry stands for, a box's
	// 36 packs included, the same figure the variable sort orders by. One
	// copy exactly is a slot every product fills: a card, a deck's, a pack's.
	for _, entry := range entries {
		yield.counts[entry.UUID] += entry.Total()
		if yield.random && entry.ExpectedCount == 1 {
			if yield.guaranteed == nil {
				yield.guaranteed = map[string]int{}
			}
			yield.guaranteed[entry.UUID] += entry.Copies
		}
	}
	return yield, nil
}

// label is how a product yields a card, keyed by the card's finish-specific
// uuid, which is the id the product counts carry, and the label's tooltip;
// "" for none, and always from a nil productOdds, as before the first load.
func (o *productOdds) label(productUUID, cardUUID string) (label, title string) {
	if o == nil {
		return "", ""
	}
	yield, found := o.yield[productUUID]
	if !found {
		return "", ""
	}
	expected := yield.counts[cardUUID]
	label = oddsLabel(expected, yield.guaranteed[cardUUID], yield.random)
	if label == "" {
		return "", ""
	}
	return label, expectedCopies(expected)
}
