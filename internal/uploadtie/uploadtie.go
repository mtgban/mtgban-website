// Package uploadtie decides which store wins when several offer the same
// best price on an upload row, by the rule the reader picked in the
// upload settings.
package uploadtie

import "cmp"

// The rules a reader can pick. The empty rule compares shorthands alone.
// Credit and MarketCredit are also the units an upload's offers can be
// priced in, spelled as the upload's price source spells them.
const (
	Credit       = "credit"
	MarketCredit = "marketCredit"
	Consolidate  = "consolidate"
	Custom       = "custom"
)

// Breaker orders the stores tied on a row's best offer: by each key in
// turn, higher first, then by shorthand. A store a key leaves out scores 0.
// The zero Breaker compares shorthands alone.
type Breaker struct {
	keys []map[string]float64
}

// Compare orders two tied stores, the one that wins the tie first.
func (t Breaker) Compare(a, b string) int {
	for _, key := range t.keys {
		c := cmp.Compare(key[b], key[a])
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(a, b)
}

// Rates are a store's credit multiplier and the market rate of its credit,
// each 0 where it has none.
type Rates struct {
	Credit float64
	Market float64
}

// worth is what one dollar of cash offered is worth in unit: nothing in
// credit a store does not pay, and in market credit its cash where its
// credit has no market rate, as search values it.
func (r Rates) worth(unit string) float64 {
	switch unit {
	case Credit:
		return r.Credit
	case MarketCredit:
		v := r.Credit * r.Market
		if v == 0 {
			return 1
		}
		return v
	}
	return 1
}

// ByCredit breaks ties by what each tied offer is worth in store credit
// then in market credit, or in market credit first when rule is
// MarketCredit. offerUnit is what the offers are priced in: cash (""),
// Credit or MarketCredit.
func ByCredit(rule, offerUnit string, rates map[string]Rates) Breaker {
	other := MarketCredit
	if rule == MarketCredit {
		other = Credit
	}
	first := map[string]float64{}
	second := map[string]float64{}
	for store, r := range rates {
		// An offer in a unit the store does not pay is never an offer
		unit := r.worth(offerUnit)
		if unit == 0 {
			continue
		}
		first[store] = r.worth(rule) / unit
		second[store] = r.worth(other) / unit
	}
	return Breaker{keys: []map[string]float64{first, second}}
}

// ByOrder breaks ties for the stores order names, the first one first;
// the stores it leaves out compare by shorthand after them.
func ByOrder(order []string) Breaker {
	rank := map[string]float64{}
	for i, store := range order {
		_, found := rank[store]
		if !found {
			rank[store] = float64(len(order) - i)
		}
	}
	return Breaker{keys: []map[string]float64{rank}}
}

// Shares are the value of the rows each store has the best offer on alone.
type Shares map[string]float64

// Add files a row's best offer, the highest on a buylist and the lowest at
// retail, under its store when no other store matches it.
func (s Shares) Add(offers map[string]float64, blMode bool) {
	best, sole, tied := 0.0, "", false
	for store, price := range offers {
		if price == 0 {
			continue
		}
		better := price < best
		if blMode {
			better = price > best
		}
		switch {
		case sole == "" || better:
			best, sole, tied = price, store, false
		case price == best:
			tied = true
		}
	}
	if sole != "" && !tied {
		s[sole] += best
	}
}

// ByShare breaks ties for the store already holding the largest share of
// the list, so that a tied row joins the stores the rest is going to.
func ByShare(shares Shares) Breaker {
	return Breaker{keys: []map[string]float64{shares}}
}
