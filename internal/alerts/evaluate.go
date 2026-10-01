package alerts

import (
	"cmp"
	"slices"
	"time"
)

// Quote is one in-scope store's price in the alert's condition.
type Quote struct {
	Store string
	Price float64
}

// Decision is what one evaluation concluded for an alert.
type Decision struct {
	FireAbove, FireBelow   bool
	AboveHits, BelowHits   []Quote
	AboveArmed, BelowArmed bool
	Throttled              bool
}

// bestQuote is the lowest ask on retail and the highest offer on buylist.
func bestQuote(side Side, quotes []Quote) (float64, bool) {
	if len(quotes) == 0 {
		return 0, false
	}
	byPrice := func(x, y Quote) int { return cmp.Compare(x.Price, y.Price) }
	if side == SideRetail {
		return slices.MinFunc(quotes, byPrice).Price, true
	}
	return slices.MaxFunc(quotes, byPrice).Price, true
}

// crossed says whether best stands past each threshold that is set.
func crossed(a Alert, best float64) (above, below bool) {
	if a.Above.Set() {
		above = best >= a.Above.Resolve(a.ReferencePrice, true)
	}
	if a.Below.Set() {
		below = best <= a.Below.Resolve(a.ReferencePrice, false)
	}
	return above, below
}

// startArmed is the armed state a created or edited alert starts in: a
// side its best price already stands past waits for the price to come back.
func startArmed(a Alert, best float64, hasPrice bool) (above, below bool) {
	if !hasPrice {
		return true, true
	}
	pastAbove, pastBelow := crossed(a, best)
	return !pastAbove, !pastBelow
}

// pastLine is the quotes for which past holds, best first.
func pastLine(side Side, quotes []Quote, past func(price float64) bool) []Quote {
	var hits []Quote
	for _, q := range quotes {
		if past(q.Price) {
			hits = append(hits, q)
		}
	}
	slices.SortStableFunc(hits, func(x, y Quote) int {
		if side == SideRetail {
			return cmp.Compare(x.Price, y.Price)
		}
		return cmp.Compare(y.Price, x.Price)
	})
	return hits
}

// Evaluate applies the crossing, re-arm and minimum-gap rules to the best
// quote and says what to send and what armed state to keep. A side fires
// when the best price crosses its line and re-arms once it is back; no
// quotes at all leave both sides as they were.
func Evaluate(a Alert, quotes []Quote, now time.Time, minGap time.Duration) Decision {
	d := Decision{AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed}
	best, ok := bestQuote(a.Side, quotes)
	if !ok {
		return d
	}
	inGap := a.LastFiredAt != nil && now.Sub(*a.LastFiredAt) < minGap
	pastAbove, pastBelow := crossed(a, best)

	if a.Above.Set() {
		switch {
		case a.AboveArmed && pastAbove && inGap:
			d.Throttled = true
		case a.AboveArmed && pastAbove:
			limit := a.Above.Resolve(a.ReferencePrice, true)
			d.AboveHits = pastLine(a.Side, quotes, func(p float64) bool { return p >= limit })
			d.FireAbove, d.AboveArmed = true, false
		case !a.AboveArmed && !pastAbove:
			d.AboveArmed = true
		}
	}
	if a.Below.Set() {
		switch {
		case a.BelowArmed && pastBelow && inGap:
			d.Throttled = true
		case a.BelowArmed && pastBelow:
			limit := a.Below.Resolve(a.ReferencePrice, false)
			d.BelowHits = pastLine(a.Side, quotes, func(p float64) bool { return p <= limit })
			d.FireBelow, d.BelowArmed = true, false
		case !a.BelowArmed && !pastBelow:
			d.BelowArmed = true
		}
	}
	return d
}
