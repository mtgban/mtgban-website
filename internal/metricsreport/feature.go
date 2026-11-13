package metricsreport

import "github.com/mtgban/mtgban-website/observability"

// Use is one name's uses in a window and its rate against its denominator.
type Use struct {
	Count int64 // every scope and value of the name in the window
	Denom int64 // the denominator rows' sum in the window; 0 when it has none to count
	// Rate is Count over Denom as a fraction (0.005 is 0.5%), 0 when Denom is 0.
	Rate     float64
	RateText string // as a Candidate's RateText, or ""
	NoRate   string // as a Candidate's NoRate: why RateText is ""; "" when there is a rate or n is stored state
}

// NameUse sums one name over the window of totals, the slice Remove takes, and rates it
// against its denominator by Remove's rule. A stored-state name is never summed: its Use is zero.
func NameUse(n observability.Name, totals []observability.DayTotal, w Window) Use {
	if n.Family == observability.FamilyStock {
		return Use{}
	}
	k := windowPeriods(w)
	idx := newIndex(totals, k)
	var u Use
	for _, p := range idx.window(Unit{Name: n.Name}) {
		u.Count += p.n
	}
	d := denominatorOf(n)
	u.Denom, _ = d.measure(idx, k)
	if u.Denom > 0 {
		_, wider := widerDenom[n.Name]
		u.Rate = float64(u.Count) / float64(u.Denom)
		u.RateText = rateText(n.Family == observability.FamilyUI, u.Count, u.Denom, d.word, wider)
	} else {
		u.NoRate = d.noRate()
	}
	return u
}
