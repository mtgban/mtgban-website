package main

import (
	"net/http"
	"strconv"

	"github.com/mtgban/mtgban-website/timeseries"
)

// The floors a fresh screener load applies; every later form and link re-sends them.
const (
	screenerLandingMinPrice = 5
	screenerLandingMinPct   = 20
)

// screenerLanding reports whether r is a fresh load, naming no provider, min_price or min_pct.
func screenerLanding(r *http.Request) bool {
	return r.FormValue("provider") == "" && r.FormValue("min_price") == "" && r.FormValue("min_pct") == ""
}

// screenerRun is what one screener view ran with.
type screenerRun struct {
	filter       screenerFilter
	landing      bool // the request named no provider, min_price or min_pct
	editions     int  // editions ticked
	size, index  int  // index is the clamped page, 0 when there were no rows
	sorting, dir string
}

// screenerProviderName is a seeded provider's shorthand, else "".
func screenerProviderName(id int) string {
	for _, p := range timeseries.Providers() {
		if int(p.ID) == id {
			return p.Shorthand
		}
	}
	return ""
}

// screenerFacts lists what one screener view ran with.
func screenerFacts(run screenerRun) []fact {
	f := run.filter
	var facts []fact
	if name := screenerProviderName(f.Metric); name != "" {
		facts = append(facts, newFact("", "screener.provider", name))
	}
	facts = append(facts,
		newFact("", "screener.window", strconv.Itoa(f.Window)),
		newFact("", "screener.kind", f.Kind),
		newFact("", "screener.move", f.Move),
	)
	// The landing's floors are not a choice, and filterScreenerRows ignores a MaxPct below 1.
	if !run.landing {
		for _, c := range []struct {
			on  bool
			key string
		}{
			{f.MinPrice > 0 && f.MinPrice != screenerLandingMinPrice, "min_price"},
			{f.MinPriorPrice > 0, "min_was"},
			{f.MinPct != 0 && f.MinPct != screenerLandingMinPct, "min_pct"},
			{f.MaxPct > 0, "max_pct"},
			{run.editions > 0, "edition"},
		} {
			if c.on {
				facts = append(facts, newFact("", "screener.filter", c.key))
			}
		}
	}
	facts = append(facts, newFact("", "screener.size", strconv.Itoa(run.size)))
	sorting := run.sorting
	if sorting == "" {
		sorting = "pct"
	}
	switch sorting {
	case "current", "prior", "pct", "abs":
		dir := "desc"
		if run.dir == "asc" {
			dir = "asc"
		}
		facts = append(facts, newFact(dir, "screener.sort", sorting))
	}
	return append(facts, newFact("", "screener.page", pageBucket(run.index)))
}

// countScreener reports whether served rows will be counted: a page view,
// or the rows=1 fetch a deferred page makes for them.
func countScreener(r *http.Request) bool {
	return FeatureCounter != nil && (isPageView(r) || r.FormValue("rows") == "1")
}

// readScreenerRun reads what one screener view ran with.
func readScreenerRun(r *http.Request, filter screenerFilter, editions, size, index int, sorting, dir string) screenerRun {
	return screenerRun{
		filter:   filter,
		landing:  screenerLanding(r),
		editions: editions,
		size:     size,
		index:    index,
		sorting:  sorting,
		dir:      dir,
	}
}
