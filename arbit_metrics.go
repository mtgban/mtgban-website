package main

import (
	"net/http"
	"net/url"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
)

// arbitRun is what one arbitrage view ran with.
type arbitRun struct {
	page     string     // arbit, reverse or global
	form     url.Values // the request's own form
	state    arbitState
	mode     arbitMode     // the comparison the state was applied to; zero on the landing
	source   string        // the source's shorthand; "" on the landing
	sort     string        // the sort the tables ran with
	excluded int           // stores in the reader's hidden-stores cookie
	sections int           // len(pageVars.Arb)
	elapsed  time.Duration // since scraperCompare started
}

// arbitResetKey marks the Restore defaults link; only the count reads it.
const arbitResetKey = "reset"

// arbitPage is the page a view is scoped to.
func arbitPage(global, reverse bool) string {
	switch {
	case global:
		return "global"
	case reverse:
		return "reverse"
	}
	return "arbit"
}

// arbitApply is arbit.apply's value: the filter form, the reset link, or "".
func arbitApply(form url.Values, st arbitState) string {
	if !form.Has(arbitMarker) {
		return ""
	}
	switch {
	case form.Has("toggles_on"):
		return "apply"
	case form.Has(arbitResetKey) && st.isZero():
		return "reset"
	}
	return ""
}

// arbitToggleChosen reports whether the reader set key away from the mode's default on a page that shows it.
func arbitToggleChosen(st arbitState, m arbitMode, key string) bool {
	on, set := st.Toggles[key]
	return set && FilterOptConfig[key].Shown(m.Global, m.Reverse, m.Sealed) && on != m.toggleDefault(key)
}

// arbitFacts lists what one arbitrage view ran with.
func arbitFacts(run arbitRun) []fact {
	page := run.page
	excluded := newFact(page, "arbit.excluded_vendors", observability.Bucket([]int64{1, 5, 10}, int64(run.excluded)))
	if run.source == "" {
		return []fact{newFact(page, "arbit.view", "landing"), excluded}
	}
	facts := []fact{newFact(page, "arbit.view", "store"), newFact(page, "arbit.source", run.source)}
	if v := arbitApply(run.form, run.state); v != "" {
		facts = append(facts, newFact(page, "arbit.apply", v))
	}
	st := run.state
	for _, key := range arbitBoundKeys {
		if st.bound(key).Set {
			facts = append(facts, newFact(page, "arbit.bound", key))
		}
	}
	for _, key := range arbitPickKeys {
		if st.pick(key).Set {
			facts = append(facts, newFact(page, "arbit.pick", key))
		}
	}
	for _, key := range FilterOptKeys {
		if arbitToggleChosen(st, run.mode, key) {
			facts = append(facts, newFact(page, "arbit.toggle", key))
		}
	}
	return append(facts,
		newFact(page, "arbit.sort", run.sort),
		excluded,
		newFact(page, "arbit.sections", observability.Bucket([]int64{1, 5, 10, 20}, int64(run.sections))),
		newFact(page, "arbit.duration", durationBucket(run.elapsed)),
	)
}

// countArbit reports whether an arbitrage view will be counted.
func countArbit(r *http.Request) bool {
	return FeatureCounter != nil && isPageView(r)
}

// readArbitRun reads what one view ran with; source is nil on the landing.
func readArbitRun(r *http.Request, pageVars PageVars, cmp scraperCompareOpts, state arbitState,
	mode arbitMode, source mtgban.Scraper, sorting string, start time.Time) arbitRun {
	run := arbitRun{
		page:     arbitPage(pageVars.GlobalMode, pageVars.ReverseMode),
		form:     r.Form,
		state:    state,
		mode:     mode,
		sort:     sorting,
		excluded: cmp.ExcludedVendors,
		sections: len(pageVars.Arb),
		elapsed:  time.Since(start),
	}
	if source != nil {
		run.source = source.Info().Shorthand
	}
	return run
}

// nonEmpty counts the entries of a split cookie value that name something.
func nonEmpty(entries []string) int {
	n := 0
	for _, entry := range entries {
		if entry != "" {
			n++
		}
	}
	return n
}
