package metricsreport

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The Invest sections, in the order Invest returns them.
const (
	SectionWalls    = "walls"
	SectionFailures = "failures"
	SectionMobile   = "mobile"
	SectionGrowing  = "growing"
	SectionNew      = "new"
	SectionDepth    = "depth"
)

// SectionOrder lists the Invest sections in order; a fresh slice each call.
func SectionOrder() []string {
	return []string{SectionWalls, SectionFailures, SectionMobile, SectionGrowing, SectionNew, SectionDepth}
}

// Signal is one Invest row: a wall, a failure rate, a page phones reach, a growing or new name, a page's depth.
type Signal struct {
	Section, Label, Evidence string // walls, failures, mobile, growing, new, depth
	Name, Scope, Value       string // the registry key behind the row, for its link
	Count, Denom, Previous   int64  // Previous is Count over the window before
	PrevDenom                int64  // Denom over the window before; 0 for a row with no Denom
	// Rate is Count over Denom as a fraction (0.25 is 25%); for growing, this
	// period's use over the last one's per counted day (1.5 is 1.5 times).
	// It is 0 when HasRate is false.
	Rate        float64
	NotMeasured bool
	Help        string // the registry Help of Name, what the number is of; "" when Name is not registered
}

// HasRate reports whether Rate may be shown: a growing row, or a Denom of at least the rate floor.
// A row with a smaller nonzero Denom is too few to say.
func (s Signal) HasRate() bool {
	if s.Section == SectionGrowing {
		return s.Previous > 0
	}
	return s.Denom >= minRateDenom
}

// PageDepth is one page's signed-in human traffic from events.
type PageDepth struct {
	Page                     string
	Views, MobileViews       int64
	Visitors, Once, FivePlus int64
	HasMobile                bool // the page has a mobile template
}

// per says what one row of a pick is.
type per int

const (
	perName per = iota
	perValue
	perScope
)

// part is some of one name's rows: values nil is every value, except leaves some out.
type part struct {
	name           string
	values, except []string
}

// has reports whether a row's value belongs to the part.
func (p part) has(value string) bool {
	if slices.Contains(p.except, value) {
		return false
	}
	return p.values == nil || slices.Contains(p.values, value)
}

// evidence says how a failure row explains its count.
type evidence int

const (
	evNone    evidence = iota
	evLargest          // the numerator's values, largest first
	evInOrder          // the numerator's values in the pick's order, zeros included
)

// pick is one row source of walls or failures.
type pick struct {
	label    string
	num      part
	per      per
	denom    []part // nil for a count row; summed in the row's scope when per is perScope
	evidence evidence
}

// walls are readers reaching for something they cannot have.
var walls = []pick{
	{label: "Locked sort clicked", num: part{name: "ui.search.sort_locked"}, per: perName},
	{label: "Locked row action", num: part{name: "ui.row.locked"}, per: perValue},
	{label: "Upload upsell clicked", num: part{name: "ui.upload.upsell"}, per: perName},
	{label: "Page refused for the tier", num: part{name: "auth.refuse", values: []string{"no_access"}}, per: perScope},
	{label: "API call refused by plan", num: part{name: "api.refuse", values: []string{"plan"}}, per: perName},
}

// failures are rates of things going wrong, and the rate limiters' refusals as counts.
var failures = []pick{
	{label: "Empty searches", num: part{name: "search.result", values: []string{"empty"}}, per: perName,
		denom: []part{{name: "search.result"}}},
	// upload.source counts priced runs only, so the errors join the denominator; url_prefix
	// is a redirect whose upload counts url again.
	{label: "Upload parse errors", num: part{name: "upload.parse_error"}, per: perName, evidence: evLargest,
		denom: []part{{name: "upload.source", except: []string{"url_prefix"}}, {name: "upload.parse_error"}}},
	// deferred counts again on every retry, so it is in neither side.
	{label: "Alert deliveries failed", num: part{name: "alerts.delivered", values: []string{"fail", "refused"}}, per: perScope, evidence: evInOrder,
		denom: []part{{name: "alerts.delivered", values: []string{"ok", "fail", "refused"}}}},
	{label: "Server errors", num: part{name: "http.status", values: []string{"5xx"}}, per: perScope,
		denom: []part{{name: "http.status"}}},
	{label: "Slow requests", num: part{name: "http.duration", values: []string{"<5s", "5s+"}}, per: perScope,
		denom: []part{{name: "http.duration"}}},
	{label: "Rate limited", num: part{name: "ratelimit.reject"}, per: perValue},
	{label: "Offline sync failed", num: part{name: "ui.offline.sync", values: []string{"fail"}}, per: perScope,
		denom: []part{{name: "ui.offline.sync"}}},
}

// uiLoad is the name whose rows show the client counters run.
const uiLoad = "ui.load"

// pageView is the name of page views, the population of the mobile and depth rows.
const pageView = "page.view"

// flushName is the name whose rows show the server counter ran.
const flushName = "metrics.flush"

// windowPeriods is how many Step-30 periods a window spans.
func windowPeriods(w Window) int {
	return max(0, (w.Days+periodDays-1)/periodDays)
}

// groupByName groups totals by name, keeping their order.
func groupByName(totals []observability.DayTotal) map[string][]observability.DayTotal {
	out := map[string][]observability.DayTotal{}
	for _, t := range totals {
		out[t.Name] = append(out[t.Name], t)
	}
	return out
}

// sums is one row key's counts: this window, the window before, and this window by value.
type sums struct {
	cur, prev int64
	values    map[string]int64
}

// rowKey is the key a row of the pick falls under.
func (p pick) rowKey(t observability.DayTotal) string {
	switch p.per {
	case perScope:
		return t.Scope
	case perValue:
		return t.Value
	}
	return ""
}

// investRows builds one section's rows from its picks, measured rows ranked, then the not-measured ones in pick order.
func investRows(section string, picks []pick, registered map[string]observability.Name, rows map[string][]observability.DayTotal, k int, uiOn bool) []Signal {
	var measured, unmeasured []Signal
	for _, p := range picks {
		if !pickMeasured(p, registered, uiOn) {
			unmeasured = append(unmeasured, Signal{Section: section, Label: p.label, Name: p.num.name, NotMeasured: true, Help: registered[p.num.name].Help})
			continue
		}
		num := map[string]*sums{}
		for _, t := range rows[p.num.name] {
			if !p.num.has(t.Value) {
				continue
			}
			key := p.rowKey(t)
			s := num[key]
			if s == nil {
				s = &sums{values: map[string]int64{}}
				num[key] = s
			}
			switch {
			case t.Period >= 0 && t.Period < k:
				s.cur += t.N
				s.values[t.Value] += t.N
			case t.Period >= k && t.Period < 2*k:
				s.prev += t.N
			}
		}
		den, prevDen := map[string]int64{}, map[string]int64{}
		for _, d := range p.denom {
			for _, t := range rows[d.name] {
				if !d.has(t.Value) || t.Period < 0 || t.Period >= 2*k {
					continue
				}
				key := ""
				if p.per == perScope {
					key = t.Scope
				}
				if t.Period < k {
					den[key] += t.N
				} else {
					prevDen[key] += t.N
				}
			}
		}
		for key, s := range num {
			if s.cur <= 0 {
				continue
			}
			sig := Signal{Section: section, Label: p.label, Name: p.num.name, Count: s.cur, Previous: s.prev, Help: registered[p.num.name].Help}
			if len(p.num.values) == 1 {
				sig.Value = p.num.values[0]
			}
			switch p.per {
			case perScope:
				sig.Scope, sig.Label = key, p.label+": "+key
			case perValue:
				sig.Value, sig.Label = key, p.label+": "+key
			}
			if p.denom != nil {
				dk := ""
				if p.per == perScope {
					dk = key
				}
				sig.Denom, sig.PrevDenom = den[dk], prevDen[dk]
				if sig.Denom < minRateDenom {
					continue
				}
				sig.Rate = float64(sig.Count) / float64(sig.Denom)
			}
			sig.Evidence = p.explain(s.values)
			measured = append(measured, sig)
		}
	}
	slices.SortFunc(measured, compareFailure)
	return append(measured, unmeasured...)
}

// pickMeasured reports whether every name a pick reads is registered, and a client name's counters ran.
func pickMeasured(p pick, registered map[string]observability.Name, uiOn bool) bool {
	parts := append([]part{p.num}, p.denom...)
	for _, pt := range parts {
		n, ok := registered[pt.name]
		if !ok || (n.Family == observability.FamilyUI && !uiOn) {
			return false
		}
	}
	return true
}

// explain is a failure row's Evidence from its values' counts this window.
func (p pick) explain(values map[string]int64) string {
	var keys []string
	switch p.evidence {
	case evLargest:
		for v, n := range values {
			if n > 0 {
				keys = append(keys, v)
			}
		}
		slices.SortFunc(keys, func(a, b string) int {
			return cmp.Or(cmp.Compare(values[b], values[a]), cmp.Compare(a, b))
		})
	case evInOrder:
		keys = p.num.values
	default:
		return ""
	}
	out := make([]string, len(keys))
	for i, v := range keys {
		out[i] = fmt.Sprintf("%s %d", v, values[v])
	}
	return strings.Join(out, ", ")
}

// compareFailure ranks rate rows by rate, then count rows by count, then by key; walls have no rate.
func compareFailure(a, b Signal) int {
	if ar, br := a.Denom > 0, b.Denom > 0; ar != br {
		if ar {
			return -1
		}
		return 1
	}
	return cmp.Or(cmp.Compare(b.Rate, a.Rate), cmp.Compare(b.Count, a.Count), compareKey(a, b))
}

// compareKey is the total order every ranking falls back on.
func compareKey(a, b Signal) int {
	return cmp.Or(cmp.Compare(a.Label, b.Label), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
}

// Invest lists where usage is and where it hits walls, as the sections walls, failures, mobile,
// growing, new and depth, each ranked. totals are DayTotals with Step 30 over 2*w.Days days, unsplit,
// the same slice Remove takes; pages are signed-in human page hits for the window, whatever the toggles.
func Invest(names []observability.Name, totals []observability.DayTotal, pages []PageDepth, w Window) []Signal {
	k := windowPeriods(w)
	registered := make(map[string]observability.Name, len(names))
	for _, n := range names {
		registered[n.Name] = n
	}
	rows := groupByName(totals)
	uiOn := false
	for _, t := range rows[uiLoad] {
		if t.Period >= 0 && t.Period < k {
			uiOn = true
			break
		}
	}
	out := investRows(SectionWalls, walls, registered, rows, k, uiOn)
	out = append(out, investRows(SectionFailures, failures, registered, rows, k, uiOn)...)
	pageHelp := registered[pageView].Help
	out = append(out, mobileRows(pages, pageHelp)...)
	out = append(out, growingRows(names, totals)...)
	out = append(out, newRows(names, rows, k)...)
	out = append(out, depthRows(pages, pageHelp)...)
	return out
}

// rateOf is count over denom as a fraction, 0 under the rate floor.
func rateOf(count, denom int64) float64 {
	if denom < minRateDenom {
		return 0
	}
	return float64(count) / float64(denom)
}

// mobileRows are the pages with no mobile template that phones reached, most mobile views first.
func mobileRows(pages []PageDepth, help string) []Signal {
	var out []Signal
	for _, p := range pages {
		if p.HasMobile || p.MobileViews <= 0 {
			continue
		}
		out = append(out, Signal{Section: SectionMobile, Label: p.Page, Name: pageView, Value: p.Page, Help: help,
			Count: p.MobileViews, Denom: p.Views, Rate: rateOf(p.MobileViews, p.Views)})
	}
	slices.SortFunc(out, func(a, b Signal) int { return cmp.Or(cmp.Compare(b.Count, a.Count), compareKey(a, b)) })
	return out
}

// depthRows are the pages with visitors, the most visitors first.
func depthRows(pages []PageDepth, help string) []Signal {
	var out []Signal
	for _, p := range pages {
		if p.Visitors <= 0 {
			continue
		}
		out = append(out, Signal{Section: SectionDepth, Label: p.Page, Name: pageView, Value: p.Page, Help: help,
			Count: p.FivePlus, Denom: p.Visitors, Rate: rateOf(p.FivePlus, p.Visitors),
			Evidence: fmt.Sprintf("%d once, %d on five or more days", p.Once, p.FivePlus)})
	}
	slices.SortFunc(out, func(a, b Signal) int { return cmp.Or(cmp.Compare(b.Denom, a.Denom), compareKey(a, b)) })
	return out
}

// reportable reports whether a name may appear as growing or new: not internal, and no standing count.
func reportable(n observability.Name) bool {
	return n.Report != observability.ReportInternal && n.Family != observability.FamilyStock
}

// unitLabel names a unit for a row: the name, then its scope and value.
func unitLabel(u Unit) string {
	var rest []string
	for _, s := range []string{u.Scope, u.Value} {
		if s != "" {
			rest = append(rest, s)
		}
	}
	if len(rest) == 0 {
		return u.Name
	}
	return u.Name + ": " + strings.Join(rest, " ")
}

// growingRows compare period 0 with period 1 per day the counter flushed; a candidate per unit, any other name whole.
// Both periods need minDaysMeasured flushed days, or nothing is compared.
func growingRows(names []observability.Name, totals []observability.DayTotal) []Signal {
	r := ReachOf(totals, Window{Days: periodDays})
	if !r.Growing {
		return nil
	}
	d0, d1 := r.GrowingDays[0], r.GrowingDays[1]
	idx := newIndex(totals, 2)
	var out []Signal
	for _, n := range names {
		if !reportable(n) {
			continue
		}
		units := Units(n)
		if units == nil {
			units = []Unit{{Name: n.Name}}
		}
		for _, u := range units {
			w := idx.window(u)
			if w == nil {
				continue
			}
			p0, p1 := w[0].n, w[1].n
			if p0 < growthFloor || p1 <= 0 {
				continue
			}
			// per flushed day: p0/d0 against p1/d1
			ratio := float64(p0) * float64(d1) / (float64(p1) * float64(d0))
			if ratio < growthFactor {
				continue
			}
			out = append(out, Signal{Section: SectionGrowing, Label: unitLabel(u), Name: u.Name, Scope: u.Scope, Value: u.Value, Help: n.Help,
				Count: p0, Previous: p1, Rate: ratio})
		}
	}
	slices.SortFunc(out, func(a, b Signal) int { return cmp.Or(cmp.Compare(b.Rate, a.Rate), compareKey(a, b)) })
	return out
}

// newRows are names first seen in the window, with at least newFloor uses, while the counter
// already ran on minDaysMeasured days of the window before.
func newRows(names []observability.Name, rows map[string][]observability.DayTotal, k int) []Signal {
	if flushDays(rows[flushName], k, 2*k) < minDaysMeasured { // ReachOf's New
		return nil
	}
	var out []Signal
	for _, n := range names {
		if !reportable(n) {
			continue
		}
		var cur int64
		var oldest time.Time
		seen, before := false, false
		for _, t := range rows[n.Name] {
			switch {
			case t.Period >= 0 && t.Period < k:
				cur += t.N
				if !seen || t.First.Before(oldest) {
					oldest = t.First
				}
				seen = true
			case t.Period >= k && t.Period < 2*k:
				before = true
			}
		}
		if !seen || before || cur < newFloor {
			continue
		}
		out = append(out, Signal{Section: SectionNew, Label: n.Name, Name: n.Name, Count: cur, Help: n.Help,
			Evidence: "first seen " + oldest.Format("2006-01-02")})
	}
	slices.SortFunc(out, func(a, b Signal) int { return cmp.Or(cmp.Compare(b.Count, a.Count), compareKey(a, b)) })
	return out
}

// scriptErrors is the failures row WithErrors puts in place of rows phase 2f does not yet make.
const scriptErrors = "Script errors"

// WithErrors puts the script error rows at the end of the failures section.
// With measured false it puts one "Script errors" not-measured row there. The input is not modified.
func WithErrors(signals, errors []Signal, measured bool) []Signal {
	insert := errors
	if !measured {
		insert = []Signal{{Section: SectionFailures, Label: scriptErrors, NotMeasured: true}}
	}
	at := len(signals)
	seenFailures := false
	for i, s := range signals {
		if s.Section == SectionFailures {
			seenFailures = true
			at = i + 1
			continue
		}
		if seenFailures || laterThanFailures(s.Section) {
			at = i
			break
		}
		at = i + 1
	}
	out := make([]Signal, 0, len(signals)+len(insert))
	out = append(out, signals[:at]...)
	out = append(out, insert...)
	return append(out, signals[at:]...)
}

// laterThanFailures reports whether a section comes after failures.
func laterThanFailures(section string) bool {
	return section != SectionWalls && section != SectionFailures
}

// Reach says whether Growing and New could compare, with the counted days behind each.
type Reach struct {
	Growing     bool
	GrowingDays [2]int // counted days of the last 30 days and of the 30 before
	New         bool
	NewDays     int // counted days of the window before
}

// ReachOf is the Reach of totals, the slice Invest takes; each side needs MinDaysMeasured counted days.
func ReachOf(totals []observability.DayTotal, w Window) Reach {
	k := windowPeriods(w)
	rows := groupByName(totals)[flushName]
	r := Reach{GrowingDays: [2]int{flushDays(rows, 0, 1), flushDays(rows, 1, 2)}, NewDays: flushDays(rows, k, 2*k)}
	r.Growing = Comparable(r.GrowingDays[0], r.GrowingDays[1])
	r.New = r.NewDays >= minDaysMeasured
	return r
}
