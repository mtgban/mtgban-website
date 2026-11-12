package metricsreport

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// Window is a report's span in days and its two reader toggles.
type Window struct {
	Days   int  // 30, 90 or 180
	Signed bool // signed-in rows only
	Humans bool // bot rows left out
}

// The classes a removal candidate takes, in the order Remove lists them.
const (
	ClassUnused      = "unused"
	ClassRare        = "rare"
	ClassUnusedSoFar = "unused_so_far"
	ClassNotMeasured = "not_measured"
	ClassReviewed    = "reviewed"
)

// classRank orders the classes in Remove's result.
var classRank = map[string]int{ClassUnused: 0, ClassRare: 1, ClassUnusedSoFar: 2, ClassNotMeasured: 3, ClassReviewed: 4}

// widerSuffix ends the rate text of a name whose Denom is wider than its population.
const widerSuffix = " (of a wider population; see help)"

// Candidate is one removal unit with the evidence for its class.
type Candidate struct {
	Name, Scope, Value string // the unit's key; "" is every scope or value
	Area, Kind, Help   string // from the registry, Help unshortened
	Class              string // unused, rare, unused_so_far, not_measured, reviewed
	Count              int64  // the unit's uses in the window
	Denom              int64  // the denominator rows' sum in the window; 0 when it has none
	// Rate is Count over Denom as a fraction (0.005 is 0.5%), 0 when Denom is 0.
	Rate         float64
	RateText     string    // "0.8 per 1,000 loads", "0.49% of requests", "0.50% of upload.mode", or ""
	NoRate       string    // why RateText is "": NoRateDays or NoRateEmpty; "" when there is a rate
	Basis        string    // what the days measured were counted on, as a sentence
	On           CountedOn // the same as a value, for the page to put in its own words
	DaysMeasured int       // days in the window its denominator had rows, a floor over several keys
	LastSeen     time.Time // newest day with a row of the unit in either window; zero if none
	Verdict      string    // the review's, when Class is reviewed
	Note         string    // the review's, when Class is reviewed
	Changes      int64     // setting changes, -1 until phase 2e counts them
	Requests     int64     // requests that ran with a setting, -1 until phase 2e counts them
}

// period is one key's sum over one window period.
type period struct {
	n    int64
	days int // the most days any one contributing row has
}

// series is one key's window periods and the newest day of any period given.
type series struct {
	periods []period
	last    time.Time
}

// index maps every key a row matches, its wildcards included, to its sums.
type index map[Unit]*series

// newIndex sums totals once by key; periods 0 to k-1 are summed, any period sets last.
func newIndex(totals []observability.DayTotal, k int) index {
	idx := index{}
	for _, t := range totals {
		keys := []Unit{
			{t.Name, t.Scope, t.Value},
			{t.Name, "", t.Value},
			{t.Name, t.Scope, ""},
			{t.Name, "", ""},
		}
		for i, key := range keys {
			if slices.Contains(keys[:i], key) {
				continue
			}
			s := idx[key]
			if s == nil {
				s = &series{periods: make([]period, k)}
				idx[key] = s
			}
			if t.Last.After(s.last) {
				s.last = t.Last
			}
			if t.Period >= 0 && t.Period < k {
				p := &s.periods[t.Period]
				p.n += t.N
				p.days = max(p.days, t.Days)
			}
		}
	}
	return idx
}

// window is the key's per-period sums, nil when no row matched it.
func (idx index) window(u Unit) []period {
	if s := idx[u]; s != nil {
		return s.periods
	}
	return nil
}

// denominator is what a candidate name is measured against.
type denominator struct {
	sources []Unit // rows summed for Denom, and whose days are measured
	count   bool   // the sources count something a rate can be taken of
	gate    []Unit // when set, a period's days are capped by the most days any of these has
	ownRows bool   // measured only if the name itself has a row in the window
	basis   string
	on      CountedOn
	word    string // the rate text's last words
}

// The kinds of thing a candidate's days are counted on, CountedOn's Kind.
const (
	OnDenom     = "denom"      // the rows of Name, the candidate's Denom
	OnEveryPage = "every_page" // views of every page, or script loads when Scripts
	OnPages     = "pages"      // views of Pages, or script loads on them when Scripts
	OnFlushDays = "flush_days" // days the counter ran, each with a script load when Scripts
	OnNoRows    = "no_rows"    // the name has no row on this site in the window
)

// CountedOn is what a candidate's days are counted on, for the page to put in words.
type CountedOn struct {
	Kind    string
	Scripts bool   // ui.load rows in place of page.view, or flushed days that had one
	Pages   string // OnPages: the pages, sorted and comma-separated
	Name    string // OnDenom: the Denom
}

// denominatorOf applies the roadmap's rule: Denom, else the Page list, else the flushed days.
func denominatorOf(n observability.Name) denominator {
	ui := n.Family == observability.FamilyUI
	if n.Denom != "" {
		return denominator{sources: []Unit{{Name: n.Denom}}, count: true, basis: n.Denom, word: n.Denom, on: CountedOn{Kind: OnDenom, Name: n.Denom}}
	}
	pages, every := pageList(n.Page)
	switch {
	case every && ui:
		return denominator{sources: []Unit{{Name: "ui.load"}}, count: true, basis: "ui.load on every page", word: "loads", on: CountedOn{Kind: OnEveryPage, Scripts: true}}
	case every:
		return denominator{sources: []Unit{{Name: "page.view"}}, count: true, basis: "page.view on every page", word: "requests", on: CountedOn{Kind: OnEveryPage}}
	case len(pages) > 0:
		slices.Sort(pages)
		pages = slices.Compact(pages)
		d := denominator{count: true, on: CountedOn{Kind: OnPages, Scripts: ui, Pages: strings.Join(pages, ",")}}
		for _, p := range pages {
			if ui {
				d.sources = append(d.sources, Unit{Name: "ui.load", Scope: p})
			} else {
				d.sources = append(d.sources, Unit{Name: "page.view", Value: p})
			}
		}
		if ui {
			d.basis, d.word = "ui.load on "+strings.Join(pages, ","), "loads"
		} else {
			d.basis, d.word = "page.view on "+strings.Join(pages, ","), "requests"
		}
		return d
	case ui:
		return denominator{sources: []Unit{{Name: "metrics.flush"}}, gate: []Unit{{Name: "ui.load"}}, ownRows: true, basis: "days the counter flushed with a ui.load",
			on: CountedOn{Kind: OnFlushDays, Scripts: true}}
	default:
		return denominator{sources: []Unit{{Name: "metrics.flush"}}, ownRows: true, basis: "days the counter flushed", on: CountedOn{Kind: OnFlushDays}}
	}
}

// pageDenominator is a per-page unit's own page, for a ScopePage name with no Denom:
// a unit on one page is rated against that page's views alone, never its whole list.
func pageDenominator(n observability.Name, u Unit) (denominator, bool) {
	if n.Scope != observability.ScopePage || u.Scope == "" || n.Denom != "" {
		return denominator{}, false
	}
	one := n
	one.Page = u.Scope
	return denominatorOf(one), true
}

// What a row with no rate says instead: counted on days, or counted against a base that had no rows.
const (
	NoRateDays  = "no rate, measured in days"
	NoRateEmpty = "no rate: what it is counted against had no rows in this window"
)

// noRate is why a name with this denominator and no rate has none.
func (d denominator) noRate() string {
	if d.count {
		return NoRateEmpty
	}
	return NoRateDays
}

// NoRateText is why a name has no rate when its denominator summed to nothing; see NoRateDays and NoRateEmpty.
func NoRateText(n observability.Name) string {
	return denominatorOf(n).noRate()
}

// noRowsBasis is the Basis of a name measured on flushed days that has no row at all.
const noRowsBasis = "no rows for this name on this site in the window"

// NoRowsBasis is the Basis of a name measured on flushed days that has no row at all.
const NoRowsBasis = noRowsBasis

// hasRows reports whether the name has any row, any scope and value, in the window.
func (idx index) hasRows(name string) bool {
	for _, p := range idx.window(Unit{Name: name}) {
		if p.days > 0 || p.n > 0 {
			return true
		}
	}
	return false
}

// measure sums a denominator over the window: its count (0 without one) and its days measured.
func (d denominator) measure(idx index, k int) (int64, int) {
	var total int64
	days := 0
	for i := range k {
		pd := 0
		for _, u := range d.sources {
			if w := idx.window(u); w != nil {
				total += w[i].n
				pd = max(pd, w[i].days)
			}
		}
		if d.gate != nil {
			gd := 0
			for _, u := range d.gate {
				if w := idx.window(u); w != nil {
					gd = max(gd, w[i].days)
				}
			}
			pd = min(pd, gd)
		}
		days += pd
	}
	if !d.count {
		total = 0
	}
	return total, days
}

// Remove lists the registry's removal candidates that are unused, rare,
// unused so far, not measured or reviewed; units in use are left out.
// totals are DayTotals with Step periodDays over 2*w.Days days, unsplit;
// names have been through Expand; settings are not read before phase 2e.
func Remove(names []observability.Name, settings []observability.Setting,
	totals []observability.DayTotal, reviews []Review, w Window) []Candidate {
	k := windowPeriods(w)
	idx := newIndex(totals, k)
	marks := make(map[Unit]Review, len(reviews))
	for _, r := range reviews {
		marks[Unit{r.Name, r.Scope, r.Value}] = r
	}
	var out []ranked
	for _, n := range names {
		if n.Family == observability.FamilyState || n.Family == observability.FamilyStock {
			continue
		}
		units := Units(n)
		if len(units) == 0 {
			continue
		}
		d := denominatorOf(n)
		denom, days := d.measure(idx, k)
		if d.ownRows && !idx.hasRows(n.Name) {
			// nothing shows the feature runs on this site, so its flushed days are no evidence
			denom, days, d.basis, d.on = 0, 0, noRowsBasis, CountedOn{Kind: OnNoRows}
		}
		_, wider := widerDenom[n.Name]
		for _, u := range units {
			d, denom, days := d, denom, days
			if pd, ok := pageDenominator(n, u); ok {
				d = pd
				denom, days = d.measure(idx, k)
			}
			c := Candidate{
				Name: u.Name, Scope: u.Scope, Value: u.Value,
				Area: n.Area, Kind: n.Kind, Help: n.Help,
				Denom: denom, Basis: d.basis, On: d.on, DaysMeasured: days,
				Changes: -1, Requests: -1,
			}
			for _, p := range idx.window(u) {
				c.Count += p.n
			}
			if s := idx[u]; s != nil {
				c.LastSeen = s.last
			}
			if denom > 0 {
				c.Rate = float64(c.Count) / float64(denom)
				c.RateText = rateText(n.Family == observability.FamilyUI, c.Count, denom, d.word, wider)
			} else {
				c.NoRate = d.noRate()
			}
			c.Class = classify(c, n.Family, wider, marks, w)
			if c.Class == "" {
				continue
			}
			if c.Class == ClassReviewed {
				r := marks[u]
				c.Verdict, c.Note = r.Verdict, r.Note
			}
			out = append(out, ranked{c, underLine(n.Family, c.Count, denom)})
		}
	}
	slices.SortFunc(out, compareRanked)
	if out == nil {
		return nil
	}
	cs := make([]Candidate, len(out))
	for i, r := range out {
		cs[i] = r.Candidate
	}
	return cs
}

// ranked is a candidate with its rate as a share of its family's rare line.
type ranked struct {
	Candidate
	under float64
}

// rareLine is the family's rare line in uses per 1,000 of the denominator.
func rareLine(family observability.Family) int64 {
	if family == observability.FamilyUI {
		return rareLoadsLine
	}
	return rareRequestsLine
}

// underLine is the rate over the family's line: under 1 is rare; 0 without a denominator.
func underLine(family observability.Family, count, denom int64) float64 {
	if denom <= 0 {
		return 0
	}
	return float64(count) * 1000 / (float64(rareLine(family)) * float64(denom))
}

// classify is the first class that fits, or "" for a unit in use.
func classify(c Candidate, family observability.Family, wider bool, marks map[Unit]Review, w Window) string {
	if _, ok := marks[Unit{c.Name, c.Scope, c.Value}]; ok {
		return ClassReviewed
	}
	switch {
	case c.DaysMeasured < minDaysMeasured:
		return ClassNotMeasured
	case c.Count == 0 && c.DaysMeasured >= w.Days:
		return ClassUnused
	case c.Count == 0:
		return ClassUnusedSoFar
	case !wider && isRare(family, c.Count, c.Denom):
		return ClassRare
	}
	return ""
}

// isRare is the family's rare rule; with no count denominator nothing is rare.
func isRare(family observability.Family, count, denom int64) bool {
	if denom <= 0 {
		return false
	}
	return count*1000 < rareLine(family)*denom
}

// rateText prints a rate per 1,000 for a ui. name and as a percent otherwise, rounded down
// so a rare row never prints its line; denom must be positive.
func rateText(ui bool, count, denom int64, word string, wider bool) string {
	steps := count * 10000 / denom // tenths per 1,000, or hundredths of a percent
	var s string
	if ui {
		s = fmt.Sprintf("%d.%d per 1,000 %s", steps/10, steps%10, word)
	} else {
		s = fmt.Sprintf("%d.%02d%% of %s", steps/100, steps%100, word)
	}
	if wider {
		s += widerSuffix
	}
	return s
}

// compareRanked orders by class, then strength within it, then key.
func compareRanked(a, b ranked) int {
	if r := cmp.Compare(classRank[a.Class], classRank[b.Class]); r != 0 {
		return r
	}
	var strength int
	switch a.Class {
	case ClassUnused:
		strength = cmp.Compare(b.Denom, a.Denom)
	case ClassRare:
		strength = cmp.Compare(a.under, b.under)
	case ClassUnusedSoFar:
		strength = cmp.Compare(b.DaysMeasured, a.DaysMeasured)
	}
	return cmp.Or(strength, cmp.Compare(a.Name, b.Name), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
}

// Candidates is Remove over names expanded with l. For another site's instance (foreign) it leaves
// out page-valued candidates with no page views in the window, since a page that site hides looks
// unused from here; a reviewed one stays, so its mark can be seen.
func Candidates(names []observability.Name, l Lists, settings []observability.Setting,
	totals []observability.DayTotal, reviews []Review, w Window, foreign bool) []Candidate {
	candidates := Remove(Expand(names, l), settings, totals, reviews, w)
	if !foreign {
		return candidates
	}
	pageValued := map[string]bool{}
	for _, n := range names {
		if n.Values == observability.ValuePage {
			pageValued[n.Name] = true
		}
	}
	k := windowPeriods(w)
	viewed := map[string]bool{}
	for _, t := range totals {
		if t.Name == pageView && t.Period >= 0 && t.Period < k && t.N > 0 {
			viewed[t.Value] = true
		}
	}
	var out []Candidate
	for _, c := range candidates {
		if pageValued[c.Name] && c.Value != "" && !viewed[c.Value] && c.Class != ClassReviewed {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Measured counts the candidate units of names, which have been through Expand, whose days
// measured reach MinDaysMeasured, so Remove could class them; most is the most days any
// unit short of that has.
func Measured(names []observability.Name, totals []observability.DayTotal, w Window) (measured, most int) {
	units := 0
	for _, n := range names {
		if n.Family != observability.FamilyState && n.Family != observability.FamilyStock {
			units += len(Units(n))
		}
	}
	waiting := 0
	for _, c := range Remove(names, nil, totals, nil, w) {
		if c.Class == ClassNotMeasured {
			waiting++
			most = max(most, c.DaysMeasured)
		}
	}
	return units - waiting, most
}

// Orphans are the reviews no candidate carries: a unit no longer listed, as a hidden page or a
// retired name leaves, so the page can still show and clear the mark. Order is the reviews'.
func Orphans(reviews []Review, candidates []Candidate) []Review {
	listed := make(map[Unit]bool, len(candidates))
	for _, c := range candidates {
		listed[Unit{c.Name, c.Scope, c.Value}] = true
	}
	var out []Review
	for _, r := range reviews {
		if !listed[Unit{r.Name, r.Scope, r.Value}] {
			out = append(out, r)
		}
	}
	return out
}
