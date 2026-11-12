package metricsreport

import (
	"maps"
	"slices"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The digest's fixed windows, whatever the page's picker says: candidates over 30 days,
// signals over the last 7 against the 7 before, signed-in humans both.
var (
	digestCandidates = Window{Days: 30, Signed: true, Humans: true}
	digestWeek       = Window{Days: digestWeekDays, Signed: true, Humans: true}
)

// BundleQuery is the totals Remove, Invest and Coverage take for w: Step-30 periods over
// twice the window, ending on to, unsplit.
func BundleQuery(inst string, to time.Time, w Window) observability.DayQuery {
	return observability.DayQuery{Instance: inst, To: to, Days: 2 * w.Days, Step: periodDays, Signed: w.Signed, Humans: w.Humans}
}

// DigestLoads are the queries the digest reads, at its fixed windows; none reads page hits.
type DigestLoads struct {
	Week      observability.DayQuery // the last 14 days in two 7-day periods: signals and counted days
	Devices   observability.DayQuery // the same weeks' page.view rows by device: the phone rows
	Now, Prev observability.DayQuery // 30-day bundles ending on the last day and 7 days before: candidates
}

// DigestQueries are the loads Changes needs, last being the newest folded day.
func DigestQueries(inst string, last time.Time) DigestLoads {
	week := observability.DayQuery{Instance: inst, To: last, Days: 2 * digestWeekDays, Step: digestWeekDays, Signed: true, Humans: true}
	devices := week
	devices.ByDevice, devices.Names = true, []string{pageView}
	return DigestLoads{
		Week: week, Devices: devices,
		Now: BundleQuery(inst, last, digestCandidates), Prev: BundleQuery(inst, last.AddDate(0, 0, -digestWeekDays), digestCandidates),
	}
}

// DigestInput is what DigestLoads returned, with what else the two snapshots carry.
type DigestInput struct {
	Names           []observability.Name // the registry, not expanded
	Lists           Lists
	Settings        []observability.Setting
	Week, Now, Prev []observability.DayTotal // DigestLoads' Week, Now and Prev
	Devices         []observability.DayTotal // DigestLoads' Devices
	Pages           []string                 // the page labels a phone row may name; any other is left out
	HasMobile       func(page string) bool   // whether a page has a mobile template
	Reviews         []Review
	Problems        []string // now's Health lines
	NowErrors       []string // each week's script error labels; nil until 2f fills them
	PrevErrors      []string
	Foreign         bool // another site's instance: see Candidates
}

// DigestSnapshots builds the two snapshots Changes compares from the digest's loads.
func DigestSnapshots(in DigestInput) (now, prev Snapshot) {
	snapshot := func(bundle, week []observability.DayTotal, period int) Snapshot {
		pages := DevicePages(in.Devices, period, in.Pages, in.HasMobile)
		s := Snapshot{
			Candidates: Candidates(in.Names, in.Lists, in.Settings, bundle, in.Reviews, digestCandidates, in.Foreign),
			Signals:    Invest(in.Names, week, pages, digestWeek),
		}
		for _, t := range week {
			if t.Name == flushName && t.Period == 0 {
				s.CounterDays = max(s.CounterDays, t.Days)
			}
		}
		return s
	}
	now = snapshot(in.Now, in.Week, 0)
	now.Problems, now.Errors = in.Problems, in.NowErrors
	prev = snapshot(in.Prev, ShiftPeriods(in.Week, 1), 1)
	prev.Errors = in.PrevErrors
	return now, prev
}

// PageDepths are page hits as Invest's pages, keeping only the labels in pages: a path the
// list does not hold (a catch-all, an old or unbounded one) is left out, never grouped.
// With hasMobile nil every page counts as having a mobile template.
func PageDepths(visits []observability.PageVisit, pages []string, hasMobile func(string) bool) []PageDepth {
	var out []PageDepth
	for _, v := range visits {
		if !slices.Contains(pages, v.Path) {
			continue
		}
		out = append(out, PageDepth{
			Page: v.Path, Views: v.Views, MobileViews: v.MobileViews,
			Visitors: v.Visitors, Once: v.Once, FivePlus: v.FivePlus,
			HasMobile: hasMobile == nil || hasMobile(v.Path),
		})
	}
	return out
}

// DevicePages are one period's page.view rows split by device as Invest's pages, views and
// phone views only, keeping only the labels in pages; the digest's phone rows come from them.
func DevicePages(rows []observability.DayTotal, period int, pages []string, hasMobile func(string) bool) []PageDepth {
	byPage := map[string]*PageDepth{}
	for _, t := range rows {
		if t.Name != pageView || t.Period != period || !slices.Contains(pages, t.Value) {
			continue
		}
		p := byPage[t.Value]
		if p == nil {
			p = &PageDepth{Page: t.Value, HasMobile: hasMobile == nil || hasMobile(t.Value)}
			byPage[t.Value] = p
		}
		p.Views += t.N
		if t.Device == "mobile" {
			p.MobileViews += t.N
		}
	}
	out := make([]PageDepth, 0, len(byPage))
	for _, page := range slices.Sorted(maps.Keys(byPage)) {
		out = append(out, *byPage[page])
	}
	return out
}
