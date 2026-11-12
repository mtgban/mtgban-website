package metricsreport

import (
	"cmp"
	"slices"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// topPerSection is how many rows of each section Top takes first.
const topPerSection = 2

// Top takes the strongest n measured rows, two a section, then by order.
// Not-measured rows are skipped; the input is not modified.
func Top(signals []Signal, n int) []Signal {
	if n <= 0 {
		return nil
	}
	taken := make([]bool, len(signals))
	var out []Signal
	for _, section := range SectionOrder() {
		got := 0
		for i, s := range signals {
			if len(out) == n || got == topPerSection {
				break
			}
			if s.Section == section && !s.NotMeasured {
				out = append(out, s)
				taken[i] = true
				got++
			}
		}
	}
	for i, s := range signals {
		if len(out) == n {
			break
		}
		if !taken[i] && !s.NotMeasured {
			out = append(out, s)
		}
	}
	return out
}

// The family labels Coverage gives, in its order.
const (
	CoverageServer   = "Server facts"
	CoverageControls = "Controls"
	CoverageSettings = "Settings"
	CoverageStock    = "Stored state"
)

// FamilyCoverage is how many days of rows one family has behind the reports.
type FamilyCoverage struct {
	Label    string // Server facts, Controls, Settings, Stored state
	Days     int    // days in the window with rows
	Measured bool
	PrevDays int // the same for the window before; Server only
}

// stateReader is the name whose rows show the settings counters run.
const stateReader = "state.reader"

// Coverage always returns the four families, in that order. totals is the
// slice Invest takes; stock is the stored-state load, read only for its days.
func Coverage(totals, stock []observability.DayTotal, w Window) []FamilyCoverage {
	k := windowPeriods(w)
	rows := groupByName(totals)
	server := FamilyCoverage{Label: CoverageServer}
	server.Days, server.PrevDays = WindowDays(totals, w)
	server.Measured = server.Days > 0
	controls := FamilyCoverage{Label: CoverageControls, Days: widestScope(rows[uiLoad], k)}
	controls.Measured = controls.Days > 0
	settings := FamilyCoverage{Label: CoverageSettings, Days: widestScope(rows[stateReader], k)}
	settings.Measured = settings.Days > 0
	stored := FamilyCoverage{Label: CoverageStock, Measured: len(stock) > 0}
	days := map[time.Time]bool{}
	for _, t := range stock {
		days[t.Last] = true
	}
	stored.Days = len(days)
	return []FamilyCoverage{server, controls, settings, stored}
}

// flushDays sums over periods [from, to) the most days any one row of a period has.
func flushDays(rows []observability.DayTotal, from, to int) int {
	per := map[int]int{}
	for _, t := range rows {
		if t.Period >= from && t.Period < to {
			per[t.Period] = max(per[t.Period], t.Days)
		}
	}
	days := 0
	for _, d := range per {
		days += d
	}
	return days
}

// widestScope is the largest per-scope sum of days over the window's periods.
func widestScope(rows []observability.DayTotal, k int) int {
	byScope := map[string][]observability.DayTotal{}
	for _, t := range rows {
		byScope[t.Scope] = append(byScope[t.Scope], t)
	}
	best := 0
	for _, rs := range byScope {
		best = max(best, flushDays(rs, 0, k))
	}
	return best
}

// AreaCount is one registry area's counted events in the window: every option, control and
// signal row summed, so an area that counts several events a view is not comparable with one that counts few.
type AreaCount struct {
	Area   string
	Events int64
}

// notUse are the Signal names that count refusals, errors or the system's own work, not
// a reader using an area: Areas leaves them out, with page.view, which counts every page.
var notUse = map[string]bool{
	"auth.refuse":         true, // requests refused at the door, unauthenticated ones included
	"api.refuse":          true, // API calls refused, by reason
	"ratelimit.reject":    true, // requests a rate limiter refused
	"upload.parse_error":  true, // uploads that could not be read
	"alerts.delivered":    true, // the alert job's deliveries, deferred retries counted again
	"alerts.mail_event":   true, // the mail provider's bounce and complaint webhooks
	"userstate.conflict":  true, // sync writes lost to a newer version
	"favshare.view_gone":  true, // share links opened after they ended
	"ui.offline.sync":     true, // offline syncs, most run at a page load
	"ui.offline.sw":       true, // the service worker's registration when offline mode is switched on
	"ui.offline.failover": true, // the offline shell served for a page the network could not reach
	pageView:              true, // every page's traffic, a candidate in area site
}

// Areas lists the registry's areas by counted events in the window, most first, ties by area,
// to show where the counting is; it is no measure of use. It sums Candidate and Signal names
// only, never a notUse name or a standing count; every area of such a name appears, zero or not.
func Areas(names []observability.Name, totals []observability.DayTotal, w Window) []AreaCount {
	k := windowPeriods(w)
	rows := groupByName(totals)
	uses := map[string]int64{}
	for _, n := range names {
		if n.Report != observability.ReportCandidate && n.Report != observability.ReportSignal {
			continue
		}
		if n.Area == "" || notUse[n.Name] || n.Family == observability.FamilyStock {
			continue
		}
		total := uses[n.Area]
		for _, t := range rows[n.Name] {
			if t.Period >= 0 && t.Period < k {
				total += t.N
			}
		}
		uses[n.Area] = total
	}
	out := make([]AreaCount, 0, len(uses))
	for a, u := range uses {
		out = append(out, AreaCount{Area: a, Events: u})
	}
	slices.SortFunc(out, func(a, b AreaCount) int { return cmp.Or(cmp.Compare(b.Events, a.Events), cmp.Compare(a.Area, b.Area)) })
	return out
}

// StockGroup is one stored-state name's standing count on the newest stock day.
type StockGroup struct {
	Name  string
	Total int64        // the name's own total that day
	Rows  []StockShare // its scopes and values, largest first
}

// StockShare is one scope and value of a stored-state name on that day.
type StockShare struct {
	Scope, Value string
	N            int64
	// Share is N over its group's Total as a fraction (0.25 is 25%), 0 when Total is 0.
	Share float64
}

// Stock reads stored-state rows loaded under observability.SharedInstance with Step 1.
// It keeps only the newest day that has any stock row, and only one-day rows of it,
// so no standing count is summed over days; a bucket with no row is absent, not zero.
// Groups follow the registry's order of its FamilyStock names; day is zero with no rows.
func Stock(names []observability.Name, stock []observability.DayTotal) (day time.Time, groups []StockGroup) {
	for _, t := range stock {
		if t.Last.After(day) {
			day = t.Last
		}
	}
	if day.IsZero() {
		return day, nil
	}
	byStock := map[string][]StockShare{}
	for _, t := range stock {
		if !t.Last.Equal(day) || !t.First.Equal(day) {
			continue
		}
		byStock[t.Name] = append(byStock[t.Name], StockShare{Scope: t.Scope, Value: t.Value, N: t.N})
	}
	for _, n := range names {
		rows := byStock[n.Name]
		if n.Family != observability.FamilyStock || len(rows) == 0 {
			continue
		}
		delete(byStock, n.Name)
		g := StockGroup{Name: n.Name}
		for _, r := range rows {
			g.Total += r.N
		}
		for i := range rows {
			if g.Total > 0 {
				rows[i].Share = float64(rows[i].N) / float64(g.Total)
			}
		}
		slices.SortFunc(rows, func(a, b StockShare) int {
			return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
		})
		g.Rows = rows
		groups = append(groups, g)
	}
	return day, groups
}

// severalPerRow are the stored-state names whose values are not a partition of what they
// count: one reader or row can count under several values, so their parts are no share.
var severalPerRow = map[string]bool{
	"stock.pref":     true, // a reader's row holds several preference keys
	"stock.channels": true, // a reader can hold more than one channel
}

// Partition reports whether a name's parts on one day add up to its whole, so each may be
// shown as a share of it; false for severalPerRow.
func Partition(n observability.Name) bool {
	return !severalPerRow[n.Name]
}
