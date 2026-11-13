package metricsreport

import (
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The digest's loads are fixed: a 14-day week query and two 30-day bundles a week apart, signed-in humans.
func TestDigestQueries(t *testing.T) {
	last := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	got := DigestQueries("magic", last)
	if got.Week.Instance != "magic" || !got.Week.To.Equal(last) || got.Week.Days != 14 || got.Week.Step != 7 || !got.Week.Signed || !got.Week.Humans {
		t.Errorf("week = %+v", got.Week)
	}
	for name, q := range map[string]observability.DayQuery{"now": got.Now, "prev": got.Prev} {
		if q.Days != 60 || q.Step != 30 || !q.Signed || !q.Humans || q.Instance != "magic" || q.ByTier || q.ByDevice || q.Names != nil {
			t.Errorf("%s = %+v", name, q)
		}
	}
	if !got.Now.To.Equal(last) || !got.Prev.To.Equal(last.AddDate(0, 0, -7)) {
		t.Errorf("bundles end on %v and %v", got.Now.To, got.Prev.To)
	}
	if d := got.Devices; !d.ByDevice || len(d.Names) != 1 || d.Names[0] != "page.view" || d.Days != 14 || d.Step != 7 || !d.To.Equal(last) || !d.Signed || !d.Humans {
		t.Errorf("devices = %+v", d)
	}
	if b := BundleQuery("magic", last, Window{Days: 90, Signed: true}); b.Days != 180 || b.Step != 30 || !b.Signed || b.Humans {
		t.Errorf("bundle = %+v", b)
	}
}

// For another site, an unviewed page is left out unless it carries a review mark.
func TestCandidatesLeaveOutAnotherSitesUnviewedPages(t *testing.T) {
	names := []observability.Name{{Name: "page.view", Values: observability.ValuePage, Report: observability.ReportCandidate, Unit: observability.UnitValue, Kind: "page", Help: "h"},
		{Name: "metrics.flush", Report: observability.ReportInternal}}
	l := Lists{Pages: []string{"alerts", "search", "sets"}}
	totals := []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30), tot(0, "page.view", "", "search", 900, 30), tot(1, "page.view", "", "alerts", 3, 3)}
	pages := func(cs []Candidate) map[string]string {
		out := map[string]string{}
		for _, c := range cs {
			out[c.Value] = c.Class
		}
		return out
	}
	own := pages(Candidates(names, l, nil, totals, nil, w30, false))
	if own["alerts"] != ClassUnused || own["sets"] != ClassUnused {
		t.Errorf("own site: %v", own)
	}
	other := pages(Candidates(names, l, nil, totals, nil, w30, true))
	if _, ok := other["alerts"]; ok || len(other) != 0 {
		t.Errorf("another site lists unviewed pages: %v", other)
	}
	marked := pages(Candidates(names, l, nil, totals, []Review{{Name: "page.view", Value: "sets", Verdict: "keep"}}, w30, true))
	if marked["sets"] != ClassReviewed || len(marked) != 1 {
		t.Errorf("a reviewed page stays: %v", marked)
	}
}

// Every denominator kind says what it is as a value, the page building its words from it.
func TestCountedOnByDenominator(t *testing.T) {
	ui := observability.FamilyUI
	cases := []struct {
		n    observability.Name
		want CountedOn
	}{
		{observability.Name{Denom: "upload.mode"}, CountedOn{Kind: OnDenom, Name: "upload.mode"}},
		{observability.Name{Page: "*"}, CountedOn{Kind: OnEveryPage}},
		{observability.Name{Page: "*", Family: ui}, CountedOn{Kind: OnEveryPage, Scripts: true}},
		{observability.Name{Page: "search, alerts,search"}, CountedOn{Kind: OnPages, Pages: "alerts,search"}},
		{observability.Name{Page: "arbit", Family: ui}, CountedOn{Kind: OnPages, Scripts: true, Pages: "arbit"}},
		{observability.Name{}, CountedOn{Kind: OnFlushDays}},
		{observability.Name{Family: ui}, CountedOn{Kind: OnFlushDays, Scripts: true}},
	}
	for _, tc := range cases {
		if got := denominatorOf(tc.n).on; got != tc.want {
			t.Errorf("%+v: %+v, want %+v", tc.n, got, tc.want)
		}
	}
	names := []observability.Name{option("discord.store_link", "", "tcg")}
	if got := Remove(names, nil, []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 30)}, nil, w30); len(got) != 1 || got[0].On != (CountedOn{Kind: OnNoRows}) {
		t.Errorf("no rows: %+v", got)
	}
}

// Page hits keep only the listed labels: a stray path is left out, not grouped.
func TestPageDepthsKeepOnlyListedPages(t *testing.T) {
	visits := []observability.PageVisit{{Path: "search", Views: 9, Visitors: 3}, {Path: "other", Views: 5}, {Path: "admin/<b>", Views: 7}, {Path: "arbit", Views: 4, MobileViews: 2}}
	got := PageDepths(visits, []string{"arbit", "search"}, func(p string) bool { return p == "search" })
	if len(got) != 2 || got[0].Page != "search" || !got[0].HasMobile || got[1].Page != "arbit" || got[1].HasMobile || got[1].MobileViews != 2 {
		t.Errorf("got %+v", got)
	}
}

// The digest's phone rows come from page.view by device, one period at a time, listed labels only.
func TestDevicePages(t *testing.T) {
	rows := []observability.DayTotal{
		{Period: 0, Name: "page.view", Value: "arbit", Device: "mobile", N: 30},
		{Period: 0, Name: "page.view", Value: "arbit", Device: "desktop", N: 70},
		{Period: 1, Name: "page.view", Value: "arbit", Device: "mobile", N: 5},
		{Period: 0, Name: "page.view", Value: "/wp-login.php", Device: "mobile", N: 500},
		{Period: 0, Name: "search.result", Value: "arbit", Device: "mobile", N: 9},
	}
	got := DevicePages(rows, 0, []string{"arbit"}, func(string) bool { return false })
	if len(got) != 1 || got[0] != (PageDepth{Page: "arbit", Views: 100, MobileViews: 30}) {
		t.Errorf("period 0: %+v", got)
	}
	if got := DevicePages(rows, 1, []string{"arbit"}, nil); len(got) != 1 || got[0].MobileViews != 5 || !got[0].HasMobile {
		t.Errorf("period 1: %+v", got)
	}
	// and the digest moves on them: a page phones reached three times more
	in := DigestInput{Names: investNames(), Devices: append(rows, observability.DayTotal{Period: 1, Name: "page.view", Value: "arbit", Device: "desktop", N: 95}),
		Pages: []string{"arbit"}, HasMobile: func(string) bool { return false },
		Week: []observability.DayTotal{tot(0, "metrics.flush", "", "", 1, 7), tot(1, "metrics.flush", "", "", 1, 7)}}
	now, prev := DigestSnapshots(in)
	if m := section(now.Signals, SectionMobile); len(m) != 1 || m[0].Count != 30 || len(section(prev.Signals, SectionMobile)) != 1 {
		t.Errorf("now %+v prev %+v", now.Signals, prev.Signals)
	}
}
