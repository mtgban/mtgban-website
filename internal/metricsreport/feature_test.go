package metricsreport

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

func TestNameUse(t *testing.T) {
	w := Window{Days: 30, Signed: true, Humans: true}
	totals := []observability.DayTotal{
		{Period: 0, Name: "search.sort", Scope: "search", Value: "alpha", N: 3, Days: 2},
		{Period: 0, Name: "search.sort", Scope: "sets", Value: "price", N: 2, Days: 2},
		{Period: 1, Name: "search.sort", Value: "alpha", N: 500, Days: 30}, // the window before
		{Period: 0, Name: "search.result", Value: "found", N: 1000, Days: 30},
		{Period: 0, Name: "page.view", Value: "sets", N: 400, Days: 30},
		{Period: 0, Name: "page.view", Value: "search", N: 600, Days: 30},
		{Period: 0, Name: "upload.option", Value: "lowval", N: 10, Days: 30},
		{Period: 0, Name: "upload.mode", Value: "buylist", N: 100, Days: 30},
		{Period: 0, Name: "metrics.flush", N: 1440, Days: 30},
		{Period: 0, Name: "patreon.webhook", N: 4, Days: 3},
		{Period: 0, Name: "stock.rows", N: 999, Days: 30},
	}
	for _, c := range []struct {
		n    observability.Name
		want Use
	}{
		{observability.Name{Name: "search.sort", Denom: "search.result"}, Use{Count: 5, Denom: 1000, Rate: 0.005, RateText: "0.50% of search.result"}},
		{observability.Name{Name: "search.sort", Page: "sets"}, Use{Count: 5, Denom: 400, Rate: 5.0 / 400, RateText: "1.25% of requests"}},
		{observability.Name{Name: "upload.option", Denom: "upload.mode"}, Use{Count: 10, Denom: 100, Rate: 0.1, RateText: "10.00% of upload.mode (of a wider population; see help)"}},
		{observability.Name{Name: "patreon.webhook"}, Use{Count: 4, NoRate: NoRateDays}},
		{observability.Name{Name: "search.sort", Denom: "search.missing"}, Use{Count: 5, NoRate: NoRateEmpty}},
		{observability.Name{Name: "stock.rows", Family: observability.FamilyStock}, Use{}},
	} {
		if got := NameUse(c.n, totals, w); got != c.want {
			t.Errorf("NameUse(%+v) = %+v, want %+v", c.n, got, c.want)
		}
	}
	if got := NameUse(observability.Name{Name: "search.sort"}, nil, w); got != (Use{NoRate: NoRateDays}) {
		t.Errorf("no rows: %+v", got)
	}
}

func TestNoRateText(t *testing.T) {
	ui := observability.FamilyUI
	for _, c := range []struct {
		n    observability.Name
		want string
	}{
		{observability.Name{Name: "patreon.webhook"}, NoRateDays},
		{observability.Name{Name: "go.click", Family: ui}, NoRateDays},
		{observability.Name{Name: "bot.cmd", Page: " , "}, NoRateDays},
		{observability.Name{Name: "search.sort", Page: "*"}, NoRateEmpty},
		{observability.Name{Name: "go.click", Family: ui, Page: "*"}, NoRateEmpty},
		{observability.Name{Name: "search.view", Page: "search"}, NoRateEmpty},
		{observability.Name{Name: "search.sort", Denom: "search.result"}, NoRateEmpty},
	} {
		if got := NoRateText(c.n); got != c.want {
			t.Errorf("NoRateText(%+v) = %q, want %q", c.n, got, c.want)
		}
	}
}

// A candidate with no rate carries the same words NameUse gives; one with a rate carries none.
func TestRemoveSaysWhyARowHasNoRate(t *testing.T) {
	w := Window{Days: 30}
	names := []observability.Name{
		{Name: "search.sort", Report: observability.ReportCandidate, Kind: "option", Denom: "search.result"},
		{Name: "bot.cmd", Report: observability.ReportCandidate, Kind: "control"},
		{Name: "go.view", Report: observability.ReportCandidate, Kind: "control", Page: "*"},
	}
	totals := []observability.DayTotal{
		{Period: 0, Name: "metrics.flush", N: 1440, Days: 30},
		{Period: 0, Name: "bot.cmd", N: 0, Days: 30},
		{Period: 0, Name: "page.view", Value: "search", N: 900, Days: 30},
	}
	got := map[string]string{}
	for _, c := range Remove(names, nil, totals, nil, w) {
		got[c.Name] = c.NoRate
		if (c.RateText == "") == (c.NoRate == "") {
			t.Errorf("%s: rate %q, no rate %q", c.Name, c.RateText, c.NoRate)
		}
		if c.NoRate != NameUse(names[slices.IndexFunc(names, func(n observability.Name) bool { return n.Name == c.Name })], totals, w).NoRate {
			t.Errorf("%s: Remove and NameUse disagree", c.Name)
		}
	}
	if got["search.sort"] != NoRateEmpty || got["bot.cmd"] != NoRateDays || got["go.view"] != "" {
		t.Errorf("no rate = %v", got)
	}
}
