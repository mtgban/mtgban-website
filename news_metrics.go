package main

import (
	"net/http"

	"github.com/mtgban/mtgban-website/observability"
)

// newsRun is what one newspaper report ran with.
type newsRun struct {
	report NewspaperPage
	oneDay bool
	query  newsQuery
	index  int // the clamped page of results, 0 when there were none
}

// newsFacts lists what one report ran with.
func newsFacts(run newsRun) []fact {
	report, q := run.report, run.query
	threeDay := "off"
	if !run.oneDay {
		threeDay = "on"
	}
	facts := []fact{newFact("", "news.report", report.Option), newFact("", "news.three_day", threeDay)}
	for _, h := range report.Head {
		if q.Sort == "" || h.Field != q.Sort {
			continue
		}
		dir := "desc"
		if q.Dir == "asc" {
			dir = "asc"
		}
		facts = append(facts, newFact(dir, "news.sort", h.Field))
		break
	}
	// newsFilter ignores a bound the report has no column for.
	priced, changed := report.Priced != "", report.PercChanged != ""
	for _, f := range []struct {
		on  bool
		key string
	}{
		{q.Rarity != "", "rarity"},
		{q.Bucket != "", "bucket"},
		{q.Finish != "", "finish"},
		{priced && q.MinPrice != nil, "min_price"},
		{priced && q.MaxPrice != nil, "max_price"},
		{changed && q.MinChange != nil, "min_change"},
		{changed && q.MaxChange != nil, "max_change"},
		{q.Set != "", "edition"},
	} {
		if f.on {
			facts = append(facts, newFact("", "news.filter", f.key))
		}
	}
	return append(facts,
		newFact("", "news.page", pageBucket(run.index)),
		newFact("", "news.editions_hidden", observability.Bucket([]int64{1, 5, 20}, int64(len(q.SkipSets)))),
	)
}

// sypSort is news.syp_sort's value; the list's default order is by edition.
func sypSort(sorting string) string {
	switch sorting {
	case "alpha", "available", "sell_price":
		return sorting
	}
	return "edition"
}

// countNews reports whether a newspaper page view will be counted.
func countNews(r *http.Request) bool {
	return FeatureCounter != nil && isPageView(r)
}

// readNewsRun reads what one report ran with, after Paginate.
func readNewsRun(report NewspaperPage, pageVars PageVars, query newsQuery) newsRun {
	return newsRun{report: report, oneDay: pageVars.IsOneDay, query: query, index: pageVars.Pagination.CurrentIndex}
}
