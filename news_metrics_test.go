package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/timeseries"
)

func TestNewsFacts(t *testing.T) {
	report := NewspaperPage{Option: "spike_score", Priced: "current_price", Head: []Heading{{Field: "ranking"}, {Field: "current_price"}}}
	five := 5.0
	got := newsFacts(newsRun{report: report, query: newsQuery{
		Sort: "current_price", Dir: "asc", Rarity: "M", MinPrice: &five, Set: "LEA",
		SkipSets: []string{"A", "B", "C", "D", "E", "F"},
	}, index: 4})
	wantFacts(t, got, []fact{
		newFact("", "news.report", "spike_score"), newFact("", "news.three_day", "on"),
		newFact("asc", "news.sort", "current_price"),
		newFact("", "news.filter", "rarity"), newFact("", "news.filter", "min_price"), newFact("", "news.filter", "edition"),
		newFact("", "news.page", "3-5"), newFact("", "news.editions_hidden", "5-19"),
	})

	// A sort the report has no column for is not a value; no direction means descending.
	plain := newsFacts(newsRun{report: report, oneDay: true, query: newsQuery{Sort: "ck_buy_price"}})
	wantFacts(t, plain, []fact{
		newFact("", "news.report", "spike_score"), newFact("", "news.three_day", "off"),
		newFact("", "news.page", "1"), newFact("", "news.editions_hidden", "0"),
	})
	desc := newsFacts(newsRun{report: report, oneDay: true, query: newsQuery{Sort: "ranking"}, index: 1})
	if desc[2] != newFact("desc", "news.sort", "ranking") {
		t.Errorf("sort fact = %v", desc[2])
	}
}

// Every filter in force counts, in the enum's order; a bound the report has no column for is not in force.
func TestNewsFactsFilters(t *testing.T) {
	one := 1.0
	all := newsQuery{Rarity: "R", Bucket: "$2+", Finish: "Foil", MinPrice: &one, MaxPrice: &one, MinChange: &one, MaxChange: &one, Set: "Bloomburrow"}
	filters := func(report NewspaperPage) []string {
		var out []string
		for _, f := range newsFacts(newsRun{report: report, query: all}) {
			if f.name == "news.filter" {
				out = append(out, f.value)
			}
		}
		return out
	}
	both := NewspaperPage{Option: "greatest_increase_buylist", Priced: "ck_buy_price", PercChanged: "pct_increase_7d"}
	if got, want := filters(both), []string{"rarity", "bucket", "finish", "min_price", "max_price", "min_change", "max_change", "edition"}; !slices.Equal(got, want) {
		t.Errorf("filters %v, want %v", got, want)
	}
	neither := NewspaperPage{Option: "spike_score"}
	if got, want := filters(neither), []string{"rarity", "bucket", "finish", "edition"}; !slices.Equal(got, want) {
		t.Errorf("no bound columns: filters %v, want %v", got, want)
	}
}

func TestSypSort(t *testing.T) {
	for in, want := range map[string]string{
		"alpha": "alpha", "available": "available", "sell_price": "sell_price",
		"": "edition", "edition": "edition", "x": "edition",
	} {
		if got := sypSort(in); got != want {
			t.Errorf("sypSort(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every report and every sortable column is a registry value.
func TestNewsEnumsMatchTheCode(t *testing.T) {
	reports, _ := observability.Lookup("news.report")
	sorts, _ := observability.Lookup("news.sort")
	for _, page := range newspaperPagesInitial {
		if page.Option != "options" && !slices.Contains(reports.Enum, page.Option) {
			t.Errorf("news.report lacks %q", page.Option)
		}
		for _, h := range page.Head {
			if h.Field != "" && !slices.Contains(sorts.Enum, h.Field) {
				t.Errorf("news.sort lacks %q", h.Field)
			}
		}
	}
}

// newsMetricsSite points the newspaper at an unreachable database and caches pages for one test.
func newsMetricsSite(t *testing.T, pages []NewspaperPage) {
	t.Helper()
	withSigMode(t, true, false)
	db, err := timeseries.SQLConfig{Host: "127.0.0.1", Port: 1, User: "none", Password: "none", DBName: "none"}.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	prevDB, prevPages := NewNewspaperDB, newspaperPagesPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB = prevDB
		newspaperPagesPtr.Store(prevPages)
	})
	NewNewspaperDB = db
	newspaperPagesPtr.Store(&pages)
}

// newsGet serves one newspaper request as a page view and returns the rows written.
func newsGet(t *testing.T, query string, dest string) []observability.Row {
	t.Helper()
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodGet, "/newspaper?"+query, nil)
	req.Header.Set("Sec-Fetch-Dest", dest)
	testSite.Newspaper(httptest.NewRecorder(), req)
	return rows.rows()
}

func TestNewspaperReportIsCounted(t *testing.T) {
	var rows []NewspaperResult
	for i := 1; i <= 30; i++ {
		rows = append(rows, NewspaperResult{Ranking: i, UUID: fmt.Sprint("u-", i), Edition: "Bloomburrow", Variant: "Normal", Rarity: "rare", BucketName: "$2+", CurrentPrice: float64(i)})
	}
	newsMetricsSite(t, []NewspaperPage{newsWithRows(t, "spike_score", rows), newsInitialPage(t, "greatest_decrease_listings")})

	// A hand-typed page past the end counts as the last page it was clamped to.
	got := newsGet(t, "page=spike_score&sort=current_price&dir=asc&min_price=2&min_change=5&rarity=R&index=999", "document")
	wantRow(t, got, "", "news.report", "spike_score", 1)
	wantRow(t, got, "", "news.three_day", "off", 1)
	wantRow(t, got, "asc", "news.sort", "current_price", 1)
	wantRow(t, got, "", "news.filter", "min_price", 1)
	wantRow(t, got, "", "news.filter", "rarity", 1)
	wantRow(t, got, "", "news.page", "2", 1)
	wantRow(t, got, "", "news.editions_hidden", "0", 1)
	if n := len(find(got, "news.filter")); n != 2 {
		t.Errorf("news.filter rows = %d, want 2 (spike_score has no change column)", n)
	}

	// The links' empty and zero values are no filter and no sort.
	links := newsGet(t, "page=spike_score&sort=&dir=&index=&filter=&rarity=&min_price=0&max_price=0&min_change=0&max_change=0&bucket=&finish=", "document")
	wantRow(t, links, "", "news.page", "1", 1)
	wantNoRow(t, links, "news.filter")
	wantNoRow(t, links, "news.sort")

	t.Run("index", func(t *testing.T) {
		got := newsGet(t, "", "document")
		wantRow(t, got, "", "news.report", "index", 1)
		wantNoRow(t, got, "news.page")
	})
	t.Run("a fetch is no page view", func(t *testing.T) {
		wantNoRow(t, newsGet(t, "page=spike_score", "empty"), "news.report")
	})
	t.Run("not ready and unknown pages count nothing", func(t *testing.T) {
		wantNoRow(t, newsGet(t, "page=greatest_decrease_listings", "document"), "news.report")
		wantNoRow(t, newsGet(t, "page=nope", "document"), "news.report")
	})
}

// A reader the page turns away counts nothing.
func TestNewspaperRefusalIsNotCounted(t *testing.T) {
	withSigMode(t, true, false)
	prevDB := NewNewspaperDB
	t.Cleanup(func() { NewNewspaperDB = prevDB })
	NewNewspaperDB = nil
	got := newsGet(t, "", "document")
	wantNoRow(t, got, "news.report")
}

func TestNewspaperSYPIsCounted(t *testing.T) {
	newsMetricsSite(t, nil)
	withPrices(t, nil, []mtgban.Vendor{mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "SYP", Shorthand: "SYP"})})

	list := newsGet(t, "page=syp&sort=available", "document")
	wantRow(t, list, "", "news.report", "syp", 1)
	wantRow(t, list, "", "news.syp_sort", "available", 1)
	wantNoRow(t, list, "news.syp_csv")

	def := newsGet(t, "page=syp", "document")
	wantRow(t, def, "", "news.syp_sort", "edition", 1)

	// A download is counted whatever its fetch destination.
	csv := newsGet(t, "page=syp&format=csv", "empty")
	wantRow(t, csv, "", "news.syp_csv", "", 1)
	wantNoRow(t, csv, "news.report")
}
