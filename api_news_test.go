package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newsFixtureNow is the fixture clock: 07:00 on the host's clock, two hours and 33 minutes before a refresh.
var newsFixtureNow = time.Date(2026, 10, 13, 7, 0, 0, 0, time.Local)

// newsCalcDate is the fixture rows' calc_date as the database driver hands it over.
const newsCalcDate = "2026-10-13T00:00:00Z"

// newsSpikeRows are spike_score's fixture rows, in ranking order.
func newsSpikeRows() []NewspaperResult {
	return []NewspaperResult{
		{Date: newsCalcDate, UUID: "u-ragavan", Ranking: 1, CardName: "Ragavan, Nimble Pilferer", Edition: "Modern Horizons 2", Number: "138", Variant: "Normal", Rarity: "mythic", BucketName: "$50+", BucketRank: 1, CurrentPrice: 64.99},
		{Date: newsCalcDate, UUID: "u-fable", Ranking: 2, CardName: "Fable of the Mirror-Breaker", Edition: "Kamigawa: Neon Dynasty", Number: "141", Variant: "Foil", Rarity: "rare", BucketName: "$20+", BucketRank: 1, CurrentPrice: 24.5},
		{Date: newsCalcDate, UUID: "u-llanowar", Ranking: 3, CardName: "Llanowar Elves", Edition: "Dominaria", Number: "168", Variant: "Normal", Rarity: "common", BucketName: "$2+", BucketRank: 2, CurrentPrice: 2.25},
		{Date: newsCalcDate, UUID: "u-counterspell", Ranking: 4, CardName: "Counterspell", Edition: "Modern Horizons 2", Number: "267", Variant: "Normal", Rarity: "uncommon", BucketName: "$2+", BucketRank: 1, CurrentPrice: 3.1},
	}
}

// newsListingRows are greatest_increase_listings' fixture rows, in ranking order; changes are fractions.
func newsListingRows() []NewspaperResult {
	return []NewspaperResult{
		{Date: newsCalcDate, UUID: "u-solring", Ranking: 1, CardName: "Sol Ring", Edition: "Commander Masters", Number: "395", Variant: "Normal", Rarity: "uncommon", SellersToday: 120, SellersLastWeek: 80, SellersMonthAgo: 60, WeeklyPctChange: 0.5},
		{Date: newsCalcDate, UUID: "u-brainstorm", Ranking: 2, CardName: "Brainstorm", Edition: "Mercadian Masques", Number: "58", Variant: "Normal", Rarity: "common", SellersToday: 40, SellersLastWeek: 30, SellersMonthAgo: 5, WeeklyPctChange: 0.3333},
		{Date: newsCalcDate, UUID: "u-thoughtseize", Ranking: 3, CardName: "Thoughtseize", Edition: "Theros", Number: "107", Variant: "Foil", Rarity: "rare", SellersToday: 12, SellersLastWeek: 11, SellersMonthAgo: 10, WeeklyPctChange: 0.0909},
	}
}

// newsCombinedRows are combined_spike_score's fixture rows, a report Magic alone shows.
func newsCombinedRows() []NewspaperResult {
	return []NewspaperResult{
		{Date: newsCalcDate, UUID: "u-sheoldred", Ranking: 1, CardName: "Sheoldred, the Apocalypse", Edition: "Dominaria United", Number: "107", Variant: "Normal", Rarity: "mythic", BucketName: "$50+", BucketRank: 1, CKRetailPrice: 89.99, TCGMarketPrice: 79.5, CKBuyPrice: 60},
	}
}

// withNewsPages publishes pages refreshed at refreshed, on a clock stopped at newsFixtureNow.
func withNewsPages(t *testing.T, pages []NewspaperPage, refreshed time.Time) {
	t.Helper()
	prevPages, prevUpdate, prevNow := newspaperPagesPtr.Load(), lastNewspaperUpdatePtr.Load(), newsNow
	t.Cleanup(func() {
		newspaperPagesPtr.Store(prevPages)
		lastNewspaperUpdatePtr.Store(prevUpdate)
		newsNow = prevNow
	})
	newspaperPagesPtr.Store(&pages)
	SetLastNewspaperUpdate(refreshed)
	newsNow = func() time.Time { return newsFixtureNow }
}

// withNewsFixture publishes three reports with rows, one empty report and the settings entry.
func withNewsFixture(t *testing.T, refreshed time.Time) {
	t.Helper()
	withNewsPages(t, []NewspaperPage{
		newsWithRows(t, "combined_spike_score", newsCombinedRows()),
		newsWithRows(t, "spike_score", newsSpikeRows()),
		newsWithRows(t, "greatest_increase_listings", newsListingRows()),
		newsInitialPage(t, "greatest_decrease_listings"),
		newsInitialPage(t, "options"),
	}, refreshed)
}

// newsServe calls the handler with signing on and a signature granting modes.
func newsServe(t *testing.T, target, modes string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	signingEnabled(t, false)
	sig := signedAs(t, url.Values{"APImode": {modes}, "UserEmail": {"n@example.com"}}, time.Now().Add(time.Hour))
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	req := httptest.NewRequest(http.MethodGet, target+sep+"sig="+url.QueryEscape(sig), nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	testSite.NewspaperAPI(rec, req)
	return rec
}

type newsReportsOut struct {
	Meta    newsListMeta `json:"meta"`
	Reports []newsReport `json:"reports"`
}

type newsRowOut struct {
	Ranking int `json:"ranking"`
}

type newsReportOut struct {
	Error string         `json:"error"`
	Meta  newsReportMeta `json:"meta"`
	Rows  []newsRowOut   `json:"rows"`
}

// rankings lists the rows' rankings in order.
func (o newsReportOut) rankings() []int {
	out := []int{}
	for _, r := range o.Rows {
		out = append(out, r.Ranking)
	}
	return out
}

// newsGetReport calls the handler with the newspaper mode and decodes the JSON body.
func newsGetReport(t *testing.T, target string) (*httptest.ResponseRecorder, newsReportOut) {
	t.Helper()
	rec := newsServe(t, target, "newspaper", nil)
	var out newsReportOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v\n%s", target, err, rec.Body.String())
	}
	return rec, out
}

// The page's stale rule: refreshed, and 12 hours or more ago.
func TestNewsStale(t *testing.T) {
	for _, tc := range []struct {
		refreshed time.Time
		want      bool
	}{
		{time.Time{}, false},
		{newsFixtureNow.Add(-11*time.Hour - 59*time.Minute), false},
		{newsFixtureNow.Add(-12 * time.Hour), true},
		{newsFixtureNow.Add(-30 * time.Hour), true},
	} {
		if got := newsStale(tc.refreshed, newsFixtureNow); got != tc.want {
			t.Errorf("newsStale(%s) = %t, want %t", tc.refreshed, got, tc.want)
		}
	}
}

// reports.json lists the shown reports in the page's order, each with its
// columns, filters and values; the buylist report is Magic's alone.
func TestNewspaperAPIReports(t *testing.T) {
	withConfigCopy(t)
	Config().Game = DefaultGame
	refreshed := newsFixtureNow.Add(-27 * time.Minute)
	withNewsFixture(t, refreshed)

	rec := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	var out newsReportsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Meta.Latest != "2026-10-13" || out.Meta.Refreshed != refreshed.UTC().Format(time.RFC3339) || out.Meta.Stale {
		t.Errorf("meta %+v", out.Meta)
	}
	var keys []string
	for _, r := range out.Reports {
		keys = append(keys, r.Key)
	}
	if want := []string{"combined_spike_score", "spike_score", "greatest_increase_listings", "greatest_decrease_listings"}; !slices.Equal(keys, want) {
		t.Fatalf("reports %v, want %v", keys, want)
	}

	spike := out.Reports[1]
	wantCols := []newsColumn{
		{Field: "ranking", Title: "Ranking", Kind: "number", Sortable: true},
		{Field: "bucket_name", Title: "Bucket", Kind: "text", Sortable: true},
		{Field: "bucket_rank", Title: "Bucket Rank", Kind: "number", Sortable: true},
		{Field: "current_price", Title: "Current Price", Kind: "dollar", Sortable: true},
	}
	if !slices.Equal(spike.Columns, wantCols) {
		t.Errorf("spike columns %+v", spike.Columns)
	}
	if spike.Title != "Top Singles by Spike Score" || spike.Description != newsInitialPage(t, "spike_score").Desc || spike.Rows != 4 {
		t.Errorf("spike %+v", spike)
	}
	if !slices.Equal(spike.Filters, []string{"set", "rarity", "finish", "bucket", "min_price", "max_price"}) {
		t.Errorf("spike filters %v", spike.Filters)
	}
	if !slices.Equal(spike.Sets, []string{"Dominaria", "Kamigawa: Neon Dynasty", "Modern Horizons 2"}) {
		t.Errorf("spike sets %v", spike.Sets)
	}
	if !slices.Equal(spike.Finishes, []string{"Foil", "Normal"}) {
		t.Errorf("spike finishes %v", spike.Finishes)
	}
	if !slices.Equal(spike.Buckets, []string{"$2+", "$5+", "$10+", "$20+", "$35+", "$50+", "$75+"}) {
		t.Errorf("spike buckets %v", spike.Buckets)
	}

	listings := out.Reports[2]
	wantListCols := []newsColumn{
		{Field: "ranking", Title: "Ranking", Kind: "number", Sortable: true},
		{Field: "sellers_Today", Title: "Today's Sellers", Kind: "number", Sortable: true},
		{Field: "sellers_d7", Title: "Last Week Sellers", Kind: "number", Sortable: true},
		{Field: "sellers_d30", Title: "Month Ago Sellers", Kind: "number", Sortable: true},
		{Field: "pct_gain_7d", Title: "Weekly % Change", Kind: "percent", Sortable: true},
	}
	if !slices.Equal(listings.Columns, wantListCols) {
		t.Errorf("listings columns %+v", listings.Columns)
	}
	if !slices.Equal(listings.Filters, []string{"set", "rarity", "finish", "min_change", "max_change"}) || listings.Buckets != nil {
		t.Errorf("listings filters %v buckets %v", listings.Filters, listings.Buckets)
	}
	if !slices.Equal(out.Reports[0].Filters, []string{"set", "rarity", "finish", "bucket", "min_price", "max_price"}) {
		t.Errorf("combined filters %v", out.Reports[0].Filters)
	}

	Config().Game = "lorcana"
	rec = newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	out = newsReportsOut{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	keys = nil
	for _, r := range out.Reports {
		keys = append(keys, r.Key)
	}
	if want := []string{"spike_score", "greatest_increase_listings", "greatest_decrease_listings"}; !slices.Equal(keys, want) {
		t.Errorf("lorcana reports %v, want %v", keys, want)
	}
}

// A shown report whose query never succeeded lists with no rows and answers a 503 to retry.
func TestNewspaperAPIUnloadedReport(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-27*time.Minute))
	rec := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	var list newsReportsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body.String())
	}
	i := slices.IndexFunc(list.Reports, func(r newsReport) bool { return r.Key == "greatest_decrease_listings" })
	if i < 0 {
		t.Fatalf("not listed: %s", rec.Body.String())
	}
	if r := list.Reports[i]; r.Rows != 0 || r.Sets == nil || len(r.Sets) != 0 || r.Finishes == nil || len(r.Finishes) != 0 || len(r.Columns) == 0 {
		t.Errorf("unloaded entry %+v", r)
	}
	for _, path := range []string{"greatest_decrease_listings.json", "greatest_decrease_listings.csv", "greatest_decrease_listings.json?set=Alpha"} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+path)
		h := rec.Header()
		if rec.Code != http.StatusServiceUnavailable || out.Error != "report not loaded yet" || h.Get("Retry-After") != "300" ||
			h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q Retry-After %q Cache-Control %q", path, rec.Code, out.Error, h.Get("Retry-After"), h.Get("Cache-Control"))
		}
	}
}

// A report whose query ran and returned no rows is loaded: it lists with no
// rows and answers an empty page, not the 503 a never-loaded one does.
func TestNewspaperAPIEmptyReport(t *testing.T) {
	empty := newsInitialPage(t, "greatest_decrease_listings")
	empty.Loaded = true
	withNewsPages(t, []NewspaperPage{
		newsWithRows(t, "spike_score", newsSpikeRows()),
		empty,
		newsInitialPage(t, "options"),
	}, newsFixtureNow.Add(-27*time.Minute))

	rec := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	var list newsReportsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body.String())
	}
	i := slices.IndexFunc(list.Reports, func(r newsReport) bool { return r.Key == "greatest_decrease_listings" })
	if i < 0 || list.Reports[i].Rows != 0 || len(list.Reports[i].Sets) != 0 {
		t.Errorf("empty report listed as %+v", list.Reports)
	}

	rec, out := newsGetReport(t, "/api/v2/newspaper/greatest_decrease_listings.json")
	h := rec.Header()
	if rec.Code != http.StatusOK || out.Error != "" || out.Meta.Rows != 0 || out.Meta.Page != 1 || out.Meta.Pages != 1 || out.Meta.Date != "" ||
		!strings.Contains(rec.Body.String(), `"rows":[]`) || h.Get("Retry-After") != "" || !strings.HasPrefix(h.Get("Cache-Control"), "public") {
		t.Errorf("json: %d %+v Retry-After %q Cache-Control %q\n%s", rec.Code, out.Meta, h.Get("Retry-After"), h.Get("Cache-Control"), rec.Body.String())
	}

	rec = newsServe(t, "/api/v2/newspaper/greatest_decrease_listings.csv", "newspaper", nil)
	h = rec.Header()
	if lines := strings.Split(strings.TrimRight(rec.Body.String(), "\r\n"), "\n"); rec.Code != http.StatusOK || len(lines) != 1 ||
		!strings.HasPrefix(lines[0], "ranking,id,name,set,number,finish,rarity,") {
		t.Errorf("csv: %d %q", rec.Code, rec.Body.String())
	}
	if _, ok := h["X-Mtgban-Date"]; ok || h.Get("X-MTGBAN-Rows") != "0" || h.Get("X-MTGBAN-Pages") != "1" || h.Get("Retry-After") != "" {
		t.Errorf("csv headers: %v", h)
	}

	if rec, out := newsGetReport(t, "/api/v2/newspaper/greatest_decrease_listings.json?set=Alpha"); rec.Code != http.StatusBadRequest || out.Error == "" {
		t.Errorf("set outside an empty list: %d %q", rec.Code, out.Error)
	}
}

// A game whose every report loaded empty serves its list and empty pages, not the empty-cache 503.
func TestNewspaperAPIAllReportsEmpty(t *testing.T) {
	var pages []NewspaperPage
	for _, page := range newspaperPagesInitial {
		if page.Query != "" {
			page.Loaded = true
		}
		pages = append(pages, page)
	}
	withNewsPages(t, pages, time.Time{})
	rec := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"latest":""`) {
		t.Errorf("reports.json: %d %s", rec.Code, rec.Body.String())
	}
	if rec, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json"); rec.Code != http.StatusOK || out.Meta.Rows != 0 {
		t.Errorf("spike_score.json: %d %+v", rec.Code, out)
	}
}

// An absent value is null in JSON and an empty cell in CSV, and fails a bound on its column.
func TestNewspaperAPIAbsentValue(t *testing.T) {
	bare := NewspaperResult{Date: newsCalcDate, UUID: "u-bare", Ranking: 5, CardName: "Bare", Edition: "Dominaria", Number: "1", Variant: "Normal", Rarity: "rare", BucketName: "$2+"}
	withNewsPages(t, []NewspaperPage{newsWithRows(t, "spike_score", append(newsSpikeRows(), bare))}, newsFixtureNow.Add(-27*time.Minute))

	rec, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"bucket_name":"$2+","bucket_rank":null,"current_price":null}`) {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
	if got := out.rankings(); !slices.Equal(got, []int{1, 2, 3, 4, 5}) {
		t.Errorf("no bound: rankings %v", got)
	}
	csv := newsServe(t, "/api/v2/newspaper/spike_score.csv", "newspaper", nil)
	if !strings.HasSuffix(csv.Body.String(), "\n5,u-bare,Bare,Dominaria,1,Normal,rare,$2+,,\n") {
		t.Errorf("CSV:\n%s", csv.Body.String())
	}
	if _, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json?min_price=0"); !slices.Equal(out.rankings(), []int{1, 2, 3, 4}) {
		t.Errorf("min_price=0: rankings %v", out.rankings())
	}
}

// A report is its rows in ranking order, each keyed ranking, the card fields,
// then the report's columns, numbers as numbers; hidden fields never appear.
func TestNewspaperAPIReportShape(t *testing.T) {
	refreshed := newsFixtureNow.Add(-27 * time.Minute)
	withNewsFixture(t, refreshed)

	rec, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json")
	if rec.Code != http.StatusOK || out.Error != "" {
		t.Fatalf("status %d error %q", rec.Code, out.Error)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	m := out.Meta
	if m.Report != "spike_score" || m.Title != "Top Singles by Spike Score" || m.Date != "2026-10-13" ||
		m.Refreshed != refreshed.UTC().Format(time.RFC3339) || m.Stale || m.Rows != 4 || len(m.Columns) != 4 {
		t.Errorf("meta %+v", m)
	}
	if got := out.rankings(); !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Errorf("rankings %v", got)
	}
	body := rec.Body.String()
	const first = `{"ranking":1,"id":"u-ragavan","name":"Ragavan, Nimble Pilferer","set":"Modern Horizons 2","number":"138","finish":"Normal","rarity":"mythic","bucket_name":"$50+","bucket_rank":1,"current_price":64.99}`
	if !strings.Contains(body, `"rows":[`+first+`,`) {
		t.Errorf("first row is not %s\n%s", first, body)
	}
	for _, key := range []string{`"product_name"`, `"Tier"`, `"Recent_BL"`, `"Date"`, `"UUID"`} {
		if strings.Contains(body, key) {
			t.Errorf("body carries %s", key)
		}
	}

	rec, _ = newsGetReport(t, "/api/v2/newspaper/greatest_increase_listings.json")
	if !strings.Contains(rec.Body.String(), `"rarity":"uncommon","sellers_Today":120,"sellers_d7":80,"sellers_d30":60,"pct_gain_7d":50}`) {
		t.Errorf("listings row keys\n%s", rec.Body.String())
	}
}

// Every option on {report}.json, alone and together, and a filter matching nothing.
func TestNewspaperAPIOptions(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-27*time.Minute))
	for _, tc := range []struct {
		query string
		want  []int
	}{
		{"spike_score.json", []int{1, 2, 3, 4}},
		{"spike_score.json?sort=current_price", []int{1, 2, 4, 3}},
		{"spike_score.json?sort=current_price&dir=asc", []int{3, 4, 2, 1}},
		{"spike_score.json?sort=ranking&dir=desc", []int{4, 3, 2, 1}},
		{"spike_score.json?sort=name&dir=asc", []int{4, 2, 3, 1}},
		{"spike_score.json?sort=set&dir=asc", []int{3, 2, 1, 4}},
		{"spike_score.json?sort=number", []int{4, 3, 2, 1}},
		{"spike_score.json?sort=finish", []int{1, 3, 4, 2}},
		{"spike_score.json?sort=bucket_rank&dir=asc", []int{1, 2, 4, 3}},
		{"spike_score.json?sort=bucket_name&dir=asc", []int{3, 4, 2, 1}},
		{"spike_score.json?set=Modern%20Horizons%202", []int{1, 4}},
		{"spike_score.json?rarity=M", []int{1}},
		{"spike_score.json?rarity=M%2FR", []int{1, 2}},
		{"spike_score.json?rarity=U/C", []int{3, 4}},
		{"spike_score.json?rarity=C", []int{3}},
		{"spike_score.json?finish=Foil", []int{2}},
		{"spike_score.json?bucket=%242%2B", []int{3, 4}},
		{"spike_score.json?min_price=3.1", []int{1, 2, 4}},
		{"spike_score.json?max_price=3.1", []int{3, 4}},
		{"spike_score.json?min_price=3&max_price=30", []int{2, 4}},
		{"spike_score.json?bucket=%242%2B&sort=current_price", []int{4, 3}},
		{"spike_score.json?set=Dominaria&rarity=M", []int{}},
		{"greatest_increase_listings.json?min_change=10", []int{1, 2}},
		{"greatest_increase_listings.json?max_change=33.33", []int{2, 3}},
		{"greatest_increase_listings.json?max_change=0", []int{}},
		{"greatest_increase_listings.json?sort=pct_gain_7d&dir=asc", []int{3, 2, 1}},
		{"greatest_increase_listings.json?sort=sellers_Today", []int{1, 2, 3}},
		{"greatest_increase_listings.json?sort=sellers_d30&dir=asc", []int{2, 3, 1}},
	} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+tc.query)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d %s", tc.query, rec.Code, out.Error)
			continue
		}
		if got := out.rankings(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: rankings %v, want %v", tc.query, got, tc.want)
		}
		if out.Meta.Rows != len(tc.want) {
			t.Errorf("%s: meta.rows %d, want %d", tc.query, out.Meta.Rows, len(tc.want))
		}
	}
	rec, _ := newsGetReport(t, "/api/v2/newspaper/spike_score.json?set=Dominaria&rarity=M")
	if !strings.Contains(rec.Body.String(), `"rows":[]`) {
		t.Errorf("an empty result is not rows: []\n%s", rec.Body.String())
	}
}

// Bad reports, options and values are 400s, bad paths 404s, all JSON and uncached.
func TestNewspaperAPIRefusals(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-27*time.Minute))
	for _, tc := range []struct {
		target string
		status int
		msg    string
	}{
		{"nope.json", 400, `unknown report "nope"`},
		{"options.json", 400, `unknown report "options"`},
		{"spike_score.json?min_change=1", 400, "spike_score does not take min_change"},
		{"greatest_increase_listings.json?bucket=%242%2B", 400, "greatest_increase_listings does not take bucket"},
		{"greatest_increase_listings.json?max_price=5", 400, "greatest_increase_listings does not take max_price"},
		{"spike_score.json?set=Alpha", 400, `set "Alpha" is not in spike_score`},
		{"spike_score.json?finish=Etched", 400, `finish "Etched" is not in spike_score`},
		{"spike_score.json?rarity=X", 400, "rarity must be one of M, R, U, C, S, M/R, U/C"},
		{"spike_score.json?bucket=%243%2B", 400, "bucket must be one of $2+, $5+, $10+, $20+, $35+, $50+, $75+"},
		{"spike_score.json?min_price=cheap", 400, "min_price must be a number"},
		{"spike_score.json?max_price=NaN", 400, "max_price must be a number"},
		{"spike_score.json?max_price=Inf", 400, "max_price must be a number"},
		{"greatest_increase_listings.json?min_change=lots", 400, "min_change must be a number"},
		{"spike_score.json?dir=up", 400, `dir must be asc or desc, not "up"`},
		{"spike_score.json?sort=product_name", 400, `cannot sort spike_score by "product_name"`},
		{"spike_score.json?sort=Tier", 400, `cannot sort spike_score by "Tier"`},
		{"spike_score", 404, "Not found"},
		{"", 404, "Not found"},
		{".json", 404, "Not found"},
		{"spike_score/x.json", 404, "Not found"},
		{"spike_score.xml", 404, "Not found"},
	} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+tc.target)
		if rec.Code != tc.status || !strings.Contains(out.Error, tc.msg) {
			t.Errorf("%s: %d %q, want %d %q", tc.target, rec.Code, out.Error, tc.status, tc.msg)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", tc.target, cc)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type %q", tc.target, ct)
		}
	}
}

// The signature's APImode is the grant: newspaper or all; dev mode with signing off passes.
func TestNewspaperAPIAccess(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-27*time.Minute))
	for _, tc := range []struct {
		modes  string
		status int
	}{
		{"retail,buylist", 403},
		{"history", 403},
		{"", 403},
		{"newspaper", 200},
		{"retail,newspaper", 200},
		{"all", 200},
	} {
		for _, path := range []string{"reports.json", "spike_score.json"} {
			rec := newsServe(t, "/api/v2/newspaper/"+path, tc.modes, nil)
			if rec.Code != tc.status {
				t.Errorf("modes %q %s: status %d, want %d", tc.modes, path, rec.Code, tc.status)
			}
			if tc.status == 403 && !strings.Contains(rec.Body.String(), "plan does not include newspaper") {
				t.Errorf("modes %q: body %s", tc.modes, rec.Body.String())
			}
		}
	}
	if rec := newsServe(t, "/api/v2/newspaper/nope", "retail", nil); rec.Code != 403 {
		t.Errorf("a refused key reached the path check: %d", rec.Code)
	}
	withSigMode(t, true, false)
	rec := httptest.NewRecorder()
	testSite.NewspaperAPI(rec, httptest.NewRequest(http.MethodGet, "/api/v2/newspaper/reports.json", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("dev mode without signing: %d", rec.Code)
	}
}

// With nothing cached every route is a 503 the client retries in five minutes.
func TestNewspaperAPIEmptyCache(t *testing.T) {
	withNewsPages(t, slices.Clone(newspaperPagesInitial), time.Time{})
	for _, path := range []string{"reports.json", "spike_score.json", "nope.json"} {
		rec := newsServe(t, "/api/v2/newspaper/"+path, "newspaper", nil)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "300" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d Retry-After %q Cache-Control %q", path, rec.Code, rec.Header().Get("Retry-After"), rec.Header().Get("Cache-Control"))
		}
	}
}

// Past twelve hours without a refresh, meta says so.
func TestNewspaperAPIStale(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-13*time.Hour))
	_, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json")
	if !out.Meta.Stale {
		t.Error("report meta not stale")
	}
	rec := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	if !strings.Contains(rec.Body.String(), `"stale":true`) {
		t.Errorf("reports.json not stale: %s", rec.Body.String())
	}
}

// With signing on, a request carrying no signature has no mode, never all.
func TestNewspaperAPIUnsigned(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-27*time.Minute))
	signingEnabled(t, false)
	for _, path := range []string{"reports.json", "spike_score.json"} {
		rec := httptest.NewRecorder()
		testSite.NewspaperAPI(rec, httptest.NewRequest(http.MethodGet, "/api/v2/newspaper/"+path, nil))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "plan does not include newspaper") {
			t.Errorf("%s without sig: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// A report shown on Magic alone is an unknown report on another game, loaded or not.
func TestNewspaperAPIMagicOnlyReport(t *testing.T) {
	withConfigCopy(t)
	Config().Game = "lorcana"
	withNewsPages(t, []NewspaperPage{
		newsWithRows(t, "combined_spike_score", newsCombinedRows()),
		newsWithRows(t, "spike_score", newsSpikeRows()),
		newsInitialPage(t, "greatest_increase_buylist"),
	}, newsFixtureNow.Add(-27*time.Minute))
	for _, key := range []string{"combined_spike_score", "greatest_increase_buylist"} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+key+".json")
		if rec.Code != http.StatusBadRequest || !strings.Contains(out.Error, `unknown report "`+key+`"`) {
			t.Errorf("%s on lorcana: %d %q", key, rec.Code, out.Error)
		}
	}
}

// A visible column whose heading cannot sort is refused like a missing one.
func TestNewsParseQueryUnsortableColumn(t *testing.T) {
	page := newsWithRows(t, "spike_score", newsSpikeRows())
	page.Head = slices.Clone(page.Head)
	i := slices.IndexFunc(page.Head, func(h Heading) bool { return h.Field == "current_price" })
	page.Head[i].CanSort = false
	_, err := newsParseQuery(page, url.Values{"sort": {"current_price"}})
	if err == nil || err.Error() != `cannot sort spike_score by "current_price"` {
		t.Errorf("err %v", err)
	}
	if _, err := newsParseQuery(page, url.Values{"sort": {"bucket_rank"}}); err != nil {
		t.Errorf("bucket_rank: %v", err)
	}
}

// A value that is not finite is written as null, so the body stays JSON.
func TestNewsReportJSONNotFinite(t *testing.T) {
	page := newsInitialPage(t, "spike_score")
	row := newsSpikeRows()[0]
	row.CurrentPrice = math.NaN()
	meta := newsReportMeta{Report: "spike_score", Rows: 1, Columns: newsColumns(page)}
	body, err := newsReportJSON(meta, []NewspaperResult{row})
	if err != nil || !json.Valid(body) || !strings.Contains(string(body), `"current_price":null}`) {
		t.Errorf("err %v body %s", err, body)
	}
	row.CurrentPrice = math.Inf(1)
	if got := newsNumber(row, newsColumn{Field: "current_price", Kind: "dollar"}); got != "null" {
		t.Errorf("Inf is %s", got)
	}
}

// A percent column serves the stored fraction times 100, to two decimals.
func TestNewsNumberPercent(t *testing.T) {
	row := NewspaperResult{WeeklyPctChange: 0.0654, CurrentPrice: 0.0654}
	if got := newsNumber(row, newsColumn{Field: "pct_gain_7d", Kind: "percent"}); got != "6.54" {
		t.Errorf("0.0654 serves as %s, want 6.54", got)
	}
	if got := newsNumber(row, newsColumn{Field: "current_price", Kind: "dollar"}); got != "0.0654" {
		t.Errorf("a dollar column serves as %s", got)
	}
}

// max-age: to the next refresh, 60 at least or while a run is pending, 300 once stale.
func TestNewsMaxAge(t *testing.T) {
	at := func(h, m, s int) time.Time { return time.Date(2026, 10, 13, h, m, s, 0, time.Local) }
	for _, tc := range []struct {
		now, refreshed time.Time
		stale          bool
		want           int
	}{
		{at(7, 0, 0), at(6, 33, 0), false, 9180},
		{at(7, 0, 0), at(6, 34, 0), false, 9180},
		{at(7, 0, 0).Add(-500 * time.Millisecond), at(6, 34, 0), false, 9180},
		{at(6, 31, 59), at(3, 34, 0), false, 61},
		{at(6, 32, 30), at(3, 34, 0), false, 60},
		{at(6, 32, 59), at(3, 34, 0), false, 60},
		{at(6, 33, 0), at(6, 33, 0), false, 10800},
		{at(6, 34, 0), at(6, 33, 30), false, 10740},
		{at(23, 40, 0), at(21, 34, 0), false, 3180},
		{at(1, 0, 0), at(0, 34, 0), false, 9180},
		{at(7, 0, 0), at(6, 32, 59), false, 60},
		{at(6, 33, 20), at(3, 34, 0), false, 60},
		{at(1, 0, 0), at(21, 34, 0).Add(-24 * time.Hour), false, 60},
		{at(7, 0, 0), time.Time{}, false, 60},
		{at(7, 0, 0), at(6, 34, 0), true, 300},
		{at(7, 0, 0), at(6, 32, 59), true, 300},
	} {
		if got := newsMaxAge(tc.now, tc.refreshed, tc.stale); got != tc.want {
			t.Errorf("newsMaxAge(%s, %s, %t) = %d, want %d", tc.now.Format("15:04:05.0"), tc.refreshed.Format("01-02 15:04:05"), tc.stale, got, tc.want)
		}
	}
}

// RFC 7232's weak comparison: a list, W/ prefixes and * all match.
func TestNewsETagMatches(t *testing.T) {
	const etag = `"abc"`
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{`"abc"`, true},
		{`W/"abc"`, true},
		{`"x", W/"abc" , "y"`, true},
		{`*`, true},
		{`"abd"`, false},
		{`"x", "y"`, false},
		{``, false},
	} {
		if got := newsETagMatches(tc.header, etag); got != tc.want {
			t.Errorf("newsETagMatches(%q) = %t, want %t", tc.header, got, tc.want)
		}
	}
}

// The CSV form is the same rows as a table, meta in headers; errors stay JSON.
func TestNewspaperAPICSV(t *testing.T) {
	refreshed := newsFixtureNow.Add(-27 * time.Minute)
	withNewsFixture(t, refreshed)
	rec := newsServe(t, "/api/v2/newspaper/spike_score.csv?sort=current_price&dir=asc", "newspaper", nil)
	want := "ranking,id,name,set,number,finish,rarity,bucket_name,bucket_rank,current_price\n" +
		"3,u-llanowar,Llanowar Elves,Dominaria,168,Normal,common,$2+,2,2.25\n" +
		"4,u-counterspell,Counterspell,Modern Horizons 2,267,Normal,uncommon,$2+,1,3.1\n" +
		"2,u-fable,Fable of the Mirror-Breaker,Kamigawa: Neon Dynasty,141,Foil,rare,$20+,1,24.5\n" +
		"1,u-ragavan,\"Ragavan, Nimble Pilferer\",Modern Horizons 2,138,Normal,mythic,$50+,1,64.99\n"
	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("spike_score.csv: %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
	h := rec.Header()
	if h.Get("Content-Type") != "text/csv" || h.Get("X-MTGBAN-Date") != "2026-10-13" ||
		h.Get("X-MTGBAN-Refreshed") != refreshed.UTC().Format(time.RFC3339) ||
		h.Get("X-MTGBAN-Stale") != "false" || h.Get("X-MTGBAN-Rows") != "4" {
		t.Errorf("headers %v", h)
	}

	none := newsServe(t, "/api/v2/newspaper/spike_score.csv?rarity=S", "newspaper", nil)
	if none.Body.String() != "ranking,id,name,set,number,finish,rarity,bucket_name,bucket_rank,current_price\n" || none.Header().Get("X-MTGBAN-Rows") != "0" {
		t.Errorf("an empty CSV: %q rows %q", none.Body.String(), none.Header().Get("X-MTGBAN-Rows"))
	}

	listings := newsServe(t, "/api/v2/newspaper/greatest_increase_listings.csv", "newspaper", nil)
	if !strings.HasPrefix(listings.Body.String(), "ranking,id,name,set,number,finish,rarity,sellers_Today,sellers_d7,sellers_d30,pct_gain_7d\n1,u-solring,Sol Ring,Commander Masters,395,Normal,uncommon,120,80,60,50\n") {
		t.Errorf("listings CSV:\n%s", listings.Body.String())
	}

	nan, inf := newsSpikeRows()[0], newsSpikeRows()[1]
	nan.CurrentPrice, inf.CurrentPrice = math.NaN(), math.Inf(-1)
	inf.CardName = `Kongming, "Sleeping Dragon"`
	body, err := newsCSV([]NewspaperResult{nan, inf}, newsColumns(newsInitialPage(t, "spike_score")))
	if err != nil || !strings.HasSuffix(string(body), ",$50+,1,\n2,u-fable,\"Kongming, \"\"Sleeping Dragon\"\"\",Kamigawa: Neon Dynasty,141,Foil,rare,$20+,1,\n") {
		t.Errorf("a value not finite is not an empty cell: %v\n%s", err, body)
	}

	for _, tc := range []struct {
		target string
		status int
	}{
		{"nope.csv", 400},
		{"spike_score.csv?dir=up", 400},
		{"reports.csv", 404},
	} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+tc.target)
		if rec.Code != tc.status || out.Error == "" || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q %q", tc.target, rec.Code, out.Error, rec.Header().Get("Content-Type"))
		}
	}
}

// Before the first refresh is stamped, refreshed is left out of meta and headers.
func TestNewspaperAPINeverRefreshed(t *testing.T) {
	withNewsFixture(t, time.Time{})
	for _, target := range []string{"reports.json", "spike_score.json", "spike_score.csv"} {
		rec := newsServe(t, "/api/v2/newspaper/"+target, "newspaper", nil)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"refreshed"`) {
			t.Errorf("%s: %d %s", target, rec.Code, rec.Body.String())
		}
		if _, ok := rec.Header()["X-Mtgban-Refreshed"]; ok {
			t.Errorf("%s: X-MTGBAN-Refreshed is set", target)
		}
	}
}

// Responses cache to the next refresh with an ETag and Last-Modified; a held ETag is a 304.
func TestNewspaperAPICaching(t *testing.T) {
	refreshed := newsFixtureNow.Add(-27 * time.Minute)
	withNewsFixture(t, refreshed)
	for _, path := range []string{"reports.json", "spike_score.json", "spike_score.csv"} {
		target := "/api/v2/newspaper/" + path
		rec := newsServe(t, target, "newspaper", nil)
		h := rec.Header()
		if cc := h.Get("Cache-Control"); cc != "public, max-age=9180" {
			t.Errorf("%s: Cache-Control %q", path, cc)
		}
		if lm := h.Get("Last-Modified"); lm != refreshed.UTC().Format(http.TimeFormat) {
			t.Errorf("%s: Last-Modified %q", path, lm)
		}
		etag := h.Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag", path)
		}
		if again := newsServe(t, target, "newspaper", nil); again.Header().Get("ETag") != etag {
			t.Errorf("%s: ETag moved between two reads", path)
		}
		for _, held := range []string{etag, "W/" + etag, `"x", W/` + etag, "*"} {
			nm := newsServe(t, target, "newspaper", http.Header{"If-None-Match": {held}})
			if nm.Code != http.StatusNotModified || nm.Body.Len() != 0 || nm.Header().Get("ETag") != etag ||
				nm.Header().Get("Cache-Control") != h.Get("Cache-Control") || nm.Header().Get("Last-Modified") != h.Get("Last-Modified") {
				t.Errorf("%s If-None-Match %s: %d, %d bytes", path, held, nm.Code, nm.Body.Len())
			}
		}
		if other := newsServe(t, target, "newspaper", http.Header{"If-None-Match": {`"other"`}}); other.Code != http.StatusOK {
			t.Errorf("%s: another tag answered %d", path, other.Code)
		}
	}
	plain := newsServe(t, "/api/v2/newspaper/spike_score.json", "newspaper", nil).Header().Get("ETag")
	sorted := newsServe(t, "/api/v2/newspaper/spike_score.json?sort=current_price", "newspaper", nil).Header().Get("ETag")
	csvTag := newsServe(t, "/api/v2/newspaper/spike_score.csv", "newspaper", nil).Header().Get("ETag")
	if plain == sorted || plain == csvTag {
		t.Errorf("ETags collide: json %s sorted %s csv %s", plain, sorted, csvTag)
	}
}

// A stale cache tells a client to recheck in five minutes.
func TestNewspaperAPICachingStale(t *testing.T) {
	withNewsFixture(t, newsFixtureNow.Add(-13*time.Hour))
	rec := newsServe(t, "/api/v2/newspaper/spike_score.csv", "newspaper", nil)
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control %q", cc)
	}
	if rec.Header().Get("X-MTGBAN-Stale") != "true" {
		t.Errorf("X-MTGBAN-Stale %q", rec.Header().Get("X-MTGBAN-Stale"))
	}
}

// newsManyRows are n spike_score rows in ranking order, for paging.
func newsManyRows(n int) []NewspaperResult {
	rows := make([]NewspaperResult, n)
	for i := range rows {
		rows[i] = NewspaperResult{Date: newsCalcDate, UUID: "u-" + strconv.Itoa(i+1), Ranking: i + 1, CardName: "Card " + strconv.Itoa(i+1), Edition: "Dominaria", Number: strconv.Itoa(i + 1), Variant: "Normal", Rarity: "common", BucketName: "$2+", BucketRank: i + 1, CurrentPrice: 2.5}
	}
	return rows
}

// A report pages at 1,000 rows; meta counts the rows matched, the page and the pages.
func TestNewspaperAPIPaging(t *testing.T) {
	withNewsPages(t, []NewspaperPage{newsWithRows(t, "spike_score", newsManyRows(1250))}, newsFixtureNow.Add(-27*time.Minute))

	rec, out := newsGetReport(t, "/api/v2/newspaper/spike_score.json")
	if rec.Code != http.StatusOK || len(out.Rows) != 1000 || out.Meta.Page != 1 || out.Meta.Pages != 2 || out.Meta.Rows != 1250 {
		t.Errorf("page 1: %d, %d rows, meta %d/%d of %d", rec.Code, len(out.Rows), out.Meta.Page, out.Meta.Pages, out.Meta.Rows)
	}
	if len(out.Rows) > 0 && (out.Rows[0].Ranking != 1 || out.Rows[len(out.Rows)-1].Ranking != 1000) {
		t.Errorf("page 1 runs %d to %d", out.Rows[0].Ranking, out.Rows[len(out.Rows)-1].Ranking)
	}
	rec2, out2 := newsGetReport(t, "/api/v2/newspaper/spike_score.json?page=2")
	if rec2.Code != http.StatusOK || len(out2.Rows) != 250 || out2.Meta.Page != 2 || out2.Meta.Pages != 2 || out2.Meta.Rows != 1250 {
		t.Errorf("page 2: %d, %d rows, meta %d/%d of %d", rec2.Code, len(out2.Rows), out2.Meta.Page, out2.Meta.Pages, out2.Meta.Rows)
	}
	if len(out2.Rows) > 0 && out2.Rows[0].Ranking != 1001 {
		t.Errorf("page 2 starts at %d", out2.Rows[0].Ranking)
	}
	if rec.Header().Get("ETag") == rec2.Header().Get("ETag") {
		t.Errorf("pages 1 and 2 share ETag %s", rec.Header().Get("ETag"))
	}

	for _, target := range []string{"spike_score.json?page=3", "spike_score.json?page=0", "spike_score.json?page=x", "spike_score.json?page=-1", "spike_score.csv?page=3"} {
		rec, out := newsGetReport(t, "/api/v2/newspaper/"+target)
		if rec.Code != http.StatusBadRequest || out.Error != "page out of range" {
			t.Errorf("%s: %d %q", target, rec.Code, out.Error)
		}
	}

	rec, out = newsGetReport(t, "/api/v2/newspaper/spike_score.json?rarity=M&page=1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"rows":[]`) || out.Meta.Page != 1 || out.Meta.Pages != 1 || out.Meta.Rows != 0 {
		t.Errorf("an empty page: %d meta %+v", rec.Code, out.Meta)
	}

	csv2 := newsServe(t, "/api/v2/newspaper/spike_score.csv?page=2", "newspaper", nil)
	h := csv2.Header()
	if csv2.Code != http.StatusOK || h.Get("X-MTGBAN-Page") != "2" || h.Get("X-MTGBAN-Pages") != "2" || h.Get("X-MTGBAN-Rows") != "1250" {
		t.Errorf("CSV page 2: %d headers %v", csv2.Code, h)
	}
	if lines := strings.Count(csv2.Body.String(), "\n"); lines != 251 {
		t.Errorf("CSV page 2 has %d lines, want a header and 250", lines)
	}
	csv1 := newsServe(t, "/api/v2/newspaper/spike_score.csv", "newspaper", nil)
	if csv1.Header().Get("X-MTGBAN-Page") != "1" || strings.Count(csv1.Body.String(), "\n") != 1001 || csv1.Header().Get("ETag") == h.Get("ETag") {
		t.Errorf("CSV page 1: page %q, %d lines", csv1.Header().Get("X-MTGBAN-Page"), strings.Count(csv1.Body.String(), "\n"))
	}
}

// reports.json reads no options, page included, and lists page as no filter.
func TestNewspaperAPIReportsIgnoresPage(t *testing.T) {
	withNewsPages(t, []NewspaperPage{newsWithRows(t, "spike_score", newsManyRows(1250))}, newsFixtureNow.Add(-27*time.Minute))
	plain := newsServe(t, "/api/v2/newspaper/reports.json", "newspaper", nil)
	for _, query := range []string{"?page=2", "?sort=nope"} {
		rec := newsServe(t, "/api/v2/newspaper/reports.json"+query, "newspaper", nil)
		if rec.Code != http.StatusOK || rec.Body.String() != plain.Body.String() {
			t.Errorf("reports.json%s: %d\n%s", query, rec.Code, rec.Body.String())
		}
	}
	var out newsReportsOut
	if err := json.Unmarshal(plain.Body.Bytes(), &out); err != nil || len(out.Reports) != 1 {
		t.Fatalf("%v %s", err, plain.Body.String())
	}
	if r := out.Reports[0]; slices.Contains(r.Filters, "page") || r.Rows != 1250 {
		t.Errorf("filters %v rows %d", r.Filters, r.Rows)
	}
}
