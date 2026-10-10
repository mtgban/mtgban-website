package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// closeVendors serves two vendors buying the same five cards within 10% of
// each other, ZZW paying 50 cents more for each, and returns the cards.
func closeVendors(t *testing.T) []string {
	t.Helper()
	keepScrapers(t)
	cards := backend().GetUUIDs()
	if len(cards) < 5 {
		t.Skip("no datastore loaded")
	}
	cards = cards[:5]

	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Upload") })
	}

	v, w := mtgban.BuylistRecord{}, mtgban.BuylistRecord{}
	for k, card := range cards {
		v[card] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: 5 + float64(k)}}
		w[card] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: 5.5 + float64(k)}}
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(v, sessionInfo("ZZV")),
		mtgban.NewVendorFromBuylist(w, sessionInfo("ZZW")),
	}
	vendorsPtr.Store(&vendors)
	return cards
}

// optimizeBuylist sells cards to ZZV and ZZW with a 10% margin and returns
// the page.
func optimizeBuylist(t *testing.T, cards []string) string {
	t.Helper()
	form := url.Values{}
	form.Set("mode", "true")
	form["stores"] = []string{"ZZV", "ZZW"}
	form.Set("minmargin", "true")
	form.Set("margin", "10")
	form.Set("lowval", "")
	form.Set("lowvalabs", "")
	var rows strings.Builder
	for _, card := range cards {
		fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
	}
	form.Set("rows", rows.String())

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	testSite.Upload(rec, req)
	return rec.Body.String()
}

var optimizedMaximum = regexp.MustCompile(`theoretical maximum of <strong>\$ ([0-9.]+)</strong>`)

// Each card's best offer is the higher one wherever the other falls within
// the margin, and the same list makes the same page every time it is sent.
func TestUploadOptimizerIgnoresStoreOrder(t *testing.T) {
	cards := closeVendors(t)

	first := optimizeBuylist(t, cards)
	m := optimizedMaximum.FindStringSubmatch(first)
	if m == nil {
		t.Fatal("the page shows no optimized maximum")
	}
	if m[1] != "37.50" {
		t.Errorf("the maximum is $%s, want $37.50, ZZW's offer for every card", m[1])
	}
	for range 20 {
		page := optimizeBuylist(t, cards)
		if page != first {
			t.Fatalf("the same upload made another page: maximum $%s, then %q",
				m[1], optimizedMaximum.FindStringSubmatch(page))
		}
	}
}

// A store's place among the offers is decided by its price, and by its
// shorthand only between equal prices.
func TestBestOffers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		offers     map[string]float64
		blMode     bool
		percMargin float64
		want       []string
	}{
		{"buylist keeps those within the margin of the highest", map[string]float64{"A": 5, "B": 5.4, "C": 5.9}, true, 0.9, []string{"C", "B"}},
		{"buylist without a margin keeps the highest", map[string]float64{"A": 5, "B": 5.4, "C": 5.9}, true, 1, []string{"C"}},
		{"a tie within the margin keeps both", map[string]float64{"B": 5, "A": 5}, true, 0.9, []string{"A", "B"}},
		{"a tie without a margin goes to the first shorthand", map[string]float64{"B": 5, "A": 5, "C": 4}, true, 1, []string{"A"}},
		{"retail keeps the lowest", map[string]float64{"C": 5, "B": 4, "A": 4.5}, false, 1, []string{"B"}},
		{"no offers", map[string]float64{}, true, 0.9, nil},
	} {
		got := bestOffers(tc.offers, tc.blMode, tc.percMargin)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestOptimizerCountsTheStoreItKept adds a row to the highest totals at the
// store the optimizer lists it under: when the high-value filter drops the
// best offer, that is the next one it kept.
func TestOptimizerCountsTheStoreItKept(t *testing.T) {
	rows := uploadRows{
		resultPrices:     map[string]map[string]float64{"card": {"CK": 55, "SCG": 49.6}},
		optimizedResults: map[string][]OptimizedUploadEntry{},
		optimizedTotals:  map[string]float64{},
		optimizedQtys:    map[string]int{},
	}
	row := uploadRow{UploadEntry: &UploadEntry{CardID: "card"}, priceKey: "card", qty: 3}
	st := uploadSettings{skipHighValueAbs: true, maxHighVal: 50}
	rows.optimizeRow(row, map[string]float64{"CK": 55, "SCG": 49.6}, []string{"CK", "SCG"}, st, uploadIndexes{})

	if len(rows.optimizedResults["CK"]) != 0 || len(rows.optimizedResults["SCG"]) != 1 {
		t.Fatalf("listed under %v, want SCG alone", rows.optimizedResults)
	}
	if rows.highestTotal != 49.6 || rows.singlesHighest != 49.6 {
		t.Errorf("highest %v, singles %v, want SCG's 49.6 in both", rows.highestTotal, rows.singlesHighest)
	}
	if rows.optimizedQtys["CK"] != 0 || rows.optimizedQtys["SCG"] != 3 {
		t.Errorf("quantities %v, want SCG's 3 alone", rows.optimizedQtys)
	}
}

// TestOptimizerCardCount spells a split's card count, singular for one, and
// adds the copies only where they differ from it.
func TestOptimizerCardCount(t *testing.T) {
	for _, tc := range []struct {
		entries []OptimizedUploadEntry
		qty     int
		want    string
	}{
		{[]OptimizedUploadEntry{{CardID: "a", Quantity: 1}}, 1, `<span class="opt-count">1 card</span>`},
		{[]OptimizedUploadEntry{{CardID: "a", Quantity: 4}}, 4, `<span class="opt-count">1 card (4 total)</span>`},
		{[]OptimizedUploadEntry{{CardID: "a", Quantity: 1}, {CardID: "b", Quantity: 1}}, 2, `<span class="opt-count">2 cards</span>`},
	} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			Optimized:           map[string][]OptimizedUploadEntry{"CK": tc.entries},
			OptimizedKeys:       []string{"CK"},
			OptimizedTotals:     map[string]float64{"CK": 1},
			OptimizedQuantities: map[string]int{"CK": tc.qty},
		}})
		if !strings.Contains(out, tc.want) {
			t.Errorf("no %s", tc.want)
		}
	}
}
