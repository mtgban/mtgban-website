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
	withPrices(t, GetSellers(), vendors)
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
		optimizedAt:      map[optimizedKey]int{},
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

// TestOptimizerMergesOpenedCopies lists a card opened from several products
// once per store, its copies added up and capped as one card's, while each
// product's section still counts its own copy.
func TestOptimizerMergesOpenedCopies(t *testing.T) {
	rows := uploadRows{
		resultPrices:     map[string]map[string]float64{"card": {"CK": 2}},
		optimizedResults: map[string][]OptimizedUploadEntry{},
		optimizedAt:      map[optimizedKey]int{},
		optimizedTotals:  map[string]float64{},
		optimizedQtys:    map[string]int{},
		tallies:          map[string]*unpackedTally{},
	}
	st := uploadSettings{maxQty: 3}
	for _, deck := range []string{"deck1", "deck2", "deck3", "deck4"} {
		entry := &UploadEntry{CardID: "card", Notes: deck, UnpackedFrom: deck}
		row := uploadRow{UploadEntry: entry, priceKey: "card", qty: 1}
		rows.optimizeRow(row, map[string]float64{"CK": 2}, []string{"CK"}, st, uploadIndexes{})
	}

	got := rows.optimizedResults["CK"]
	if len(got) != 1 || got[0].Quantity != 3 || got[0].Notes != "" {
		t.Fatalf("CK lists %+v, want one row of 3 with no notes", got)
	}
	if rows.optimizedTotals["CK"] != 6 || rows.optimizedQtys["CK"] != 3 || rows.highestTotal != 6 {
		t.Errorf("total %v, quantity %v, highest %v, want 6, 3 and 6",
			rows.optimizedTotals["CK"], rows.optimizedQtys["CK"], rows.highestTotal)
	}
	for _, deck := range []string{"deck1", "deck2", "deck3", "deck4"} {
		if rows.tallies[deck].Highest != 2 {
			t.Errorf("%s's section counts %v, want its own copy's 2", deck, rows.tallies[deck].Highest)
		}
	}
}

// TestTotalsCapOpenedCopies holds the page's store and index totals to the
// copies the optimizer lists, a card opened from several products capped as
// one card, while each product's section and an uploaded row count whole.
func TestTotalsCapOpenedCopies(t *testing.T) {
	rows := uploadRows{
		resultPrices:  map[string]map[string]float64{},
		totalEntries:  map[string]float64{},
		openedCounted: map[optimizedKey]int{},
		tallies:       map[string]*unpackedTally{},
	}
	st := uploadSettings{maxQty: 3}
	prices := uploadPrices{results: map[string]map[string]*BanPrice{"card": {"CK": {Regular: 2}}}}
	indexes := uploadIndexes{results: map[string]map[string]*BanPrice{"card": {"TCGLow": {Regular: 1}}}}
	for _, entry := range []*UploadEntry{
		{CardID: "card", UnpackedFrom: "deck1"},
		{CardID: "card", UnpackedFrom: "deck2"},
		{CardID: "card", UnpackedFrom: "deck3"},
		{CardID: "card", UnpackedFrom: "deck4"},
		{CardID: "card"},
	} {
		row := uploadRow{UploadEntry: entry, priceKey: "card", qty: 1, counts: true}
		rows.tallyIndexes(row, st, indexes)
		offers := rows.tallyOffers(row, false, st, prices, indexes)
		if offers["CK"] != 2 {
			t.Fatalf("offer %v, want the row's own 2", offers["CK"])
		}
	}

	if rows.totalEntries["CK"] != 8 || rows.totalEntries["TCGLow"] != 4 {
		t.Errorf("totals CK %v and TCGLow %v, want 8 and 4: three opened copies and the uploaded one",
			rows.totalEntries["CK"], rows.totalEntries["TCGLow"])
	}
	for _, deck := range []string{"deck1", "deck2", "deck3", "deck4"} {
		if rows.tallies[deck].Totals["CK"] != 2 || rows.tallies[deck].Totals["TCGLow"] != 1 {
			t.Errorf("%s's section totals %v, want its own copy's", deck, rows.tallies[deck].Totals)
		}
	}
}

// TestOptimizerKeepsUploadedCopiesApart leaves a row uploaded with a price of
// its own out of the opened copies' row: it was judged on that price, which
// the opened ones do not have.
func TestOptimizerKeepsUploadedCopiesApart(t *testing.T) {
	rows := uploadRows{
		resultPrices:     map[string]map[string]float64{"card": {"CK": 2}},
		optimizedResults: map[string][]OptimizedUploadEntry{},
		optimizedAt:      map[optimizedKey]int{},
		optimizedTotals:  map[string]float64{},
		optimizedQtys:    map[string]int{},
		tallies:          map[string]*unpackedTally{},
	}
	for _, entry := range []*UploadEntry{
		{CardID: "card", OriginalPrice: 4},
		{CardID: "card", UnpackedFrom: "deck1"},
		{CardID: "card", UnpackedFrom: "deck2"},
	} {
		row := uploadRow{UploadEntry: entry, priceKey: "card", qty: 1}
		rows.optimizeRow(row, map[string]float64{"CK": 2}, []string{"CK"}, uploadSettings{}, uploadIndexes{})
	}

	got := rows.optimizedResults["CK"]
	if len(got) != 2 || got[0].Price != 4 || got[0].Quantity != 1 || got[1].Price != 0 || got[1].Quantity != 2 {
		t.Fatalf("CK lists %+v, want the uploaded row at 4 alone and the opened copies as one of 2", got)
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

// An emptied option list is saved as a lone comma, which must not read as
// a cookie never set: that would bring the default options back.
func TestHasUploadOptCookie(t *testing.T) {
	for _, tc := range []struct {
		cookie string
		want   bool
	}{
		{"", true},
		{",", false},
		{"highval,", false},
		{"lowval,", true},
	} {
		req := httptest.NewRequest(http.MethodGet, "/upload", nil)
		if tc.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "UploadOptimizerOpts", Value: tc.cookie})
		}
		req.ParseForm()
		got := hasUploadOpt(req, "lowval")
		if got != tc.want {
			t.Errorf("cookie %q: lowval = %v, want %v", tc.cookie, got, tc.want)
		}
	}
}

// TestOptimizerSortsSetsByEdition sorts the Set column on the edition's
// name and then the card's, not on the set code the cell shows first.
func TestOptimizerSortsSetsByEdition(t *testing.T) {
	out := renderUpload(t, PageVars{
		Metadata: cardMetadata{"a": {Name: "Counterspell", Edition: "Seventh Edition", SetCode: "7ED"}},
		UploadVars: UploadVars{
			Optimized:     map[string][]OptimizedUploadEntry{"CK": {{CardID: "a", Quantity: 1}}},
			OptimizedKeys: []string{"CK"},
		},
	})
	want := `<td class="opt-set" data-sort="Seventh Edition&#9;Counterspell">`
	if !strings.Contains(out, want) {
		t.Errorf("no %s", want)
	}
}

// TestOptimizerShowsTheLoadedQuantity puts the quantity beside the loaded
// price, with no price too, and sorts the cell on the price alone.
func TestOptimizerShowsTheLoadedQuantity(t *testing.T) {
	for _, tc := range []struct {
		entry OptimizedUploadEntry
		want  string
	}{
		{OptimizedUploadEntry{CardID: "a", Price: 5, Quantity: 3}, `<td class="opt-loaded" data-sort="5.00">`},
		{OptimizedUploadEntry{CardID: "a", Price: 5, Quantity: 3}, `</a></span><span class="loaded-qty">&times;3</span>`},
		{OptimizedUploadEntry{CardID: "a", Quantity: 4}, `<span class="loaded"></span><span class="loaded-qty">&times;4</span>`},
		{OptimizedUploadEntry{CardID: "a"}, `<span class="loaded"></span><span class="loaded-qty"></span>`},
	} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			Optimized:     map[string][]OptimizedUploadEntry{"CK": {tc.entry}},
			OptimizedKeys: []string{"CK"},
		}})
		if !strings.Contains(out, tc.want) {
			t.Errorf("%+v: no %s", tc.entry, tc.want)
		}
	}
}

// TestOptimizerRowsCarryTheCondition marks each row with its condition,
// which the backpack takes copies by.
func TestOptimizerRowsCarryTheCondition(t *testing.T) {
	out := renderUpload(t, PageVars{UploadVars: UploadVars{
		Optimized:     map[string][]OptimizedUploadEntry{"CK": {{CardID: "a", Condition: "SP"}, {CardID: "b"}}},
		OptimizedKeys: []string{"CK"},
	}})
	for _, want := range []string{`data-opt-id="a" data-opt-cond="SP"`, `data-opt-id="b" data-opt-cond=""`} {
		if !strings.Contains(out, want) {
			t.Errorf("no %s", want)
		}
	}
}
