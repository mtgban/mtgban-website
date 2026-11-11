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
	"github.com/mtgban/mtgban-website/internal/uploadsort"
	"github.com/mtgban/mtgban-website/internal/uploadtie"
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
	withPrices(t, currentPrices().sellers, vendors)
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
		got := bestOffers(tc.offers, tc.blMode, tc.percMargin, uploadtie.Breaker{})
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The custom buylist pays in credit what it pays in cash, so a credit
// tiebreak ranks it at its price, above a store paying no credit and, on
// offers priced in credit, above a store whose credit is worth less.
func TestUploadTiebreakCustomCredit(t *testing.T) {
	prices := uploadPrices{credits: map[string]float64{"ABC": 0, customStore: 0, "CK": 1.3}}
	for _, tc := range []struct {
		rule, unit string
		want       []string
	}{
		{uploadtie.Credit, "", []string{"CK", customStore, "ABC"}},
		{uploadtie.MarketCredit, uploadtie.Credit, []string{customStore, "CK", "ABC"}},
	} {
		st := uploadSettings{tiebreak: tc.rule, priceSource: tc.unit}
		got := []string{"ABC", "CK", customStore}
		slices.SortFunc(got, uploadTiebreak(true, st, prices, nil).Compare)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s on %q offers: got %q, want %q", tc.rule, tc.unit, got, tc.want)
		}
	}
}

// A row two stores tie on goes to the one the tiebreak picks: ZZW pays more
// for four cards, both pay 9 for the fifth, and only ZZW pays credit.
func TestOptimizerTiebreak(t *testing.T) {
	cards := closeVendors(t)
	v, w := mtgban.BuylistRecord{}, mtgban.BuylistRecord{}
	for k, card := range cards {
		v[card] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: 5}}
		w[card] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: 6}}
		if k == len(cards)-1 {
			v[card][0].BuyPrice, w[card][0].BuyPrice = 9, 9
		}
	}
	credit := sessionInfo("ZZW")
	credit.CreditMultiplier = 1.3
	withPrices(t, currentPrices().sellers, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(v, sessionInfo("ZZV")),
		mtgban.NewVendorFromBuylist(w, credit),
	})

	for _, tc := range []struct {
		tiebreak, order string
		zzv             bool
	}{
		{"", "", true},
		{uploadtie.Consolidate, "", false},
		{uploadtie.Custom, "ZZW", false},
		{uploadtie.Custom, "ZZX,ZZV", true},
		{uploadtie.Credit, "", false},
		{uploadtie.MarketCredit, "", false},
	} {
		form := url.Values{"mode": {"true"}, "stores": {"ZZV", "ZZW"}, "minmargin": {""},
			"lowval": {""}, "lowvalabs": {""}, "tiebreak": {tc.tiebreak}, "tieorder": {tc.order}}
		var rows strings.Builder
		for _, card := range cards {
			fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
		}
		form.Set("rows", rows.String())
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		testSite.Upload(rec, req)

		page := rec.Body.String()
		if !strings.Contains(page, `id="opt-ZZW"`) {
			t.Fatalf("%q %q: no ZZW section", tc.tiebreak, tc.order)
		}
		if got := strings.Contains(page, `id="opt-ZZV"`); got != tc.zzv {
			t.Errorf("%q %q: ZZV listed %v, want %v", tc.tiebreak, tc.order, got, tc.zzv)
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

// TestOptimizerKeepsWhatTheRowLoaded carries the row's own price and grade
// past settings that compare it to an index and skip conditions: a share of
// the section sends those.
func TestOptimizerKeepsWhatTheRowLoaded(t *testing.T) {
	rows := uploadRows{
		resultPrices:     map[string]map[string]float64{"card": {"CK": 2}},
		optimizedResults: map[string][]OptimizedUploadEntry{},
		optimizedAt:      map[optimizedKey]int{},
		optimizedTotals:  map[string]float64{},
		optimizedQtys:    map[string]int{},
	}
	row := uploadRow{
		UploadEntry: &UploadEntry{CardID: "card", OriginalPrice: 3.5, IgnoredCondition: mtgban.SP},
		priceKey:    "card",
		qty:         1,
	}
	st := uploadSettings{skipPrices: true, altPriceSource: "TCGLow"}
	indexes := uploadIndexes{results: map[string]map[string]*BanPrice{
		"card": {"TCGLow": {Regular: 9}},
	}}
	rows.optimizeRow(row, map[string]float64{"CK": 2}, []string{"CK"}, st, indexes)

	got := rows.optimizedResults["CK"]
	if len(got) != 1 {
		t.Fatalf("listed %v, want one row", got)
	}
	if got[0].Price != 9 || got[0].Condition != "" {
		t.Errorf("compared against %v in %q, want the index's 9 and no grade", got[0].Price, got[0].Condition)
	}
	if got[0].LoadedPrice != 3.5 || got[0].LoadedCondition != mtgban.SP {
		t.Errorf("loaded %v in %q, want 3.5 in SP", got[0].LoadedPrice, got[0].LoadedCondition)
	}
}

// TestOptimizerShareButton draws a store's share button for a reader who may
// share, and its rows carry what the button sends.
func TestOptimizerShareButton(t *testing.T) {
	for _, canShare := range []bool{true, false} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			CanShare:            canShare,
			Optimized:           map[string][]OptimizedUploadEntry{"CK": {{CardID: "a", Quantity: 2, LoadedPrice: 3.5, LoadedCondition: mtgban.SP}}},
			OptimizedKeys:       []string{"CK"},
			OptimizedTotals:     map[string]float64{"CK": 1},
			OptimizedQuantities: map[string]int{"CK": 2},
		}})
		if got := strings.Contains(out, "opt-share-btn"); got != canShare {
			t.Errorf("CanShare %v: button drawn %v", canShare, got)
		}
		if !strings.Contains(out, `data-share-price="3.5" data-share-cond="SP"`) {
			t.Errorf("CanShare %v: the row carries no loaded price and grade", canShare)
		}
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
	if len(got) != 1 || got[0].Quantity != 3 {
		t.Fatalf("CK lists %+v, want one row of 3", got)
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

// TestSortByProfitabilityLeadsWithOffersOverTheBase orders offers at or over
// the base price, which all score zero, by their factor ahead of the rest.
func TestSortByProfitabilityLeadsWithOffersOverTheBase(t *testing.T) {
	results := map[string][]OptimizedUploadEntry{"store": {
		{CardID: "short", Spread: 50, Profitability: 2},
		{CardID: "at", Spread: 100},
		{CardID: "over", Spread: 140},
	}}
	sortResults(nil, nil, nil, results, "profitability")
	var got []string
	for _, e := range results["store"] {
		got = append(got, e.CardID)
	}
	want := []string{"over", "at", "short"}
	if !slices.Equal(got, want) {
		t.Errorf("sorted as %v, want %v", got, want)
	}
}

// TestNumberSortTiesGroupsEqualRows gives rows the sort cannot tell apart one
// group, for the page to break their ties.
func TestNumberSortTiesGroupsEqualRows(t *testing.T) {
	uploaded := []UploadEntry{
		{CardID: "b", OriginalPrice: 5},
		{CardID: "d", OriginalPrice: 5},
		{CardID: "a", OriginalPrice: 1},
		{CardID: "c", OriginalPrice: 1},
	}
	results := map[string][]OptimizedUploadEntry{"store": {
		{CardID: "y", BestPrice: 3},
		{CardID: "x", BestPrice: 2},
		{CardID: "z", BestPrice: 2},
	}}
	numberSortTies(uploaded, results, "highprice")

	var got []int
	for _, e := range uploaded {
		got = append(got, e.SortLead)
	}
	if want := []int{1, 1, 2, 2}; !slices.Equal(got, want) {
		t.Errorf("uploaded groups %v, want %v", got, want)
	}
	got = nil
	for _, e := range results["store"] {
		got = append(got, e.SortLead)
	}
	if want := []int{1, 2, 2}; !slices.Equal(got, want) {
		t.Errorf("optimized groups %v, want %v", got, want)
	}
}

// TestNumberSortTiesLeavesUnsortedListsUngrouped keeps SortLead 0 on a list
// the setting does not sort, so the page's tie-breakers lead it.
func TestNumberSortTiesLeavesUnsortedListsUngrouped(t *testing.T) {
	for _, sorting := range []string{"", "highspread"} {
		uploaded := []UploadEntry{{CardID: "a", OriginalPrice: 1}, {CardID: "b", OriginalPrice: 5}}
		results := map[string][]OptimizedUploadEntry{"store": {{CardID: "x", Spread: 20}, {CardID: "y", Spread: 10}}}
		numberSortTies(uploaded, results, sorting)
		if uploaded[0].SortLead != 0 || uploaded[1].SortLead != 0 {
			t.Errorf("%q: uploaded rows %+v, want them ungrouped", sorting, uploaded)
		}
		led := results["store"][0].SortLead != 0
		if led != (sorting == "highspread") {
			t.Errorf("%q: optimized rows %+v", sorting, results["store"])
		}
	}
}

// TestNumberSortTiesFollowsProfitability ties offers at or over the base on
// their factor and spread, and the rest on the spread alone.
func TestNumberSortTiesFollowsProfitability(t *testing.T) {
	results := map[string][]OptimizedUploadEntry{"store": {
		{CardID: "a", Spread: 140},
		{CardID: "b", Spread: 140},
		{CardID: "c", Spread: 100},
		{CardID: "d", Spread: 50, Profitability: 2},
		{CardID: "e", Spread: -5, Profitability: 1},
		{CardID: "f", Spread: -5, Profitability: 3},
	}}
	numberSortTies(nil, results, "profitability")
	var got []int
	for _, e := range results["store"] {
		got = append(got, e.SortLead)
	}
	if want := []int{1, 1, 2, 3, 4, 4}; !slices.Equal(got, want) {
		t.Errorf("groups %v, want %v", got, want)
	}
}

// TestNumberSortTiesKeepsAPrintingTogether gives one printing's rows one
// group though a card-data sort left another printing between them.
func TestNumberSortTiesKeepsAPrintingTogether(t *testing.T) {
	uploaded := []UploadEntry{{CardID: "a"}, {CardID: "b"}, {CardID: "a"}}
	results := map[string][]OptimizedUploadEntry{"store": {{CardID: "b"}, {CardID: "a"}, {CardID: "b"}}}
	numberSortTies(uploaded, results, "setchrono")
	var got []int
	for _, e := range uploaded {
		got = append(got, e.SortLead)
	}
	for _, e := range results["store"] {
		got = append(got, e.SortLead)
	}
	if want := []int{1, 2, 1, 1, 2, 1}; !slices.Equal(got, want) {
		t.Errorf("groups %v, want %v", got, want)
	}
}

// TestUploadRowsCarryTheirSortKeys writes each row's tie-breaker keys and,
// where the sorting setting grouped it, its tie group.
func TestUploadRowsCarryTheirSortKeys(t *testing.T) {
	keys := map[string]uploadsort.Keys{"a": {Name: "counterspell", Set: "1999-04-11 seventh edition", Number: "67", Finish: "0 nonfoil", Color: "1.01", Rarity: "3"}}
	want := `data-k-name="counterspell" data-k-set="1999-04-11 seventh edition" data-k-number="67" data-k-finish="0 nonfoil" data-k-color="1.01" data-k-rarity="3"`
	out := renderUpload(t, PageVars{
		Metadata: cardMetadata{"a": {Name: "Counterspell"}, "b": {Name: "Opt"}},
		UploadVars: UploadVars{
			SortKeys:       keys,
			SinglesEntries: []UploadEntry{{CardID: "a", OriginalCondition: "SP", SortLead: 2}, {CardID: "b"}},
			Optimized:      map[string][]OptimizedUploadEntry{"CK": {{CardID: "a", Condition: "SP", SortLead: 3}, {CardID: "b"}}},
			OptimizedKeys:  []string{"CK"},
		},
	})
	for _, w := range []string{
		`data-opt-id="a"`, want + ` data-k-cond="1" data-k-lead="3"`,
		`data-hash="a"`, `data-k-cond="1" data-k-lead="2"`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("no %s", w)
		}
	}
	if strings.Count(out, "data-k-lead=") != 2 {
		t.Errorf("%d rows carry a tie group, want the 2 grouped ones", strings.Count(out, "data-k-lead="))
	}
}
