package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/bulkrates"
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

// A buylist's margin is the one posted or saved, and the page's 10% when
// neither names one; a 0 posted is no margin.
func TestUploadMarginDefault(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   url.Values
		cookie string
		want   float64
	}{
		{"nothing posted or saved", url.Values{}, "", 0.9},
		{"not a number", url.Values{"margin": {"x"}}, "", 0.9},
		{"negative", url.Values{"margin": {"-5"}}, "", 0.9},
		{"NaN", url.Values{"margin": {"NaN"}}, "", 0.9},
		{"infinite", url.Values{"margin": {"Inf"}}, "", 0},
		{"over 100", url.Values{"margin": {"150"}}, "", 0},
		{"100", url.Values{"margin": {"100"}}, "", 0},
		{"posted", url.Values{"margin": {"25"}}, "", 0.75},
		{"zero", url.Values{"margin": {"0"}}, "", 1},
		{"saved", url.Values{}, "5", 0.95},
		{"option off", url.Values{"minmargin": {""}}, "", 1},
	} {
		cookies := map[string]string{}
		if tc.cookie != "" {
			cookies["UploadMargin"] = tc.cookie
		}
		st := readUploadSettings(uploadRequest(t, "/upload", tc.form, cookies), true)
		if math.Abs(st.percMargin-tc.want) > 1e-9 {
			t.Errorf("%s: margin %v, want %v", tc.name, st.percMargin, tc.want)
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

// A custom order naming the custom buylist ranks its sealed side in the
// same place, as the settings offer the two as one.
func TestUploadTiebreakCustomOrder(t *testing.T) {
	st := uploadSettings{tiebreak: uploadtie.Custom, tieOrder: []string{"CK", customStore, "SCG"}}
	got := []string{"SCG", customSealedStore, "ABC", "CK"}
	slices.SortFunc(got, uploadTiebreak(true, st, uploadPrices{}, nil).Compare)
	want := []string{"CK", customSealedStore, "SCG", "ABC"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
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

// TestUploadTiebreakNeedsMultiSelectOff ignores the tie rule only where
// multi-select lists a row under every tied store: on a buylist, with a margin.
func TestUploadTiebreakNeedsMultiSelectOff(t *testing.T) {
	for _, tc := range []struct {
		minmargin, margin string
		blMode            bool
		want              string
	}{
		{"", "10", true, uploadtie.Custom},
		{"true", "10", true, ""},
		{"true", "0", true, uploadtie.Custom},
		{"true", "10", false, uploadtie.Custom},
	} {
		form := url.Values{"tiebreak": {uploadtie.Custom}, "tieorder": {"ZZW"}, "minmargin": {tc.minmargin}, "margin": {tc.margin}}
		req := httptest.NewRequest(http.MethodGet, "/upload?"+form.Encode(), nil)
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := readUploadSettings(req, tc.blMode).tiebreak; got != tc.want {
			t.Errorf("minmargin %q margin %q, buylist %v: tiebreak %q, want %q", tc.minmargin, tc.margin, tc.blMode, got, tc.want)
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
		UploadEntry: &UploadEntry{CardID: "card", OriginalPrice: 3.5, PriceIsMarket: true, IgnoredCondition: mtgban.SP},
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
	if got[0].LoadedPrice != 3.5 || !got[0].LoadedIsMarket || got[0].LoadedCondition != mtgban.SP {
		t.Errorf("loaded %v (market %v) in %q, want the market's 3.5 in SP", got[0].LoadedPrice, got[0].LoadedIsMarket, got[0].LoadedCondition)
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

// TestOptimizerMarksMarketPrice marks a row's loaded price that is the
// file's market price, as a result row's is.
func TestOptimizerMarksMarketPrice(t *testing.T) {
	out := renderUpload(t, PageVars{UploadVars: UploadVars{
		Optimized:           map[string][]OptimizedUploadEntry{"CK": {{CardID: "a", Quantity: 2, LoadedPrice: 3.5, LoadedIsMarket: true}}},
		OptimizedKeys:       []string{"CK"},
		OptimizedTotals:     map[string]float64{"CK": 1},
		OptimizedQuantities: map[string]int{"CK": 2},
	}})
	if !strings.Contains(out, `data-share-price="3.5m"`) {
		t.Error("the row does not mark its loaded price as the market's")
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

// TestOptimizerShowsTheLoadedQuantity puts the grade and quantity beside
// the loaded price, with no price too, and sorts the cell on the price alone.
func TestOptimizerShowsTheLoadedQuantity(t *testing.T) {
	for _, tc := range []struct {
		entry OptimizedUploadEntry
		want  string
	}{
		{OptimizedUploadEntry{CardID: "a", Price: 5, Quantity: 3}, `<td class="opt-loaded" data-sort="5.00">`},
		{OptimizedUploadEntry{CardID: "a", Price: 5, Quantity: 3}, `5.00</button></span><button type="button" class="ures-edit-btn opt-cond-btn" data-edit="cond" title="Change the condition">NM</button><span class="loaded-qty"><button type="button" class="ures-edit-btn opt-qty-btn" data-edit="qty" title="Change the copies in your list">&times;3</button></span>`},
		{OptimizedUploadEntry{CardID: "a", Quantity: 4}, `<span class="loaded"></span><button type="button" class="ures-edit-btn opt-cond-btn" data-edit="cond" title="Change the condition">NM</button><span class="loaded-qty"><button type="button" class="ures-edit-btn opt-qty-btn" data-edit="qty" title="Change the copies in your list">&times;4</button></span>`},
		{OptimizedUploadEntry{CardID: "a"}, `<span class="loaded"></span><button type="button" class="ures-edit-btn opt-cond-btn" data-edit="cond" title="Change the condition">NM</button><span class="loaded-qty"></span>`},
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
	keys := map[string]uploadsort.Keys{"a": {Name: "counterspell", Set: "1999-04-11 seventh edition", Release: "1999-04-11", Number: "67", Finish: "0 nonfoil", Color: "1.01", Rarity: "3"}}
	want := `data-k-name="counterspell" data-k-set="1999-04-11 seventh edition" data-k-release="1999-04-11" data-k-number="67" data-k-finish="0 nonfoil" data-k-color="1.01" data-k-rarity="3"`
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

// TestOptimizerListsLeftovers lists, after the stores' sections, a buylist
// row whose offers the minimum value drops under Filtered out with its best
// offer and the stores it can be moved to, and one neither a store nor the
// bulk shelf buys under Not bought, and neither at retail.
func TestOptimizerListsLeftovers(t *testing.T) {
	cards := closeVendors(t)
	bulk := bulkrates.New(backend())
	var extra string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err != nil || slices.Contains(cards, id) {
			continue
		}
		_, bulkTakes := bulk.Offer(co)
		if !bulkTakes {
			extra = id
			break
		}
	}
	inv := mtgban.InventoryRecord{}
	for k, card := range cards {
		inv[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 5 + float64(k), Quantity: 1}}
	}
	withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(inv, sessionInfo("ZZS"))}, currentPrices().vendors)

	// Both vendors pay under 6 for the first card, and ZZS sells it for 5
	page := func(blMode bool, minval string, stores ...string) string {
		form := url.Values{}
		form.Set("mode", fmt.Sprint(blMode))
		form["stores"] = stores
		form.Set("minmargin", "true")
		form.Set("margin", "10")
		form.Set("lowval", "")
		form.Set("lowvalabs", "true")
		form.Set("minval", minval)
		var rows strings.Builder
		for _, card := range append(slices.Clone(cards), extra) {
			fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
		}
		form.Set("rows", rows.String())
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		testSite.Upload(rec, req)
		return rec.Body.String()
	}

	buylist := page(true, "6", "ZZV", "ZZW")
	stores, _, _ := strings.Cut(buylist, `id="opt-filtered-out"`)
	if strings.Contains(stores, `data-opt-id="`+cards[0]+`"`) {
		t.Error("the first card is in a store's list although its offers are under the minimum")
	}
	for _, tc := range []struct {
		id, card string
		want     []string
	}{
		{"opt-filtered-out", cards[0], []string{"Session ZZW", `<a href="/go/b/ZZW/`, `data-move="ZZW:5.50,ZZV:5.00"`, "opt-move-btn"}},
		{"opt-not-bought", extra, nil},
	} {
		section := leftoverRows(buylist, tc.id)
		if n := strings.Count(section, "<tr data-opt-id="); n != 1 {
			t.Errorf("%s lists %d rows, want 1", tc.id, n)
		}
		co, err := backend().GetUUID(tc.card)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(section, co.Name) {
			t.Errorf("%s does not name %s", tc.id, co.Name)
		}
		for _, w := range tc.want {
			if !strings.Contains(section, w) {
				t.Errorf("%s lacks %s", tc.id, w)
			}
		}
		if tc.want == nil && (strings.Contains(section, "/go/b/") || strings.Contains(section, "data-move=")) {
			t.Errorf("%s shows an offer or a move for a card no store buys", tc.id)
		}
	}

	retail := page(false, "6", "ZZS")
	if !strings.Contains(retail, `id="panel-optimizer"`) {
		t.Fatal("no optimizer at retail")
	}
	if strings.Contains(retail, `id="opt-not-bought"`) || strings.Contains(retail, `id="opt-filtered-out"`) {
		t.Error("a leftover section at retail")
	}

	// With every offer under the minimum the tab still opens, on the leftovers
	none := page(true, "100", "ZZV", "ZZW")
	if !strings.Contains(none, "showResTab('optimizer'") || strings.Contains(none, "data-load-idx=") {
		t.Error("no Optimizer tab, or a store's list, when the filters drop every row")
	}
	for id, want := range map[string]int{"opt-filtered-out": len(cards), "opt-not-bought": 1} {
		if n := strings.Count(leftoverRows(none, id), "<tr data-opt-id="); n != want {
			t.Errorf("%s lists %d rows when the filters drop every row, want %d", id, n, want)
		}
	}
}

// TestNotBoughtAlertBell draws a price alert bell on each Not bought row,
// on the buylist side at the row's condition and copies, with the dialog it opens, for a reader whose tier
// has alerts; Filtered out rows never get one.
func TestNotBoughtAlertBell(t *testing.T) {
	for _, can := range []bool{false, true} {
		out := renderUpload(t, PageVars{CanAlerts: can, UploadVars: UploadVars{
			UploadEntries: []UploadEntry{{CardID: "a"}, {CardID: "b"}},
			NotBought:     []LeftoverEntry{{CardID: "a", Condition: "SP", Quantity: 3}},
			FilteredOut:   []LeftoverEntry{{CardID: "b", Quantity: 1, Store: "ZZW", Price: 1}},
		}})
		bell := strings.Contains(leftoverRows(out, "opt-not-bought"), `class="opt-move-btn opt-alert-btn alert-link" data-card-id="a" data-side="buylist" data-cond="SP" data-qty="3"`)
		modal := strings.Contains(out, `id="alert-modal"`)
		if bell != can || modal != can {
			t.Errorf("CanAlerts %v: bell %v, dialog %v", can, bell, modal)
		}
		if strings.Contains(leftoverRows(out, "opt-filtered-out"), "opt-alert-btn") {
			t.Errorf("CanAlerts %v: a Filtered out row has a bell", can)
		}
	}
}

// leftoverRows is the body of the page's leftover section id, or nothing.
func leftoverRows(page, id string) string {
	_, section, _ := strings.Cut(page, `id="`+id+`"`)
	_, section, _ = strings.Cut(section, "<tbody>")
	section, _, _ = strings.Cut(section, "</tbody>")
	return section
}

// TestLeftoversMergeOpenedCopies lists copies of a card opened from several
// products as one line, while an uploaded copy stays its own.
func TestLeftoversMergeOpenedCopies(t *testing.T) {
	var l leftovers
	for _, from := range []string{"box-a", "box-b", ""} {
		l.add(uploadRow{UploadEntry: &UploadEntry{CardID: "card", UnpackedFrom: from}, priceKey: "card", qty: 2}, LeftoverEntry{CardID: "card", Quantity: 2})
	}
	if len(l.rows) != 2 || l.rows[0].Quantity != 4 || l.rows[1].Quantity != 2 {
		t.Errorf("listed %+v, want the opened copies as 4 and the uploaded as 2", l.rows)
	}
}

// TestMergedCopiesKeepOnlyACommonOffer keeps the offer link on opened copies
// merged into one line, in a store's list or the leftovers, only when every
// copy's notes name the same offer.
func TestMergedCopiesKeepOnlyACommonOffer(t *testing.T) {
	const a, b = "https://example.com/offer/a", "https://example.com/offer/b"
	for _, tc := range []struct {
		notes []string
		want  string
	}{
		{[]string{a, a}, a},
		{[]string{a, b}, ""},
		{[]string{a, b, a}, ""},
	} {
		rows := uploadRows{
			resultPrices:     map[string]map[string]float64{"card": {"CK": 2}},
			optimizedResults: map[string][]OptimizedUploadEntry{},
			optimizedAt:      map[optimizedKey]int{},
			optimizedTotals:  map[string]float64{},
			optimizedQtys:    map[string]int{},
			tallies:          map[string]*unpackedTally{},
		}
		var l leftovers
		for i, note := range tc.notes {
			entry := &UploadEntry{CardID: "card", Notes: note, UnpackedFrom: fmt.Sprint("deck", i)}
			row := uploadRow{UploadEntry: entry, priceKey: "card", qty: 1}
			rows.optimizeRow(row, map[string]float64{"CK": 2}, []string{"CK"}, uploadSettings{maxQty: 10}, uploadIndexes{})
			l.add(row, LeftoverEntry{CardID: "card", Quantity: 1, Notes: note})
		}
		got := rows.optimizedResults["CK"]
		if len(got) != 1 || got[0].Notes != tc.want {
			t.Errorf("notes %q: CK lists %+v, want one row noting %q", tc.notes, got, tc.want)
		}
		if len(l.rows) != 1 || l.rows[0].Notes != tc.want {
			t.Errorf("notes %q: leftovers %+v, want one row noting %q", tc.notes, l.rows, tc.want)
		}
	}
}

// TestResultsStoreColumnsMove marks the columns of the stores the list was
// priced against as draggable, with an × while another would be left, and
// leaves the custom buylist's column and a reader who may not change stores
// without either. The reload form carries a dragged order on.
func TestResultsStoreColumnsMove(t *testing.T) {
	vars := func(canChange bool, picked ...string) PageVars {
		return PageVars{UploadVars: UploadVars{
			CanChangeStores: canChange,
			EnabledSellers:  picked,
			ScraperKeys:     []string{"CK", "SCG", "custom"},
			UploadEntries:   []UploadEntry{{CardID: "a"}},
			SinglesEntries:  []UploadEntry{{CardID: "a"}},
			StoreOrder:      []string{"SCG", "CK"},
		}}
	}
	drop := `<button type="button" class="ures-store-drop"`
	out := renderUpload(t, vars(true, "CK", "SCG"))
	for _, w := range []string{
		`data-store="CK" data-store-kind="singles" draggable="true">`,
		`data-store="SCG" data-store-kind="singles" draggable="true">`,
		`<input type="hidden" name="stores" value="SCG"><input type="hidden" name="stores" value="CK">`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("no %s", w)
		}
	}
	if strings.Contains(out, `data-store="custom"`) {
		t.Error("the custom buylist's column moves")
	}
	if n := strings.Count(out, drop); n != 2 {
		t.Errorf("%d columns drop, want 2", n)
	}
	if out := renderUpload(t, vars(true, "CK")); strings.Count(out, drop) != 0 {
		t.Error("the one store left drops")
	}
	if out := renderUpload(t, vars(false, "CK", "SCG")); strings.Contains(out, `data-store-kind=`) || strings.Count(out, drop) != 0 {
		t.Error("columns move for a reader who may not change stores")
	}
}
