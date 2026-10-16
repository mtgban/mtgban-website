package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestParseStoreFactors(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want map[string]storeFactor
	}{
		{"empty", "", nil},
		{"discount only", "CK:10:", map[string]storeFactor{"CK": {Discount: 10}}},
		{"credit only", "CK::85", map[string]storeFactor{"CK": {Credit: 85}}},
		{"both", "CK:10:85", map[string]storeFactor{"CK": {Discount: 10, Credit: 85}}},
		{"two stores and a trailing comma", "CK:10:85,TCG::80,", map[string]storeFactor{"CK": {Discount: 10, Credit: 85}, "TCG": {Credit: 80}}},
		{"face credit is unset", "CK:10:100", map[string]storeFactor{"CK": {Discount: 10}}},
		{"both unset drops the item", "CK::", nil},
		{"discount out of range", "CK:91:", nil},
		{"zero discount", "CK:0:", nil},
		{"credit out of range", "CK::301", nil},
		{"credit under range", "CK::9", nil},
		{"not a number", "CK:ten:", nil},
		{"a float", "CK:12.5:", nil},
		{"two fields", "CK:10", nil},
		{"four fields", "CK:10:85:1", nil},
		{"bad shorthand", "C K:10:", nil},
		{"a bad item leaves the next alone", "CK:91:,TCG:5:", map[string]storeFactor{"TCG": {Discount: 5}}},
	} {
		got := parseStoreFactors(tc.raw)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for k, w := range tc.want {
			if got[k] != w {
				t.Errorf("%s: %s got %+v, want %+v", tc.name, k, got[k], w)
			}
		}
	}
}

func TestParseStoreFactorsCapsItems(t *testing.T) {
	items := make([]string, 300)
	for i := range items {
		items[i] = fmt.Sprintf("S%d:10:", i)
	}
	if got := parseStoreFactors(strings.Join(items, ",")); len(got) > 256 {
		t.Errorf("got %d entries, want at most 256", len(got))
	}
}

func TestReadStoreFactorsFromCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/search?q=x", nil)
	r.AddCookie(&http.Cookie{Name: "SearchStoreFactors", Value: "CK:10:85"})
	got := readStoreFactors(r)
	if got["CK"] != (storeFactor{Discount: 10, Credit: 85}) {
		t.Errorf("got %+v", got)
	}
	if readStoreFactors(httptest.NewRequest(http.MethodGet, "/search", nil)) != nil {
		t.Error("no cookie gave factors")
	}
}

func factorResult() searchResults {
	return searchResults{
		keys: []string{"card"},
		sellers: map[string]map[mtgban.Condition][]SearchEntry{"card": {"NM": {
			{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 10, Credit: 8},
			{ScraperName: "TCGplayer", Shorthand: "TCG", Price: 9},
			{ScraperName: "Custom", Shorthand: "CUSTOM", Price: 10},
			{ScraperName: "Locked", Shorthand: "LOCK", Price: 10, Locked: true},
			{ScraperName: "Wanted", Shorthand: "WANT", Price: 3, PriceUnit: PriceUnitCount},
			{ScraperName: "Empty", Shorthand: "NONE", Price: 0},
		}}},
		vendors: map[string]map[mtgban.Condition][]SearchEntry{"card": {"NM": {
			{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 6.5, MarketCredit: 5.2},
			{ScraperName: "Star City Games", Shorthand: "SCG", Price: 5.5, Credit: 6},
			{ScraperName: "Cash Only", Shorthand: "CASH", Price: 6},
		}}},
	}
}

func TestApplyStoreFactorsSellers(t *testing.T) {
	result := factorResult()
	applyStoreFactors(result, map[string]storeFactor{
		"CK": {Discount: 20, Credit: 50}, "CUSTOM": {Discount: 50}, "LOCK": {Discount: 50},
		"WANT": {Discount: 50}, "NONE": {Discount: 50}, "GONE": {Discount: 50},
	})
	rows := result.sellers["card"]["NM"]
	ck := rows[0]
	if ck.Price != 8 || ck.OrigPrice != 10 || ck.Credit != 6.4 {
		t.Errorf("CK got price %v (orig %v) credit %v, want 8 (10) 6.4", ck.Price, ck.OrigPrice, ck.Credit)
	}
	if ck.DiscountPct != 20 {
		t.Errorf("CK DiscountPct %d, want 20", ck.DiscountPct)
	}
	if !ck.Adjusted() || ck.AdjustTip() != "Store price $ 10.00, your 20% discount applied" {
		t.Errorf("CK tip %q", ck.AdjustTip())
	}
	if ck.RetailTip() != "Equivalent price if paid with credit: $ 6.40\nStore price $ 10.00, your 20% discount applied" {
		t.Errorf("CK retail tip %q", ck.RetailTip())
	}
	if rows[1].Price != 9 || rows[1].Adjusted() || rows[1].RetailTip() != "" {
		t.Errorf("TCG, not in the map, changed: %+v", rows[1])
	}
	for _, i := range []int{2, 3, 4, 5} {
		if rows[i].Adjusted() {
			t.Errorf("%s was adjusted", rows[i].ScraperName)
		}
	}
	if rows[2].Price != 10 || rows[3].Price != 10 || rows[4].Price != 3 || rows[5].Price != 0 {
		t.Errorf("a skipped row's price moved: %+v", rows[2:])
	}
}

func TestApplyStoreFactorsSkipsIndex(t *testing.T) {
	result := searchResults{
		keys: []string{"card"},
		sellers: map[string]map[mtgban.Condition][]SearchEntry{"card": {
			"INDEX": {{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 10}},
			"NM":    {{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 10}},
		}},
		vendors: map[string]map[mtgban.Condition][]SearchEntry{"card": {
			"INDEX": {{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 5, Credit: 6}},
		}},
	}
	applyStoreFactors(result, map[string]storeFactor{"TCGLow": {Discount: 10, Credit: 50}})
	if idx := result.sellers["card"]["INDEX"][0]; idx.Adjusted() || idx.Price != 10 {
		t.Errorf("INDEX seller row was adjusted: %+v", idx)
	}
	if idx := result.vendors["card"]["INDEX"][0]; idx.Adjusted() || idx.Credit != 6 {
		t.Errorf("INDEX vendor row was adjusted: %+v", idx)
	}
	if nm := result.sellers["card"]["NM"][0]; nm.Price != 9 || nm.OrigPrice != 10 {
		t.Errorf("NM row got %+v, want 9 from 10", nm)
	}
}

func TestDiscountWithoutCredit(t *testing.T) {
	result := factorResult()
	applyStoreFactors(result, map[string]storeFactor{"TCG": {Discount: 10}})
	tcg := result.sellers["card"]["NM"][1]
	if tcg.Price != 8.1 || tcg.OrigPrice != 9 || tcg.Credit != 0 {
		t.Errorf("TCG got price %v (orig %v) credit %v, want 8.10 (9) 0", tcg.Price, tcg.OrigPrice, tcg.Credit)
	}
}

func TestScaleCreditFloor(t *testing.T) {
	for _, tc := range []struct {
		credit, market         float64
		wantCredit, wantMarket float64
	}{
		{0.04, 0.03, 0.01, 0.01},
		{0.04, 0, 0.01, 0},
	} {
		e := SearchEntry{Shorthand: "CK", Price: 0.03, Credit: tc.credit, MarketCredit: tc.market}
		e.scaleCredit(10)
		if e.Credit != tc.wantCredit || e.MarketCredit != tc.wantMarket {
			t.Errorf("%v/%v at 10%%: got %v/%v, want %v/%v", tc.credit, tc.market, e.Credit, e.MarketCredit, tc.wantCredit, tc.wantMarket)
		}
	}
}

func TestDiscountOnCheapCards(t *testing.T) {
	for _, tc := range []struct {
		price float64
		pct   int
		want  float64
		tip   string
	}{
		{0.10, 15, 0.09, "Store price $ 0.10, your 15% discount applied"},
		{0.01, 90, 0.01, "Store price $ 0.01, your 90% discount applied"},
		{0.05, 10, 0.05, "Store price $ 0.05, your 10% discount applied"},
	} {
		e := SearchEntry{Shorthand: "CK", Price: tc.price}
		e.discount(tc.pct)
		if e.Price != tc.want || !e.Adjusted() || e.AdjustTip() != tc.tip {
			t.Errorf("%v at %d%%: got %v, tip %q", tc.price, tc.pct, e.Price, e.AdjustTip())
		}
	}
}

func TestApplyStoreFactorsVendors(t *testing.T) {
	result := factorResult()
	applyStoreFactors(result, map[string]storeFactor{"CK": {Discount: 20, Credit: 50}, "CASH": {Credit: 50}})
	rows := result.vendors["card"]["NM"]
	ck := rows[0]
	if ck.Price != 5 || ck.Credit != 3.25 || ck.MarketCredit != 2.6 || ck.OrigCredit != 6.5 {
		t.Errorf("CK got %+v", ck)
	}
	if ck.AdjustTip() != "Credit at face $ 6.50" {
		t.Errorf("CK tip %q", ck.AdjustTip())
	}
	if rows[1].Adjusted() || rows[1].Credit != 6 {
		t.Errorf("SCG, not in the map, changed: %+v", rows[1])
	}
	if rows[2].Adjusted() || rows[2].Price != 6 {
		t.Errorf("a vendor with no credit was adjusted: %+v", rows[2])
	}
}

func TestApplyStoreFactorsNothing(t *testing.T) {
	result := factorResult()
	applyStoreFactors(result, nil)
	if result.sellers["card"]["NM"][0].Adjusted() || result.vendors["card"]["NM"][0].Adjusted() {
		t.Error("no factors adjusted a row")
	}
}

// The offer ordering ranks what the user pays and gets, so a discount
// moves a seller up and a credit value moves a vendor under the credit
// priority.
func TestStoreFactorsRankOffers(t *testing.T) {
	result := factorResult()
	applyStoreFactors(result, map[string]storeFactor{"CK": {Discount: 20}, "SCG": {Credit: 150}})

	r := httptest.NewRequest(http.MethodGet, "/search?q=x", nil)
	sortOfferRows(r, result.keys, result)
	pos := map[string]int{}
	for i, e := range result.sellers["card"]["NM"] {
		pos[e.Shorthand] = i
	}
	if pos["CK"] > pos["TCG"] {
		t.Errorf("CK at 8.00 ranks after TCG at 9.00: %v", pos)
	}
	if got := result.vendors["card"]["NM"][0].Shorthand; got != "CASH" {
		t.Errorf("default buylist order is by cash, got %s first, want CASH", got)
	}

	r.AddCookie(&http.Cookie{Name: "SearchListingPriority", Value: "credit"})
	sortOfferRows(r, result.keys, result)
	if got := result.vendors["card"]["NM"][0].Shorthand; got != "SCG" {
		t.Errorf("credit order after scaling has %s first, want SCG (9.00 credit)", got)
	}
}
