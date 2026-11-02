package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A retail price shows one tooltip: the market warning where it has one, or
// else what it costs in store credit.
func TestRetailPriceCarriesOneTooltip(t *testing.T) {
	// No TCGMarket price, so every Direct price of a dollar or more looks off.
	var none []mtgban.Seller
	withPrices(t, none, GetVendors())

	const id = "card"
	out := renderPage(t, "search.html", false, PageVars{
		UserNav: &NavElem{Short: "b"},
		SearchVars: SearchVars{
			SearchRan: true,
			AllKeys:   []string{id},
			CondKeys:  []mtgban.Condition{"NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{
				id: {"NM": {
					{ScraperName: "TCG Direct", Shorthand: "TCGDirect", Price: 5, Credit: 4},
					{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 3.85},
				}},
			},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{id: {}},
			SearchQuery:  "a card",
		},
		Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
	})

	if !strings.Contains(out, `title="Price looks off: TCG Market has no price for it.
This price: $ 5.00
TCG Market: none" data-tip="**Price looks off**: TCG Market has no price for it.
|This price|$ 5.00
|TCG Market|none"`) {
		t.Fatal("the Direct price does not look off")
	}
	if strings.Contains(out, "paid with credit: $ 4.00") {
		t.Error("the price that looks off carries its credit title as well")
	}
	if !strings.Contains(out, `title="Equivalent price if paid with credit: $ 3.85"`) {
		t.Error("a price that looks fine lost its credit title")
	}
}

// TestDirectPriceWarning tables a flagged price beside TCG Market's, and
// says so where TCG Market has none.
func TestDirectPriceWarning(t *testing.T) {
	for _, tc := range []struct {
		price, market float64
		want          string
	}{
		{23934.02, 483.56, "**Price looks off**: over twice TCG Market.\n|This price|$ 23934.02\n|TCG Market|$ 483.56"},
		{5, 0, "**Price looks off**: TCG Market has no price for it.\n|This price|$ 5.00\n|TCG Market|none"},
	} {
		if got := directPriceWarning(tc.price, tc.market); got != tc.want {
			t.Errorf("%.2f against %.2f:\n%s\nwant:\n%s", tc.price, tc.market, got, tc.want)
		}
	}
}

// A buylist offer that looks off stays red, though it reaches the P90 that
// turns any other offer green.
func TestBuylistPriceThatLooksOffIsNotBest(t *testing.T) {
	var none []mtgban.Seller
	withPrices(t, none, GetVendors())

	const id = "card"
	pv := PageVars{
		UserNav: &NavElem{Short: "b"},
		SearchVars: SearchVars{
			SearchRan:    true,
			AllKeys:      []string{id},
			CondKeys:     []mtgban.Condition{"NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{id: {}},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{
				id: {"NM": {
					{ScraperName: "TCG Direct", Shorthand: "TCGDirectNet", Price: 5},
					{ScraperName: "ABU Games", Shorthand: "ABU", Price: 5},
				}},
			},
			SearchQuery: "a card",
		},
		Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST", GoodBuylist: 4}},
	}

	out := renderPage(t, "search.html", false, pv)
	if strings.Count(out, `class="price price-warn"`) != 1 {
		t.Error("the Direct offer is not flagged on its own")
	}
	if strings.Count(out, "price-best") != 1 {
		t.Error("want only the offer that looks fine green")
	}

	pv.IsMobile = true
	if n := strings.Count(renderPage(t, "search.html", true, pv), "m-price-best"); n != 1 {
		t.Errorf("mobile: %d offers green, want only the one that looks fine", n)
	}
}

// An adjusted retail price keeps one tooltip, now two lines, and is marked.
func TestAdjustedRetailPriceTooltip(t *testing.T) {
	var none []mtgban.Seller
	withPrices(t, none, GetVendors())

	const id = "card"
	out := renderPage(t, "search.html", false, PageVars{
		UserNav: &NavElem{Short: "b"},
		SearchVars: SearchVars{
			SearchRan: true,
			AllKeys:   []string{id},
			CondKeys:  []mtgban.Condition{"NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{
				id: {"NM": {
					{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 8, Credit: 6.4, OrigPrice: 10, DiscountPct: 20},
					{ScraperName: "Star City Games", Shorthand: "SCG", Price: 9, OrigPrice: 10, DiscountPct: 10},
					{ScraperName: "TCGplayer", Shorthand: "TCG", Price: 9.5},
					{ScraperName: "TCG Direct", Shorthand: "TCGDirect", Price: 4.5, OrigPrice: 5, DiscountPct: 10},
				}},
			},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{id: {"NM": {
				{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 3.25, MarketCredit: 2.6, OrigCredit: 6.5},
				{ScraperName: "Star City Games", Shorthand: "SCG", Price: 5.5, Credit: 6},
			}}},
			SearchQuery: "a card",
		},
		Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
	})

	if !strings.Contains(out, `class="price price-adjusted" title="Equivalent price if paid with credit: $ 6.40
Store price $ 10.00, your 20% discount applied"`) {
		t.Error("the discounted CK price does not carry the credit and store-price lines in one title")
	}
	if !strings.Contains(out, `class="price price-adjusted" title="Store price $ 10.00, your 10% discount applied"`) {
		t.Error("the discounted SCG price, with no credit, does not carry the store-price title")
	}
	if strings.Count(out, "price-adjusted") != 3 {
		t.Errorf("price-adjusted appears %d times, want 3 (the unadjusted TCG row is not marked)", strings.Count(out, "price-adjusted"))
	}
	// The warning judges the store's own price and keeps the discount line
	warn := regexp.MustCompile(`class="price price-warn price-adjusted" title="([^"]*)"`).FindStringSubmatch(out)
	if warn == nil {
		t.Fatal("the TCG Direct row with no market price is not warned")
	}
	if !strings.Contains(warn[1], "This price: $ 5.00") || !strings.Contains(warn[1], "Store price $ 5.00, your 10% discount applied") {
		t.Errorf("the warning title %q lacks the store price or the discount line", warn[1])
	}
	if !strings.Contains(out, "Credit: $ 3.25\nCredit at face: $ 6.50\nMarket: $ 2.60") {
		t.Error("the buylist row title does not show the adjusted credit with its face value")
	}
	if !strings.Contains(out, `class="buylist-extra adjusted"`) {
		t.Error("the adjusted vendor's secondary span is not marked")
	}
	if strings.Count(out, `buylist-extra adjusted`) != 1 {
		t.Error("the unadjusted SCG vendor row is marked")
	}
}

// Mobile shows the adjusted number where the Best re-pick reads it, and
// the quoted number in the details.
func TestAdjustedPricesOnMobile(t *testing.T) {
	var none []mtgban.Seller
	withPrices(t, none, GetVendors())

	const id = "card"
	out := renderPage(t, "search.html", true, PageVars{
		IsMobile: true,
		UserNav:  &NavElem{Short: "b"},
		SearchVars: SearchVars{
			SearchRan: true,
			AllKeys:   []string{id},
			CondKeys:  []mtgban.Condition{"NM"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{
				id: {"NM": {
					{ScraperName: "Star City Games", Shorthand: "SCG", Price: 9, OrigPrice: 10, DiscountPct: 10},
					{ScraperName: "TCGplayer", Shorthand: "TCG", Price: 9.5},
				}},
			},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{id: {"NM": {
				{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 3.25, MarketCredit: 2.6, OrigCredit: 6.5},
			}}},
			SearchQuery: "a card",
		},
		Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
	})

	if !strings.Contains(out, `<span class="m-vendor-price m-price-adjusted">$ 9.00</span>`) {
		t.Error("the discounted seller's summary price is not the adjusted, marked one")
	}
	if !strings.Contains(out, "Store price") || !strings.Contains(out, `$ 10.00`) {
		t.Error("the details do not show the store's own price")
	}
	if !strings.Contains(out, "Credit at face") || !strings.Contains(out, `$ 6.50`) {
		t.Error("the details do not show the credit at face")
	}
	if !strings.Contains(out, `$ 3.25`) {
		t.Error("the details do not show the adjusted credit")
	}
	if strings.Contains(out, `m-price-adjusted">$ 9.50`) {
		t.Error("the unadjusted TCG row is marked")
	}
}
