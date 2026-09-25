package main

import (
	"strings"
	"testing"
)

// A PriceUnitCount vendor's row - the shape searchVendorsNG now builds - must
// render the quantity where the price would otherwise go, on both the
// desktop and mobile search pages. This is a render-level check rather than
// a unit test on searchVendorsNG's output, because the two templates decide
// what to show independently, and it is exactly that decision that read the
// field wrong before it was even being set.
func quantityPriorityPage(mobile bool) PageVars {
	const id = "card"
	return PageVars{
		BetaNav:     &NavElem{Short: "b"},
		IsMobile:    mobile,
		SearchQuery: "a card",
		SearchRan:   true,
		AllKeys:     []string{id},
		CondKeys:    []string{"INDEX", "NM"},
		Metadata:    map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
		FoundSellers: map[string]map[string][]SearchEntry{
			id: {},
		},
		FoundVendors: map[string]map[string][]SearchEntry{
			id: {"INDEX": {
				{ScraperName: "SYP", Shorthand: "SYP", Price: 5.00, Quantity: 12, PriceUnit: PriceUnitCount},
			}},
		},
	}
}

func TestQuantityPriorityRendersAsCountNotPrice(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, quantityPriorityPage(mobile))

		// The slot itself: a bare "12" is on every page already, in the
		// favicon link's sizes="120x120".
		want := `<span class="cur">#</span><span class="amt">12</span>`
		if mobile {
			want = `<span class="m-vendor-price"># 12</span>`
		}
		if !strings.Contains(out, want) {
			t.Errorf("mobile=%v: the price slot does not read %s", mobile, want)
		}
		if strings.Contains(out, "5.00") {
			t.Errorf("mobile=%v: the price (5.00) rendered even though the vendor's unit is a count", mobile)
		}
	}
}
