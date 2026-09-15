package main

import (
	"strings"
	"testing"
)

// A QuantityPriority vendor's row - the shape searchVendorsNG now builds -
// must render the quantity where the price would otherwise go, on both the
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
		AllKeys:     []string{id},
		CondKeys:    []string{"INDEX", "NM"},
		Metadata:    map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
		FoundSellers: map[string]map[string][]SearchEntry{
			id: {},
		},
		FoundVendors: map[string]map[string][]SearchEntry{
			id: {"INDEX": {
				{ScraperName: "SYP", Shorthand: "SYP", Price: 5.00, Quantity: 12, QuantityPriority: true},
			}},
		},
	}
}

func TestQuantityPriorityRendersAsCountNotPrice(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, quantityPriorityPage(mobile))

		if !strings.Contains(out, "12") {
			t.Errorf("mobile=%v: the quantity (12) is missing from the row", mobile)
		}
		if strings.Contains(out, "5.00") {
			t.Errorf("mobile=%v: the price (5.00) rendered even though the vendor is QuantityPriority", mobile)
		}
	}
}
