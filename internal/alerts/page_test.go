package alerts

import (
	"slices"
	"testing"
)

func TestDeepLink(t *testing.T) {
	for _, c := range []struct{ edit, card, remove, want string }{
		{"12", "", "", "edit"}, {"", "abc", "", "card"}, {"12", "abc", "", "edit"}, {"", "", "12", "remove"}, {"", "", "", ""},
	} {
		if got := DeepLink(c.edit, c.card, c.remove); got != c.want {
			t.Errorf("DeepLink(%q, %q, %q) = %q, want %q", c.edit, c.card, c.remove, got, c.want)
		}
	}
}

// ?remove= names one of the reader's alerts.
func TestRemoving(t *testing.T) {
	views := []View{{Alert: Alert{ID: 3, CardID: "card-1", Status: StatusActive}}}
	for _, c := range []struct {
		remove string
		want   int64
	}{{"3", 3}, {"4", 0}, {"x", 0}, {"", 0}} {
		if got := Removing(views, c.remove); got != c.want {
			t.Errorf("Removing(%q) = %d, want %d", c.remove, got, c.want)
		}
	}
}

// The Optimize button sends each alert at the copies it notes or 1, its
// target as the row's price, on the side most of them are, buylist on a tie.
func TestOptimizeRows(t *testing.T) {
	sell := Alert{CardID: "a", Side: SideBuylist, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindPct, Value: 20}, Below: Threshold{Kind: KindAbs, Value: 5}}
	buy := Alert{CardID: "b", Side: SideRetail, Condition: "SP", Quantity: 3, ReferencePrice: 10,
		Below: Threshold{Kind: KindAbs, Value: 7.5}}
	// The same card and grade as sell, watched on retail.
	rebuy := Alert{CardID: "a", Side: SideRetail, Condition: "NM", Quantity: 2,
		Below: Threshold{Kind: KindAbs, Value: 8}}

	for name, tc := range map[string]struct {
		alerts      []Alert
		want        []OptimizeRow
		wantBuylist bool
	}{
		"a tie opens buylist":   {[]Alert{sell, buy}, []OptimizeRow{{"a", 1, "NM", "12.00"}, {"b", 3, "SP", "7.50"}}, true},
		"most are retail":       {[]Alert{sell, buy, buy}, []OptimizeRow{{"a", 1, "NM", "12.00"}, {"b", 3, "SP", "7.50"}}, false},
		"one card, both sides":  {[]Alert{rebuy, sell}, []OptimizeRow{{"a", 1, "NM", "12.00"}}, true},
		"one card, retail wins": {[]Alert{sell, rebuy, buy}, []OptimizeRow{{"a", 2, "NM", "8.00"}, {"b", 3, "SP", "7.50"}}, false},
		"none":                  {nil, nil, true},
	} {
		views := make([]View, len(tc.alerts))
		for i, a := range tc.alerts {
			views[i] = View{Alert: a}
		}
		rows, buylist := OptimizeRows(views)
		if !slices.Equal(rows, tc.want) {
			t.Errorf("%s: rows = %v, want %v", name, rows, tc.want)
		}
		if buylist != tc.wantBuylist {
			t.Errorf("%s: opens on buylist %v, want %v", name, buylist, tc.wantBuylist)
		}
	}
}
