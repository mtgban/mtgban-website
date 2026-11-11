package uploadtie

import (
	"slices"
	"testing"
)

// order sorts stores the way the optimizer orders a tie.
func order(t Breaker, stores ...string) []string {
	out := slices.Clone(stores)
	slices.SortFunc(out, t.Compare)
	return out
}

var rates = map[string]Rates{
	"CK":   {Credit: 1.3, Market: 0.8},
	"SCG":  {Credit: 1.3},
	"CSI":  {Credit: 1.25, Market: 0.9},
	"TCGD": {},
}

func TestBreakers(t *testing.T) {
	for _, tc := range []struct {
		name string
		tie  Breaker
		want []string
	}{
		{"shorthand", Breaker{}, []string{"CK", "CSI", "SCG", "TCGD"}},
		// Credit: 1.3 ties CK and SCG; CK's market credit (1.04) beats
		// SCG's, which counts at cash (1)
		{"credit", ByCredit(Credit, "", rates), []string{"CK", "SCG", "CSI", "TCGD"}},
		// Market: CSI 1.125, CK 1.04, then SCG and TCGD at cash, SCG on credit
		{"market credit", ByCredit(MarketCredit, "", rates), []string{"CSI", "CK", "SCG", "TCGD"}},
		// Offers already in credit: an equal credit offer is more cash at
		// the lower multiplier, and TCGD pays none so never ties
		{"credit offers by market", ByCredit(MarketCredit, Credit, rates), []string{"CSI", "CK", "SCG", "TCGD"}},
		{"custom", ByOrder([]string{"SCG", "TCGD", "SCG"}), []string{"SCG", "TCGD", "CK", "CSI"}},
		{"share", ByShare(Shares{"CSI": 40, "TCGD": 12.5}), []string{"CSI", "TCGD", "CK", "SCG"}},
	} {
		got := order(tc.tie, "TCGD", "SCG", "CSI", "CK")
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSharesAdd(t *testing.T) {
	s := Shares{}
	s.Add(map[string]float64{"CK": 10, "SCG": 8, "CSI": 0}, true)
	s.Add(map[string]float64{"CK": 5, "SCG": 5}, true)
	s.Add(map[string]float64{"CK": 2, "SCG": 3, "CSI": 3}, true)
	s.Add(map[string]float64{"CK": 4, "SCG": 6, "CSI": 0}, false)
	s.Add(map[string]float64{}, true)
	want := Shares{"CK": 14}
	if len(s) != len(want) || s["CK"] != want["CK"] {
		t.Errorf("got %v, want %v", s, want)
	}
}
