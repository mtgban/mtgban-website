package alerts

import (
	"math"
	"strings"
	"testing"
)

func validAlert() Alert {
	return Alert{
		Game: "magic", CardID: "abc", Side: SideBuylist, Condition: "NM",
		ReferencePrice: 10, Above: Threshold{Kind: KindAbs, Value: 12},
		Delivery: DeliveryDiscord,
	}
}

func TestValidateAcceptsAMinimalAlert(t *testing.T) {
	a := validAlert()
	err := a.Validate()
	if err != nil {
		t.Fatalf("valid alert refused: %v", err)
	}
}

// An alert on stores offering nothing yet has no reference to default to;
// dollar thresholds need none and are not held against one.
func TestValidateAcceptsDollarsWithoutReference(t *testing.T) {
	a := validAlert()
	a.ReferencePrice = 0
	a.Above.Value = 5
	a.Below = Threshold{Kind: KindAbs, Value: 15}
	err := a.Validate()
	if err != nil {
		t.Fatalf("dollar alert without a reference refused: %v", err)
	}
	a.ReferencePrice = 10
	err = a.Validate()
	if err != nil {
		t.Fatalf("dollar alert held against its reference: %v", err)
	}
}

func TestValidateRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(a *Alert)
		want string
	}{
		{"no threshold", func(a *Alert) { a.Above = Threshold{} }, "threshold"},
		{"bad side", func(a *Alert) { a.Side = "both" }, "side"},
		{"bad condition", func(a *Alert) { a.Condition = "LP" }, "condition"},
		{"bad delivery", func(a *Alert) { a.Delivery = "pigeon" }, "delivery"},
		{"negative reference", func(a *Alert) { a.ReferencePrice = -1 }, "reference"},
		{"pct without reference", func(a *Alert) { a.ReferencePrice, a.Above = 0, Threshold{Kind: KindPct, Value: 20} }, "reference"},
		{"negative value", func(a *Alert) { a.Above.Value = -1 }, "value"},
		{"pct below 100", func(a *Alert) { a.Below = Threshold{Kind: KindPct, Value: 100} }, "below"},
		{"bad kind", func(a *Alert) { a.Above.Kind = "ratio" }, "kind"},
		{"empty card", func(a *Alert) { a.CardID = "" }, "card"},
		{"blank store", func(a *Alert) { a.Stores = []string{"CK", ""} }, "store"},
		{"rounds to zero", func(a *Alert) { a.Above.Value = 0.004 }, "above zero"},
		{"infinite value", func(a *Alert) { a.Above.Value = math.Inf(1) }, "finite"},
		{"too large", func(a *Alert) { a.Above.Value = 1e8 }, "too large"},
		{"above under reference", func(a *Alert) { a.Above.Value, a.Below = 5, Threshold{Kind: KindPct, Value: 20} }, "over the reference"},
		{"below over reference", func(a *Alert) {
			a.Below, a.Above = Threshold{Kind: KindAbs, Value: 15}, Threshold{Kind: KindPct, Value: 20}
		}, "under the reference"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAlert()
			tc.mut(&a)
			err := a.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateRoundsToCents(t *testing.T) {
	a := validAlert()
	a.ReferencePrice = 10.001
	a.Above.Value = 12.006
	err := a.Validate()
	if err != nil {
		t.Fatalf("valid alert refused: %v", err)
	}
	if a.ReferencePrice != 10.0 {
		t.Fatalf("reference price = %v, want 10", a.ReferencePrice)
	}
	if a.Above.Value != 12.01 {
		t.Fatalf("above value = %v, want 12.01", a.Above.Value)
	}
}

func TestValidateTrimsAndDedupesStores(t *testing.T) {
	a := validAlert()
	a.Stores = []string{" CK ", "ck", "TCG", " tcg"}
	err := a.Validate()
	if err != nil {
		t.Fatalf("valid alert refused: %v", err)
	}
	want := []string{"CK", "TCG"}
	if len(a.Stores) != len(want) {
		t.Fatalf("stores = %v, want %v", a.Stores, want)
	}
	for i, s := range want {
		if a.Stores[i] != s {
			t.Fatalf("stores = %v, want %v", a.Stores, want)
		}
	}
}

func TestThresholdResolve(t *testing.T) {
	got := (Threshold{Kind: KindAbs, Value: 12}).Resolve(10, true)
	if got != 12 {
		t.Fatalf("abs above = %v, want 12", got)
	}
	got = (Threshold{Kind: KindPct, Value: 20}).Resolve(10, true)
	if got != 12 {
		t.Fatalf("pct above = %v, want 12", got)
	}
	got = (Threshold{Kind: KindPct, Value: 15}).Resolve(10, false)
	if got != 8.5 {
		t.Fatalf("pct below = %v, want 8.5", got)
	}
	got = (Threshold{Kind: KindPct, Value: 10}).Resolve(3, true)
	if got != 3.30 {
		t.Fatalf("pct 10 of 3.00 = %v, want exactly 3.30", got)
	}
	if (Threshold{}).Set() {
		t.Fatal("empty threshold reports set")
	}
}
