package alerts

import (
	"testing"
	"time"
)

func evalAlert() Alert {
	return Alert{
		ReferencePrice: 10, Above: Threshold{Kind: KindAbs, Value: 12}, Below: Threshold{Kind: KindPct, Value: 20},
		AboveArmed: true, BelowArmed: true,
	}
}

func TestEvaluateFiresAboveAndDisarms(t *testing.T) {
	now := time.Now()
	d := Evaluate(evalAlert(), []Quote{{"CK", 11}, {"SCG", 12}}, now, 6*time.Hour)
	if !d.FireAbove || d.FireBelow || len(d.AboveHits) != 1 || d.AboveHits[0].Store != "SCG" {
		t.Fatalf("decision = %+v", d)
	}
	if d.AboveArmed || !d.BelowArmed {
		t.Fatalf("armed flags = %v %v", d.AboveArmed, d.BelowArmed)
	}
}

func TestEvaluateFiresBelowOnPercent(t *testing.T) {
	d := Evaluate(evalAlert(), []Quote{{"CK", 8}}, time.Now(), 0)
	if !d.FireBelow || d.FireAbove || d.BelowArmed {
		t.Fatalf("decision = %+v", d)
	}
}

func TestEvaluateStaysQuietWhileHeld(t *testing.T) {
	a := evalAlert()
	a.AboveArmed = false
	d := Evaluate(a, []Quote{{"CK", 13}}, time.Now(), 0)
	if d.FireAbove || d.AboveArmed {
		t.Fatalf("held crossing re-fired or re-armed: %+v", d)
	}
}

func TestEvaluateRearmsWhenBackAcross(t *testing.T) {
	a := evalAlert()
	a.AboveArmed = false
	d := Evaluate(a, []Quote{{"CK", 11}}, time.Now(), 0)
	if !d.AboveArmed || d.FireAbove {
		t.Fatalf("did not re-arm: %+v", d)
	}
	// No quotes at all is no evidence; the side stays disarmed.
	d = Evaluate(a, nil, time.Now(), 0)
	if d.AboveArmed || d.FireAbove {
		t.Fatalf("empty quotes re-armed: %+v", d)
	}
}

func TestEvaluateThrottlesInsideTheGap(t *testing.T) {
	a := evalAlert()
	fired := time.Now().Add(-time.Hour)
	a.LastFiredAt = &fired
	d := Evaluate(a, []Quote{{"CK", 13}}, time.Now(), 6*time.Hour)
	if d.FireAbove || !d.AboveArmed || !d.Throttled {
		t.Fatalf("throttle: %+v", d)
	}
	d = Evaluate(a, []Quote{{"CK", 13}}, time.Now().Add(7*time.Hour), 6*time.Hour)
	if !d.FireAbove || d.Throttled {
		t.Fatalf("after the gap: %+v", d)
	}
}

func TestEvaluateIgnoresUnsetSide(t *testing.T) {
	a := evalAlert()
	a.Below = Threshold{}
	d := Evaluate(a, []Quote{{"CK", 1}}, time.Now(), 0)
	if d.FireBelow || !d.BelowArmed {
		t.Fatalf("unset below acted: %+v", d)
	}
}

func TestEvaluateWatchesTheBestPrice(t *testing.T) {
	// A pricier ask or a lower offer elsewhere is not a crossing: only the
	// best quote, the one the reference defaults to, decides.
	retail := Alert{
		Side: SideRetail, ReferencePrice: 10, AboveArmed: true, BelowArmed: true,
		Above: Threshold{Kind: KindPct, Value: 20}, Below: Threshold{Kind: KindPct, Value: 20},
	}
	d := Evaluate(retail, []Quote{{"TCG", 10}, {"CK", 14.99}, {"SCG", 12.5}}, time.Now(), 0)
	if d.FireAbove || d.FireBelow {
		t.Fatalf("retail fired on a store other than the cheapest: %+v", d)
	}
	buylist := retail
	buylist.Side, buylist.ReferencePrice = SideBuylist, 8
	d = Evaluate(buylist, []Quote{{"CK", 8}, {"SCG", 5}, {"ABU", 6.4}}, time.Now(), 0)
	if d.FireAbove || d.FireBelow {
		t.Fatalf("buylist fired on a store other than the best offer: %+v", d)
	}
	d = Evaluate(buylist, []Quote{{"CK", 6.3}, {"SCG", 5}}, time.Now(), 0)
	if !d.FireBelow || len(d.BelowHits) != 2 {
		t.Fatalf("best offer dropped below the line and did not fire: %+v", d)
	}
}

func TestStartArmedSkipsALineAlreadyPast(t *testing.T) {
	a := Alert{
		Side: SideRetail, ReferencePrice: 20,
		Above: Threshold{Kind: KindAbs, Value: 25}, Below: Threshold{Kind: KindPct, Value: 20},
	}
	above, below := startArmed(a, 15, true)
	if !above || below {
		t.Fatalf("best 15 against below 16: above=%v below=%v, want true false", above, below)
	}
	above, below = startArmed(a, 0, false)
	if !above || !below {
		t.Fatalf("no price is no evidence: above=%v below=%v, want both armed", above, below)
	}
}

func TestEvaluateThrottlesBelowInsideTheGap(t *testing.T) {
	a := Alert{
		ReferencePrice: 10, Below: Threshold{Kind: KindAbs, Value: 8},
		BelowArmed: true,
	}
	fired := time.Now().Add(-time.Hour)
	a.LastFiredAt = &fired
	d := Evaluate(a, []Quote{{"CK", 7}}, time.Now(), 6*time.Hour)
	if d.FireBelow || !d.BelowArmed || !d.Throttled {
		t.Fatalf("throttle below: %+v", d)
	}
}

func TestEvaluateAbovePercent(t *testing.T) {
	a := Alert{
		ReferencePrice: 10, Above: Threshold{Kind: KindPct, Value: 20},
		AboveArmed: true,
	}
	d := Evaluate(a, []Quote{{"CK", 12}}, time.Now(), 0)
	if !d.FireAbove {
		t.Fatalf("12 should fire against pct 20 of 10: %+v", d)
	}
	d = Evaluate(a, []Quote{{"CK", 11.99}}, time.Now(), 0)
	if d.FireAbove {
		t.Fatalf("11.99 should not fire against pct 20 of 10: %+v", d)
	}
}

func TestEvaluateHitsBestFirst(t *testing.T) {
	a := Alert{
		Side: SideBuylist, ReferencePrice: 10, Above: Threshold{Kind: KindAbs, Value: 12},
		AboveArmed: true,
	}
	d := Evaluate(a, []Quote{{"A", 13}, {"B", 11}, {"C", 14}}, time.Now(), 0)
	if len(d.AboveHits) != 2 || d.AboveHits[0].Store != "C" || d.AboveHits[1].Store != "A" {
		t.Fatalf("buylist hits should be C then A: %+v", d.AboveHits)
	}
	a.Side, a.Above, a.Below, a.BelowArmed = SideRetail, Threshold{}, Threshold{Kind: KindAbs, Value: 8}, true
	d = Evaluate(a, []Quote{{"A", 7}, {"B", 9}, {"C", 6}}, time.Now(), 0)
	if len(d.BelowHits) != 2 || d.BelowHits[0].Store != "C" || d.BelowHits[1].Store != "A" {
		t.Fatalf("retail hits should be C then A: %+v", d.BelowHits)
	}
}
