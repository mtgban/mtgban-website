package offline

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// bigPayload builds a payload with enough sites for rate statistics.
func bigPayload() *SetPayload {
	p := &SetPayload{SetCode: "TST", Snapshot: time.Unix(1770000000, 0).UTC(),
		Retail:  map[string]map[string]*PriceEntry{},
		Buylist: map[string]map[string]*PriceEntry{}}
	for i := 0; i < 5000; i++ {
		id := fmt.Sprintf("uuid-%04d", i)
		p.Retail[id] = map[string]*PriceEntry{
			"CK": {Regular: 1.00, Cond: "NM",
				Conditions: map[string]float64{"NM": 1.00, "SP": 0.80}},
		}
	}
	return p
}

func countDiffs(a, b *SetPayload) int {
	n := 0
	for id, byStore := range a.Retail {
		for store, e := range byStore {
			o := b.Retail[id][store]
			if e.Regular != o.Regular {
				n++
			}
			for tag, v := range e.Conditions {
				if v != o.Conditions[tag] {
					n++
				}
			}
		}
	}
	return n
}

func TestWatermarkDeterministic(t *testing.T) {
	a, b := bigPayload(), bigPayload()
	Watermark([]byte("secret"), "user@example.com", a)
	Watermark([]byte("secret"), "user@example.com", b)
	if countDiffs(a, b) != 0 {
		t.Error("same secret and email produced different watermarks")
	}
}

func TestWatermarkEmailsDiffer(t *testing.T) {
	a, b := bigPayload(), bigPayload()
	Watermark([]byte("secret"), "user1@example.com", a)
	Watermark([]byte("secret"), "user2@example.com", b)
	if countDiffs(a, b) == 0 {
		t.Error("different emails produced identical watermarks")
	}
}

func TestWatermarkRateAndDelta(t *testing.T) {
	clean, marked := bigPayload(), bigPayload()
	Watermark([]byte("secret"), "user@example.com", marked)

	changed := 0
	total := 0
	for id, byStore := range clean.Retail {
		for store, e := range byStore {
			m := marked.Retail[id][store]
			for tag, v := range e.Conditions {
				total++
				d := math.Abs(m.Conditions[tag] - v)
				if d != 0 {
					changed++
					if math.Abs(d-0.01) > 1e-9 {
						t.Fatalf("delta %f is not one cent", d)
					}
				}
			}
		}
	}
	if changed == 0 {
		t.Error("no sites were watermarked")
	}
	if rate := float64(changed) / float64(total); rate > 0.03 {
		t.Errorf("watermark rate %f too high", rate)
	}
}

func TestWatermarkSkipsCheapAndStaysConsistent(t *testing.T) {
	p := &SetPayload{SetCode: "TST", Snapshot: time.Unix(0, 0),
		Retail: map[string]map[string]*PriceEntry{},
		Buylist: map[string]map[string]*PriceEntry{}}
	for i := 0; i < 2000; i++ {
		id := fmt.Sprintf("uuid-%04d", i)
		p.Retail[id] = map[string]*PriceEntry{
			"CK": {Regular: 0.10, Cond: "NM",
				Conditions: map[string]float64{"NM": 0.10}},
			"SCG": {Regular: 4.00, Cond: "NM",
				Conditions: map[string]float64{"NM": 4.00}},
		}
	}
	Watermark([]byte("secret"), "user@example.com", p)
	for id, byStore := range p.Retail {
		if byStore["CK"].Regular != 0.10 || byStore["CK"].Conditions["NM"] != 0.10 {
			t.Fatalf("%s: price under 25 cents was perturbed", id)
		}
		if byStore["SCG"].Regular != byStore["SCG"].Conditions["NM"] {
			t.Fatalf("%s: finish price and NM condition diverged", id)
		}
	}
}
