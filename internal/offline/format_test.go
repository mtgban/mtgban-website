package offline

import (
	"bytes"
	"maps"
	"testing"
	"time"
)

func samplePayload() *SetPayload {
	return &SetPayload{
		SetCode:  "NEO",
		Snapshot: time.Unix(1770000000, 0).UTC(),
		Retail: map[string]map[string]*PriceEntry{
			"uuid-aaa": {
				"CK": {
					Regular: 0.99, Cond: "NM", Qty: 5,
					Conditions: map[string]float64{"NM": 0.99, "SP": 0.79},
					Quantities: map[string]int{"NM": 5, "SP": 2},
				},
				"TCGLow": {Regular: 0.41},
			},
			"uuid-bbb_f": {
				"CK": {Foil: 1.23, Cond: "NM", QtyFoil: 2,
					Conditions: map[string]float64{"NM_foil": 1.23}},
			},
		},
		Buylist: map[string]map[string]*PriceEntry{
			"uuid-aaa": {
				"ABU": {Regular: 0.27, Cond: "NM", Qty: 4,
					Conditions: map[string]float64{"NM": 0.27}},
			},
		},
	}
}

// These stop compiling when either type gains a field, so samePayload
// cannot fall behind one without anyone noticing.
var (
	_ = PriceEntry{0, 0, 0, 0, "", 0, 0, 0, 0, nil, nil}
	_ = SetPayload{"", time.Time{}, nil, nil}
)

// samePayload compares two payloads field by field, down to every price.
func samePayload(a, b *SetPayload) bool {
	samePrice := func(x, y *PriceEntry) bool {
		if x == nil || y == nil {
			return x == y
		}
		return x.Regular == y.Regular && x.Foil == y.Foil && x.Etched == y.Etched && x.Sealed == y.Sealed &&
			x.Cond == y.Cond &&
			x.Qty == y.Qty && x.QtyFoil == y.QtyFoil && x.QtyEtched == y.QtyEtched && x.QtySealed == y.QtySealed &&
			maps.Equal(x.Conditions, y.Conditions) && maps.Equal(x.Quantities, y.Quantities)
	}
	sameStores := func(x, y map[string]*PriceEntry) bool {
		return maps.EqualFunc(x, y, samePrice)
	}
	return a.SetCode == b.SetCode && a.Snapshot.Equal(b.Snapshot) &&
		maps.EqualFunc(a.Retail, b.Retail, sameStores) &&
		maps.EqualFunc(a.Buylist, b.Buylist, sameStores)
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	p := samplePayload()
	data, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !samePayload(p, got) {
		t.Errorf("roundtrip mismatch:\nwant %+v\ngot  %+v", p, got)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	a, err := Encode(samplePayload())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(samplePayload())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two encodes of the same payload differ")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     {},
		"bad magic": {0, 1, 2, 3, 4, 5, 6},
		"truncated": func() []byte { d, _ := Encode(samplePayload()); return d[:len(d)/2] }(),
	} {
		if _, err := Decode(data); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestHeaderBytes(t *testing.T) {
	data, err := Encode(samplePayload())
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x4F, 0x46, 0x50, 0x31, FormatVersion, MsgTypeFull}
	if !bytes.Equal(data[:6], want) {
		t.Errorf("header = % x, want % x", data[:6], want)
	}
}
