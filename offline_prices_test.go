package main

import (
	"testing"
	"time"
)

func TestBanprice2Offline(t *testing.T) {
	retail := map[string]map[string]*BanPrice{
		"uuid-a": {
			"CK": {Regular: 0.99, Cond: "NM", Qty: 5,
				Conditions: &BanConditions{NM: 0.99, SP: 0.79},
				Quantities: &BanQuantities{NM: 5}},
		},
		"uuid-b_f": {
			"CK": {Foil: 1.23, QtyFoil: 2},
		},
	}
	buylist := map[string]map[string]*BanPrice{
		"uuid-a": {"ABU": {Regular: 0.27, Cond: "NM"}},
	}
	snap := time.Unix(1770000000, 0).UTC()

	p := banprice2offline("NEO", snap, retail, buylist)

	if p.SetCode != "NEO" || !p.Snapshot.Equal(snap) {
		t.Fatalf("bad header: %+v", p)
	}
	ck := p.Retail["uuid-a"]["CK"]
	if ck == nil || ck.Regular != 0.99 || ck.Cond != "NM" || ck.Qty != 5 {
		t.Fatalf("uuid-a CK mismatch: %+v", ck)
	}
	if ck.Conditions["SP"] != 0.79 || ck.Quantities["NM"] != 5 {
		t.Fatalf("uuid-a CK maps mismatch: %+v", ck)
	}
	if p.Retail["uuid-b_f"]["CK"].Foil != 1.23 || p.Retail["uuid-b_f"]["CK"].QtyFoil != 2 {
		t.Fatal("foil entry mismatch")
	}
	if p.Buylist["uuid-a"]["ABU"].Regular != 0.27 {
		t.Fatal("buylist entry mismatch")
	}
}
