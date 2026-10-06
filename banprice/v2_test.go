package banprice

import (
	"encoding/json"
	"testing"
)

func TestMerge(t *testing.T) {
	v := V2{}
	add := func(id, finish, store string, e Entry, buying bool) {
		if v[id] == nil {
			v[id] = map[string]map[string][]Entry{}
		}
		if v[id][finish] == nil {
			v[id][finish] = map[string][]Entry{}
		}
		v[id][finish][store] = Merge(v[id][finish][store], e, buying)
	}
	add("600001", "nonfoil", "CT", Entry{Condition: "SP", Price: 0.8, Qty: 1}, false)
	add("600001", "nonfoil", "CT", Entry{Condition: "NM", Price: 1.5, Qty: 2, Available: 4}, false)
	add("600001", "nonfoil", "CT", Entry{Condition: "PO", Price: 0.2, Qty: 1}, false)
	add("600001", "nonfoil", "CT", Entry{Condition: "NM", Price: 1, Qty: 3, Available: 9}, false)
	add("600001", "nonfoil", "CT", Entry{Condition: "MP", Price: 0.5}, false)
	add("600001", "nonfoil", "MKMTrend", Entry{Price: 1.2}, false)
	add("600001", "nonfoil", "MKMTrend", Entry{Price: 1.1}, false)
	add("600001", "coldfoil", "CK", Entry{Condition: "NM", Price: 20, Qty: 4}, true)
	add("600001", "coldfoil", "CK", Entry{Condition: "NM", Price: 22, Qty: 1}, true)
	add("box", FinishSealed, "CT", Entry{Price: 99, Qty: 5}, false)

	wire, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"600001":{` +
		`"coldfoil":{"CK":[{"condition":"NM","price":22,"qty":5}]},` +
		`"nonfoil":{` +
		`"CT":[{"condition":"NM","price":1,"qty":5,"available":13},{"condition":"SP","price":0.8,"qty":1},{"condition":"MP","price":0.5},{"condition":"PO","price":0.2,"qty":1}],` +
		`"MKMTrend":[{"price":1.1}]}},` +
		`"box":{"sealed":{"CT":[{"price":99,"qty":5}]}}}`
	if string(wire) != want {
		t.Errorf("v2 =\n%s\nwant\n%s", wire, want)
	}
}
