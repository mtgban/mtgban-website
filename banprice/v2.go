package banprice

import "slices"

// FinishSealed is the finish a sealed product is filed under in V2, having
// no finish of its own.
const FinishSealed = "sealed"

// Grades are the grades an Entry can carry, best first.
var Grades = []string{"NM", "SP", "MP", "HP", "PO"}

// Entry is one grade of one finish at one store. Grade is empty for an
// index price and for sealed product, which are not graded. Qty is empty
// where the store reports none; on a buylist that means no limit.
type Entry struct {
	Grade string  `json:"grade,omitempty"`
	Price float64 `json:"price"`
	Qty   int     `json:"qty,omitempty"`
}

// V2 is the price map of the v2 API: card id, then finish, then store, then
// that store's prices, one per grade, best grade first.
type V2 map[string]map[string]map[string][]Entry

// Add files e under id, finish and store. An entry of the same grade
// already filed there keeps the better of the two prices, the higher when
// buying and the lower otherwise, and the sum of their quantities.
func (v V2) Add(id, finish, store string, e Entry, buying bool) {
	finishes := v[id]
	if finishes == nil {
		finishes = map[string]map[string][]Entry{}
		v[id] = finishes
	}
	stores := finishes[finish]
	if stores == nil {
		stores = map[string][]Entry{}
		finishes[finish] = stores
	}

	entries := stores[store]
	rank := slices.Index(Grades, e.Grade)
	i := 0
	for ; i < len(entries); i++ {
		if entries[i].Grade == e.Grade {
			better := e.Price < entries[i].Price
			if buying {
				better = e.Price > entries[i].Price
			}
			if better {
				entries[i].Price = e.Price
			}
			entries[i].Qty += e.Qty
			return
		}
		if slices.Index(Grades, entries[i].Grade) > rank {
			break
		}
	}
	stores[store] = slices.Insert(entries, i, e)
}
