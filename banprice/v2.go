package banprice

import (
	"slices"
	"time"
)

// FinishSealed is the finish a sealed product is filed under in V2, having
// no finish of its own.
const FinishSealed = "sealed"

// Grades are the grades an Entry can carry, best first.
var Grades = []string{"NM", "SP", "MP", "HP", "PO"}

// Entry is one grade of one finish at one store. Grade is empty for an
// index price and for sealed product, which are not graded. Qty is the
// copies the store's own listings in the grade hold, Price being the best of
// their prices; on a buylist, the copies it buys. Available is every copy of
// the grade on sale there at any price, where a source counts them. An empty
// Qty or Available is unknown, not zero, and an empty Qty on a buylist is
// no limit.
type Entry struct {
	Grade     string  `json:"grade,omitempty"`
	Price     float64 `json:"price"`
	Qty       int     `json:"qty,omitempty"`
	Available int     `json:"available,omitempty"`
}

// V2 is the price map of the v2 API: card id, then finish, then store, then
// that store's prices, one per grade, best grade first.
type V2 map[string]map[string]map[string][]Entry

// Add files e under id, finish and store. An entry of the same grade
// already filed there keeps the better of the two prices, the higher when
// buying and the lower otherwise, and the sums of their Qty and Available.
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
			entries[i].Available += e.Available
			return
		}
		if slices.Index(Grades, entries[i].Grade) > rank {
			break
		}
	}
	stores[store] = slices.Insert(entries, i, e)
}

// Finish is one finish a v2 response keys prices by, as finishes.json lists
// it: the key, its display name, and how many cards or products carry it.
type Finish struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// Store is one store a v2 response keys prices by, as stores.json lists it.
type Store struct {
	Shorthand string `json:"shorthand"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Sealed    bool   `json:"sealed,omitempty"`

	// Index marks a store whose prices index a market rather than list its
	// own stock, which v2 gives no grade.
	Index bool `json:"index,omitempty"`

	// Quantities marks a store whose prices carry a qty.
	Quantities bool `json:"quantities,omitempty"`

	// CreditMultiplier is what a vendor's store credit is worth against its
	// cash price: 1.3 pays 30% more in credit. Absent where it pays none.
	CreditMultiplier float64 `json:"credit_multiplier,omitempty"`

	// Updated is when the store's prices were last collected.
	Updated *time.Time `json:"updated,omitempty"`
}

// Stores is v2's stores.json: the stores a caller can read prices from,
// sellers and vendors apart, each sorted by shorthand.
type Stores struct {
	Sellers []Store `json:"sellers"`
	Vendors []Store `json:"vendors"`
}
