// Package banprice holds the wire types of the price API: per-store prices
// and quantities keyed by grade and finish, in the exact JSON shape the
// endpoint has always served.
package banprice

// ConditionTags is every grade+finish combination the price maps can carry.
// The vocabulary is closed: mtgban validates entry conditions against
// FullGradeTags on Add, and the finish suffixes are fixed at aggregation
// time. Ordered by grade, best first, then base/foil/etched within a grade.
var ConditionTags = []string{
	"NM", "NM_foil", "NM_etched",
	"SP", "SP_foil", "SP_etched",
	"MP", "MP_foil", "MP_etched",
	"HP", "HP_foil", "HP_etched",
	"PO", "PO_foil", "PO_etched",
}

// Price is the per-(id, store) aggregation the price API serves.
type Price struct {
	Regular    float64     `json:"regular,omitempty"`
	Foil       float64     `json:"foil,omitempty"`
	Etched     float64     `json:"etched,omitempty"`
	Sealed     float64     `json:"sealed,omitempty"`
	Cond       string      `json:"cond,omitempty"`
	Qty        int         `json:"qty,omitempty"`
	QtyFoil    int         `json:"qty_foil,omitempty"`
	QtyEtched  int         `json:"qty_etched,omitempty"`
	QtySealed  int         `json:"qty_sealed,omitempty"`
	Conditions *Conditions `json:"conditions,omitempty"`
	Quantities *Quantities `json:"quantities,omitempty"`
}

// Conditions holds per-grade prices as flat fields instead of a map: the
// key set is closed (see ConditionTags), and a full dump with conditions
// builds one of these per (id, store) pair, where map headers and buckets
// used to dominate the allocations. Zero prices are impossible by
// construction (aggregation drops zero-priced stores), so omitempty
// preserves the wire format; keys serialize in ConditionTags order.
type Conditions struct {
	NM       float64 `json:"NM,omitempty"`
	NMFoil   float64 `json:"NM_foil,omitempty"`
	NMEtched float64 `json:"NM_etched,omitempty"`
	SP       float64 `json:"SP,omitempty"`
	SPFoil   float64 `json:"SP_foil,omitempty"`
	SPEtched float64 `json:"SP_etched,omitempty"`
	MP       float64 `json:"MP,omitempty"`
	MPFoil   float64 `json:"MP_foil,omitempty"`
	MPEtched float64 `json:"MP_etched,omitempty"`
	HP       float64 `json:"HP,omitempty"`
	HPFoil   float64 `json:"HP_foil,omitempty"`
	HPEtched float64 `json:"HP_etched,omitempty"`
	PO       float64 `json:"PO,omitempty"`
	POFoil   float64 `json:"PO_foil,omitempty"`
	POEtched float64 `json:"PO_etched,omitempty"`
}

func (c *Conditions) ref(tag string) *float64 {
	switch tag {
	case "NM":
		return &c.NM
	case "NM_foil":
		return &c.NMFoil
	case "NM_etched":
		return &c.NMEtched
	case "SP":
		return &c.SP
	case "SP_foil":
		return &c.SPFoil
	case "SP_etched":
		return &c.SPEtched
	case "MP":
		return &c.MP
	case "MP_foil":
		return &c.MPFoil
	case "MP_etched":
		return &c.MPEtched
	case "HP":
		return &c.HP
	case "HP_foil":
		return &c.HPFoil
	case "HP_etched":
		return &c.HPEtched
	case "PO":
		return &c.PO
	case "PO_foil":
		return &c.POFoil
	case "PO_etched":
		return &c.POEtched
	}
	return nil
}

// Set stores the price for tag, ignoring unknown tags.
func (c *Conditions) Set(tag string, price float64) {
	if p := c.ref(tag); p != nil {
		*p = price
	}
}

// Get returns the price for tag, 0 when unset or on a nil receiver.
func (c *Conditions) Get(tag string) float64 {
	if c == nil {
		return 0
	}
	if p := c.ref(tag); p != nil {
		return *p
	}
	return 0
}

// Quantities is the quantity counterpart of Conditions.
type Quantities struct {
	NM       int `json:"NM,omitempty"`
	NMFoil   int `json:"NM_foil,omitempty"`
	NMEtched int `json:"NM_etched,omitempty"`
	SP       int `json:"SP,omitempty"`
	SPFoil   int `json:"SP_foil,omitempty"`
	SPEtched int `json:"SP_etched,omitempty"`
	MP       int `json:"MP,omitempty"`
	MPFoil   int `json:"MP_foil,omitempty"`
	MPEtched int `json:"MP_etched,omitempty"`
	HP       int `json:"HP,omitempty"`
	HPFoil   int `json:"HP_foil,omitempty"`
	HPEtched int `json:"HP_etched,omitempty"`
	PO       int `json:"PO,omitempty"`
	POFoil   int `json:"PO_foil,omitempty"`
	POEtched int `json:"PO_etched,omitempty"`
}

func (q *Quantities) ref(tag string) *int {
	switch tag {
	case "NM":
		return &q.NM
	case "NM_foil":
		return &q.NMFoil
	case "NM_etched":
		return &q.NMEtched
	case "SP":
		return &q.SP
	case "SP_foil":
		return &q.SPFoil
	case "SP_etched":
		return &q.SPEtched
	case "MP":
		return &q.MP
	case "MP_foil":
		return &q.MPFoil
	case "MP_etched":
		return &q.MPEtched
	case "HP":
		return &q.HP
	case "HP_foil":
		return &q.HPFoil
	case "HP_etched":
		return &q.HPEtched
	case "PO":
		return &q.PO
	case "PO_foil":
		return &q.POFoil
	case "PO_etched":
		return &q.POEtched
	}
	return nil
}

// Set stores the quantity for tag, ignoring unknown tags.
func (q *Quantities) Set(tag string, qty int) {
	if p := q.ref(tag); p != nil {
		*p = qty
	}
}

// Get returns the quantity for tag, 0 when unset or on a nil receiver.
func (q *Quantities) Get(tag string) int {
	if q == nil {
		return 0
	}
	if p := q.ref(tag); p != nil {
		return *p
	}
	return 0
}
