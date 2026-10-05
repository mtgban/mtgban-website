// Package banprice holds the wire types of the price API: per-store prices
// and quantities keyed by grade and finish, in the exact JSON shape the
// endpoint has always served.
package banprice

//go:generate go run gen.go

// The finishes every game shares. Magic sells only these; the datastore
// games sell the rest of Finishes too.
const (
	FinishNonfoil = "nonfoil"
	FinishFoil    = "foil"
	FinishEtched  = "etched"
)

// Finishes are every finish a price object files a price under, spelled as
// mtgmatcher.FinishSlug spells them: the three Magic sells, then the ones
// MoreFinishes carries. A card sold in several of them under one id - a
// TCGplayer or Cardmarket product holds every finish of its printing -
// keeps a price for each instead of one finish overwriting another.
var Finishes = append([]string{FinishNonfoil, FinishFoil, FinishEtched}, extraFinishes...)

// grades are the conditions a per-grade price is filed under, best first.
// Unexported: the v2 API (#832) exports banprice.Grades itself, and the
// two must land in either order.
var grades = []string{"NM", "SP", "MP", "HP", "PO"}

// ConditionTags is every grade+finish combination the price maps can carry.
// The vocabulary is closed: mtgban validates entry conditions against
// FullGradeTags on Add, and the finishes are Finishes. Ordered by grade,
// best first, then by finish in Finishes order within a grade.
var ConditionTags = func() []string {
	tags := make([]string, 0, len(grades)*len(Finishes))
	for _, grade := range grades {
		for _, finish := range Finishes {
			tags = append(tags, ConditionTag(grade, finish))
		}
	}
	return tags
}()

var (
	servedFinishes = setOf(Finishes)
	servedTags     = setOf(ConditionTags)
)

func setOf(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// Serves reports whether the finish has a field of its own.
func Serves(finish string) bool {
	return servedFinishes[finish]
}

// ConditionTag is the key a finish's price at a grade is filed under: the
// grade alone for nonfoil, and the grade and the finish otherwise, as in
// "NM_foil" and "SP_coldfoil".
func ConditionTag(grade, finish string) string {
	if finish == FinishNonfoil || finish == "" {
		return grade
	}
	return grade + "_" + finish
}

// Price is the per-(id, store) aggregation the price API serves.
type Price struct {
	Regular   float64 `json:"regular,omitempty"`
	Foil      float64 `json:"foil,omitempty"`
	Etched    float64 `json:"etched,omitempty"`
	Sealed    float64 `json:"sealed,omitempty"`
	Cond      string  `json:"cond,omitempty"`
	Qty       int     `json:"qty,omitempty"`
	QtyFoil   int     `json:"qty_foil,omitempty"`
	QtyEtched int     `json:"qty_etched,omitempty"`
	QtySealed int     `json:"qty_sealed,omitempty"`

	// The finishes past the three above, nil until one is set. Its fields
	// are promoted, so read them only once it is known to be there, or
	// through Get and GetQty.
	*MoreFinishes

	Conditions *Conditions `json:"conditions,omitempty"`
	Quantities *Quantities `json:"quantities,omitempty"`
}

func (p *Price) price(finish string, alloc bool) *float64 {
	switch finish {
	case FinishNonfoil:
		return &p.Regular
	case FinishFoil:
		return &p.Foil
	case FinishEtched:
		return &p.Etched
	}
	if p.MoreFinishes == nil {
		if !alloc || !Serves(finish) {
			return nil
		}
		p.MoreFinishes = &MoreFinishes{}
	}
	return p.MoreFinishes.price(finish)
}

func (p *Price) qty(finish string, alloc bool) *int {
	switch finish {
	case FinishNonfoil:
		return &p.Qty
	case FinishFoil:
		return &p.QtyFoil
	case FinishEtched:
		return &p.QtyEtched
	}
	if p.MoreFinishes == nil {
		if !alloc || !Serves(finish) {
			return nil
		}
		p.MoreFinishes = &MoreFinishes{}
	}
	return p.MoreFinishes.qty(finish)
}

// Set stores the price of a finish, ignoring one Finishes does not name.
func (p *Price) Set(finish string, price float64) {
	if ref := p.price(finish, true); ref != nil {
		*ref = price
	}
}

// Get returns the price of a finish, 0 when unset or on a nil receiver.
func (p *Price) Get(finish string) float64 {
	if p == nil {
		return 0
	}
	if ref := p.price(finish, false); ref != nil {
		return *ref
	}
	return 0
}

// AddQty adds to the quantity of a finish, ignoring one Finishes does not
// name.
func (p *Price) AddQty(finish string, qty int) {
	if ref := p.qty(finish, true); ref != nil {
		*ref += qty
	}
}

// GetQty returns the quantity of a finish, 0 when unset or on a nil
// receiver.
func (p *Price) GetQty(finish string) int {
	if p == nil {
		return 0
	}
	if ref := p.qty(finish, false); ref != nil {
		return *ref
	}
	return 0
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

	// The grades of the finishes past the three above, nil until one is
	// set, as Price.MoreFinishes is.
	*MoreConditions
}

func (c *Conditions) ref(tag string, alloc bool) *float64 {
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
	if c.MoreConditions == nil {
		if !alloc || !servedTags[tag] {
			return nil
		}
		c.MoreConditions = &MoreConditions{}
	}
	return c.MoreConditions.ref(tag)
}

// Set stores the price for tag, ignoring unknown tags.
func (c *Conditions) Set(tag string, price float64) {
	if p := c.ref(tag, true); p != nil {
		*p = price
	}
}

// Get returns the price for tag, 0 when unset or on a nil receiver.
func (c *Conditions) Get(tag string) float64 {
	if c == nil {
		return 0
	}
	if p := c.ref(tag, false); p != nil {
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

	*MoreQuantities
}

func (q *Quantities) ref(tag string, alloc bool) *int {
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
	if q.MoreQuantities == nil {
		if !alloc || !servedTags[tag] {
			return nil
		}
		q.MoreQuantities = &MoreQuantities{}
	}
	return q.MoreQuantities.ref(tag)
}

// Set stores the quantity for tag, ignoring unknown tags.
func (q *Quantities) Set(tag string, qty int) {
	if p := q.ref(tag, true); p != nil {
		*p = qty
	}
}

// Get returns the quantity for tag, 0 when unset or on a nil receiver.
func (q *Quantities) Get(tag string) int {
	if q == nil {
		return 0
	}
	if p := q.ref(tag, false); p != nil {
		return *p
	}
	return 0
}
