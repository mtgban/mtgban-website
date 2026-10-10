package main

import (
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/banprice"
)

// arbitMarker is the query key every link the arbitrage pages generate
// carries, saying the URL holds the whole filter state.
const arbitMarker = "f"

// arbitConditions are the grades the condition picker offers, best first.
// PO has no box of its own: it goes with HP.
var arbitConditions = []string{"NM", "SP", "MP", "HP"}

// arbitBoundKeys are the query keys of the reader's numeric limits.
var arbitBoundKeys = []string{
	"minsell", "maxsell", "minbuy", "maxbuy",
	"minspread", "maxspread", "mindiff", "minqty", "minprof",
}

// arbitPickKeys are the query keys of the reader's selections. Each also has
// a "<key>_on" marker, which a form posts so that a group with every box
// unchecked reads as an empty selection rather than as no selection.
var arbitPickKeys = []string{"cond", "finish", "rarity"}

// arbitSorts are the sort orders arbitLess knows.
var arbitSorts = []string{
	"profitability", "spread", "diff", "available",
	"sell_price", "buy_price", "edition", "alpha",
}

// arbitBound is a reader's limit: unset leaves the mode's default, and an
// explicit 0 is a value, distinct from unset.
type arbitBound struct {
	Set   bool
	Value float64
}

// arbitPick is a reader's selection from a list: unset keeps the whole list,
// and set with no values keeps nothing.
type arbitPick struct {
	Set    bool
	Values []string
}

// arbitState is what the reader asked the arbitrage pages for. It names no
// page: the store links are built from it before a source is picked, and
// the source decides whether the comparison is of singles or sealed, so it
// is resolved against a mode only when applied.
type arbitState struct {
	Conditions, Finishes, Rarities arbitPick

	// The table's two price columns, as arbitRowFilter reads them
	MinSell, MaxSell, MinBuy, MaxBuy arbitBound

	MinSpread, MaxSpread, MinDiff arbitBound
	MinQty, MinProf               arbitBound

	// The FilterOptKeys the reader set, on or off; absent is the mode's
	// default
	Toggles map[string]bool

	Sort string
}

func (st *arbitState) bound(key string) *arbitBound {
	switch key {
	case "minsell":
		return &st.MinSell
	case "maxsell":
		return &st.MaxSell
	case "minbuy":
		return &st.MinBuy
	case "maxbuy":
		return &st.MaxBuy
	case "minspread":
		return &st.MinSpread
	case "maxspread":
		return &st.MaxSpread
	case "mindiff":
		return &st.MinDiff
	case "minqty":
		return &st.MinQty
	case "minprof":
		return &st.MinProf
	}
	panic("unknown arbit bound " + key)
}

func (st *arbitState) pick(key string) *arbitPick {
	switch key {
	case "cond":
		return &st.Conditions
	case "finish":
		return &st.Finishes
	case "rarity":
		return &st.Rarities
	}
	panic("unknown arbit pick " + key)
}

// arbitOffer is what each picker lists: the grades, the game's rarities and
// the finishes its singles are sold in.
type arbitOffer struct {
	Rarities []string
	Finishes []banprice.Finish
}

func newArbitOffer(ds *datastore) arbitOffer {
	offer := arbitOffer{Rarities: ds.backend.Rarities}
	for _, finish := range ds.finishes {
		if finish.Value != banprice.FinishSealed {
			offer.Finishes = append(offer.Finishes, finish)
		}
	}
	return offer
}

func (offer arbitOffer) values(key string) []string {
	switch key {
	case "cond":
		return arbitConditions
	case "rarity":
		return offer.Rarities
	}
	values := make([]string, len(offer.Finishes))
	for i, finish := range offer.Finishes {
		values[i] = finish.Value
	}
	return values
}

// parseArbitState reads the filter state off a query. Numbers that are not
// finite and values no picker offers are dropped, a selection of the whole
// list is the same as none, and every other key is ignored.
func parseArbitState(form url.Values, offer arbitOffer) arbitState {
	st := arbitState{Toggles: map[string]bool{}}
	if slices.Contains(arbitSorts, form.Get("sort")) {
		st.Sort = form.Get("sort")
	}

	for _, key := range arbitBoundKeys {
		raw := form.Get(key)
		if raw == "" {
			continue
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		*st.bound(key) = arbitBound{Set: true, Value: value}
	}

	for _, key := range arbitPickKeys {
		_, given := form[key]
		if !given && form.Get(key+"_on") == "" {
			continue
		}
		var asked []string
		for _, raw := range form[key] {
			asked = append(asked, strings.Split(raw, ",")...)
		}
		offered := offer.values(key)
		var values []string
		for _, value := range offered {
			if slices.Contains(asked, value) {
				values = append(values, value)
			}
		}
		if len(values) == len(offered) {
			continue
		}
		*st.pick(key) = arbitPick{Set: true, Values: values}
	}

	shown := strings.Split(form.Get("toggles_on"), ",")
	for _, key := range FilterOptKeys {
		raw, given := form[key]
		if !given {
			if slices.Contains(shown, key) {
				st.Toggles[key] = false
			}
			continue
		}
		on, err := strconv.ParseBool(raw[0])
		if err == nil {
			st.Toggles[key] = on
		}
	}
	return st
}

// arbitSavedCookie names the cookie a page keeps the reader's filters in:
// one for arbit and reverse, which share their columns and limits, and one
// for global, whose columns are other stores and whose floors differ.
func arbitSavedCookie(global bool) string {
	if global {
		return "GlobalFilters"
	}
	return "ArbitFilters"
}

// requestArbitState is the state a request asks for: its own query where
// that carries the marker, else the reader's saved filters, whose sort the
// query can still change for the one view. A saved value that does not
// read as a query is no saved value.
func requestArbitState(form url.Values, saved string, offer arbitOffer) arbitState {
	if form.Has(arbitMarker) || saved == "" {
		return parseArbitState(form, offer)
	}
	unescaped, err := url.QueryUnescape(saved)
	if err != nil {
		return parseArbitState(form, offer)
	}
	savedForm, err := url.ParseQuery(unescaped)
	if err != nil {
		return parseArbitState(form, offer)
	}
	st := parseArbitState(savedForm, offer)
	if slices.Contains(arbitSorts, form.Get("sort")) {
		st.Sort = form.Get("sort")
	}
	return st
}

// values is the state as a query, the marker included: what every store,
// sort and reset link carries.
func (st arbitState) values() url.Values {
	v := url.Values{}
	v.Set(arbitMarker, "1")
	for _, key := range arbitPickKeys {
		pick := st.pick(key)
		if pick.Set {
			v.Set(key, strings.Join(pick.Values, ","))
		}
	}
	for _, key := range arbitBoundKeys {
		bound := st.bound(key)
		if bound.Set {
			v.Set(key, strconv.FormatFloat(bound.Value, 'f', -1, 64))
		}
	}
	for _, key := range FilterOptKeys {
		on, set := st.Toggles[key]
		if set {
			v.Set(key, "0")
			if on {
				v.Set(key, "1")
			}
		}
	}
	if st.Sort != "" {
		v.Set("sort", st.Sort)
	}
	return v
}

// isZero reports whether the reader asked for nothing at all.
func (st arbitState) isZero() bool {
	return len(st.values()) == 1
}

// arbitMode is which comparison a state is applied to.
type arbitMode struct {
	Global, Reverse, Sealed bool

	// The reader's AnySpread grant, which lowers Global's spread floor
	AnySpread bool
}

// arbitLimits are the thresholds one comparison runs with: the reader's,
// where the state sets them, and the mode's otherwise.
type arbitLimits struct {
	MinSell, MaxSell, MinBuy, MaxBuy float64
	MinSpread, MaxSpread, MinDiff    float64
	MinQty, MinProf                  float64
}

// arbitDefaults are a mode's limits before the reader sets any, those of
// the page as it has always opened.
func arbitDefaults(m arbitMode) arbitLimits {
	l := arbitLimits{
		MaxSell:   math.Inf(1),
		MaxBuy:    math.Inf(1),
		MinSpread: MinSpread,
		MaxSpread: math.Inf(1),
	}
	switch {
	case m.Global && !m.Sealed:
		l.MinSpread, _ = m.floors()
		l.MaxSpread = MaxSpreadGlobal
		l.MinDiff = 5
		l.MinSell, l.MinBuy = 1, 1
	case m.Global:
		l.MinDiff = 1
	case m.Sealed:
		l.MinSpread = MinSpreadNegative
		// Not the engine's zero, which drops every negative difference
		l.MinDiff = math.Inf(-1)
	}
	return l
}

// floors are the lowest spread and difference a reader can ask the mode
// for: arbit's "only Negative" reach, on Global sealed too. Global singles'
// spread floor is a tier gate, the AnySpread grant's.
func (m arbitMode) floors() (float64, float64) {
	switch {
	case m.Global && !m.Sealed && m.AnySpread:
		return MinSpreadGlobalPro, 0
	case m.Global && !m.Sealed:
		return MinSpreadGlobal, 0
	case m.Sealed && !m.Global:
		return MinSpreadNegative, math.Inf(-1)
	}
	return MinSpreadNegative, MinDiffNegative
}

// limits resolves the state's thresholds against the mode, holding the
// spread and difference to its floors.
func (st arbitState) limits(m arbitMode) arbitLimits {
	l := arbitDefaults(m)
	minSpread, minDiff := m.floors()
	for _, key := range arbitBoundKeys {
		bound := st.bound(key)
		if !bound.Set {
			continue
		}
		switch key {
		case "minsell":
			l.MinSell = bound.Value
		case "maxsell":
			l.MaxSell = bound.Value
		case "minbuy":
			l.MinBuy = bound.Value
		case "maxbuy":
			l.MaxBuy = bound.Value
		case "minspread":
			l.MinSpread = max(bound.Value, minSpread)
		case "maxspread":
			l.MaxSpread = bound.Value
		case "mindiff":
			l.MinDiff = max(bound.Value, minDiff)
		case "minqty":
			l.MinQty = bound.Value
		case "minprof":
			l.MinProf = bound.Value
		}
	}
	return l
}

// toggleDefault is whether a mode turns a FilterOptKeys option on by itself.
func (m arbitMode) toggleDefault(key string) bool {
	switch key {
	case "tradable":
		return m.Reverse
	case "legit":
		return m.Global && !m.Sealed
	case "stable":
		return m.Global && m.Sealed
	}
	return false
}

// applied are the toggles in effect: the reader's or the mode's, among the
// ones the page shows. One it has no control for could not be turned off,
// so it does nothing, however it got into the URL.
func (st arbitState) applied(m arbitMode) map[string]bool {
	applied := map[string]bool{}
	for _, key := range FilterOptKeys {
		if !FilterOptConfig[key].Shown(m.Global, m.Reverse, m.Sealed) {
			continue
		}
		on, set := st.Toggles[key]
		if !set {
			on = m.toggleDefault(key)
		}
		if on {
			applied[key] = true
		}
	}
	return applied
}

// arbitRowFilter holds a comparison's rows to the limits ArbitOpts cannot
// say for the columns the table shows. The engine's own MinPrice and
// MinBuyPrice read other prices: Mismatch applies MinPrice to both sides,
// and Arbit drops a whole card on its NM buy price before picking the
// condition a row shows.
type arbitRowFilter struct {
	limits arbitLimits
	global bool
}

// keep reports whether a row is within the limits. A seller publishing no
// quantities, as Mana Pool does, has none to hold to a minimum: the engine
// exempts it too.
func (f arbitRowFilter) keep(e mtgban.ArbitEntry, noQuantity bool) bool {
	buy := e.BuylistEntry.BuyPrice
	if f.global {
		buy = e.ReferenceEntry.Price
	}
	l := f.limits
	return e.InventoryEntry.Price >= l.MinSell && e.InventoryEntry.Price <= l.MaxSell &&
		buy >= l.MinBuy && buy <= l.MaxBuy && e.Spread <= l.MaxSpread &&
		(noQuantity || float64(e.Quantity) >= l.MinQty)
}

// apply builds the options one comparison runs with, and the filter its
// rows go through after.
func (st arbitState) apply(b *mtgmatcher.Backend, m arbitMode) (*mtgban.ArbitOpts, arbitRowFilter) {
	l := st.limits(m)
	opts := &mtgban.ArbitOpts{
		MinSpread:             l.MinSpread,
		MinDiff:               l.MinDiff,
		MinProfitability:      l.MinProf,
		ProfitabilityConstant: ProfConst,
	}
	switch {
	case m.Global && !m.Sealed:
		opts.MaxSpread = MaxSpreadGlobal
		opts.MaxPriceRatio = MaxPriceRatio
		opts.Editions = FilteredEditions
	case m.Sealed && !m.Global:
		opts.ProfitabilityConstant = ProfConstGlobal
	}

	if !m.Sealed {
		if st.Conditions.Set {
			for _, grade := range arbitConditions {
				if !slices.Contains(st.Conditions.Values, grade) {
					opts.Conditions = append(opts.Conditions, mtgban.Condition(grade))
				}
			}
			if !slices.Contains(st.Conditions.Values, "HP") {
				opts.Conditions = append(opts.Conditions, mtgban.PO)
			}
		}
		if st.Rarities.Set {
			for _, rarity := range b.Rarities {
				if !slices.Contains(st.Rarities.Values, rarity) {
					opts.Rarities = append(opts.Rarities, rarity)
				}
			}
		}
		if st.Finishes.Set {
			kept := st.Finishes.Values
			opts.CustomCardFilter = func(co *mtgmatcher.CardObject) (float64, bool) {
				finish := co.Finish
				if finish == "" {
					finish = mtgmatcher.FinishNonfoil
				}
				return 1, !slices.Contains(kept, finish)
			}
		}
	}

	applied := st.applied(m)
	for _, key := range FilterOptKeys {
		if applied[key] && FilterOptConfig[key].Func != nil {
			FilterOptConfig[key].Func(opts)
		}
	}
	return opts, arbitRowFilter{limits: l, global: m.Global}
}

// arbitBar is the filter bar a results page renders: what the reader set
// as values, and the mode's defaults as placeholders, so that posting the
// form leaves an untouched field unset.
type arbitBar struct {
	// No choices on a sealed source
	Condition, Finish, Rarity arbitPickGroup

	// Quantity has no Key on Global, which shows no quantities
	Sell, Buy, Spread, Diff, Quantity, Profit arbitRange

	Toggles []arbitToggle

	// The toggles this bar shows, posted as toggles_on so one left
	// unchecked reads as off
	TogglesOn string

	// The reader's sort, which a submit keeps
	Sort string

	// How many filters differ from the page's defaults, which the closed
	// bar counts
	Set int

	// Whether the reader left the bar open, from the ArbitFiltersOpen
	// cookie
	Open bool
}

type arbitPickGroup struct {
	Key, Label string
	Choices    []arbitChoice
}

type arbitChoice struct {
	Value, Label string
	Checked      bool
}

// arbitRange is one labelled limit, or a pair of them where High has a Key.
type arbitRange struct {
	Label, Unit string
	Low, High   arbitField
}

type arbitField struct {
	Key, Value, Placeholder string

	// The lowest value the mode honours, for the input's min
	Floor string
}

type arbitToggle struct {
	Key, Title string
	Checked    bool
}

// values lists the limits in one order, for comparing two sets of them.
func (l arbitLimits) values() []float64 {
	return []float64{l.MinSell, l.MaxSell, l.MinBuy, l.MaxBuy, l.MinSpread, l.MaxSpread, l.MinDiff, l.MinQty, l.MinProf}
}

// changed counts the filters that make the comparison differ from the
// page's defaults: a limit set to the default, or an option turned off
// where it is off anyway, counts for nothing.
func (st arbitState) changed(m arbitMode) int {
	n := 0
	if !m.Sealed {
		for _, pick := range []arbitPick{st.Conditions, st.Finishes, st.Rarities} {
			if pick.Set {
				n++
			}
		}
	}
	defaults := arbitDefaults(m).values()
	for i, value := range st.limits(m).values() {
		if value != defaults[i] {
			n++
		}
	}
	applied := st.applied(m)
	for _, key := range FilterOptKeys {
		if FilterOptConfig[key].Shown(m.Global, m.Reverse, m.Sealed) && applied[key] != m.toggleDefault(key) {
			n++
		}
	}
	return n
}

// formatLimit spells a limit for an input, and an unbounded one as nothing.
func formatLimit(value float64) string {
	if math.IsInf(value, 0) {
		return ""
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func (st arbitState) field(key string, fallback, floor float64) arbitField {
	f := arbitField{Key: key, Placeholder: formatLimit(fallback), Floor: formatLimit(floor)}
	bound := st.bound(key)
	if bound.Set {
		f.Value = formatLimit(bound.Value)
	}
	return f
}

// newArbitBar lays out the bar for one comparison, whose source is named,
// with the price columns labelled as its tables label them.
func newArbitBar(st arbitState, m arbitMode, offer arbitOffer, b *mtgmatcher.Backend, sourceShort string) arbitBar {
	bar := arbitBar{Sort: st.Sort, Set: st.changed(m)}

	bar.Condition = arbitPickGroup{Key: "cond", Label: "Condition"}
	bar.Finish = arbitPickGroup{Key: "finish", Label: "Finish"}
	bar.Rarity = arbitPickGroup{Key: "rarity", Label: "Rarity"}
	if !m.Sealed {
		for _, grade := range arbitConditions {
			bar.Condition.Choices = append(bar.Condition.Choices, st.Conditions.choice(grade, grade))
		}
		for _, f := range offer.Finishes {
			bar.Finish.Choices = append(bar.Finish.Choices, st.Finishes.choice(f.Value, f.Label))
		}
		for _, r := range offer.Rarities {
			bar.Rarity.Choices = append(bar.Rarity.Choices, st.Rarities.choice(r, b.RarityLabel(r)))
		}
	}

	sell, buy := "Sell", "Buy"
	if m.Global {
		sell, buy = scraperName(sourceShort), "Store"
		if m.Sealed {
			sell, buy = buy, sell
		}
	}
	none := math.Inf(-1)
	l := arbitDefaults(m)
	minSpread, minDiff := m.floors()
	bar.Sell = arbitRange{Label: sell, Unit: "$", Low: st.field("minsell", l.MinSell, 0), High: st.field("maxsell", l.MaxSell, 0)}
	bar.Buy = arbitRange{Label: buy, Unit: "$", Low: st.field("minbuy", l.MinBuy, 0), High: st.field("maxbuy", l.MaxBuy, 0)}
	bar.Spread = arbitRange{Label: "Spread", Unit: "%", Low: st.field("minspread", l.MinSpread, minSpread), High: st.field("maxspread", l.MaxSpread, none)}
	bar.Diff = arbitRange{Label: "Difference", Unit: "$", Low: st.field("mindiff", l.MinDiff, minDiff)}
	if !m.Global {
		bar.Quantity = arbitRange{Label: "Quantity", Low: st.field("minqty", l.MinQty, 0)}
	}
	bar.Profit = arbitRange{Label: "Profit", Low: st.field("minprof", l.MinProf, none)}

	applied := st.applied(m)
	var shown []string
	for _, key := range FilterOptKeys {
		if !FilterOptConfig[key].Shown(m.Global, m.Reverse, m.Sealed) {
			continue
		}
		shown = append(shown, key)
		bar.Toggles = append(bar.Toggles, arbitToggle{Key: key, Title: FilterOptConfig[key].Title, Checked: applied[key]})
	}
	bar.TogglesOn = strings.Join(shown, ",")
	return bar
}

// choice is one box of a picker, ticked unless the reader left it out.
func (pick arbitPick) choice(value, label string) arbitChoice {
	return arbitChoice{Value: value, Label: label, Checked: !pick.Set || slices.Contains(pick.Values, value)}
}
