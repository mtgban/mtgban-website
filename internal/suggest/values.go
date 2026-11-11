package suggest

import (
	"maps"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/fuzzy"
)

// Sets rewrites a query whose set filters name no set, "s:atw", with the
// sets nearest what was typed among those its name is printed in, nearest
// first. Every value of such a filter needs a set.
func Sets(p Params) []string {
	if len(p.UnknownSets) == 0 {
		return nil
	}
	codes := setsFound(p)
	nearest := make([][][]string, len(p.UnknownSets))
	for i, field := range p.UnknownSets {
		_, values, ok := strings.Cut(field, ":")
		if !ok {
			return nil
		}
		for _, value := range SplitList(values) {
			near := nearestSets(p.Backend, value, codes)
			if len(near) == 0 {
				return nil
			}
			nearest[i] = append(nearest[i], near)
		}
	}
	return rewrites(p.RawQuery, p.UnknownSets, nearest)
}

// Tags rewrites a query whose is: values name no promo type, "is:riple",
// with the promo types nearest what was typed, or their short forms,
// among those the printings of its name carry, nearest first. A value
// with none near stays as typed, as is:reserved names no promo type.
func Tags(p Params) []string {
	if p.Sealed || len(p.UnknownSets) != 0 {
		return nil
	}
	tags := tagsFound(p)
	var fields []string
	var nearest [][][]string
	var rewritten bool
	for _, field := range p.AppliedFilters {
		key, values, ok := strings.Cut(field, ":")
		if !ok || !strings.EqualFold(key, "is") {
			continue
		}
		var fieldNearest [][]string
		for _, value := range SplitList(values) {
			near := nearestTags(p, value, tags)
			if len(near) == 0 {
				near = []string{value}
			} else {
				rewritten = true
			}
			fieldNearest = append(fieldNearest, near)
		}
		fields = append(fields, field)
		nearest = append(nearest, fieldNearest)
	}
	if !rewritten {
		return nil
	}
	return rewrites(p.RawQuery, fields, nearest)
}

// tagsFound are the values an is: may be rewritten to: the promo types
// the printings of the query's name carry, or every one where it has no
// name, each after the short forms it answers to.
func tagsFound(p Params) []string {
	promoTypes := p.Backend.AllPromoTypes
	cards, named := printings(p)
	if named {
		promoTypes = nil
		for _, co := range cards {
			for _, promoType := range co.PromoTypes {
				if !slices.Contains(promoTypes, promoType) {
					promoTypes = append(promoTypes, promoType)
				}
			}
		}
	}
	var tags []string
	for _, short := range slices.Sorted(maps.Keys(p.PromoAliases)) {
		if slices.Contains(promoTypes, p.PromoAliases[short]) {
			tags = append(tags, short)
		}
	}
	return append(tags, promoTypes...)
}

// nearestTags returns the tags nearest value, nearest first, or none
// where value is a promo type or a short form already. An edit is allowed
// per four letters, so a value too short for one, "lea", is no typo of a
// tag, "ea".
func nearestTags(p Params, value string, tags []string) []string {
	value = strings.ToLower(value)
	_, short := p.PromoAliases[value]
	if short || slices.Contains(p.Backend.AllPromoTypes, value) {
		return nil
	}
	limit := len(value) / 4
	if limit == 0 {
		return nil
	}
	near := slices.DeleteFunc(slices.Clone(tags), func(tag string) bool {
		return fuzzy.Distance(value, tag, limit) > limit
	})
	return fuzzy.Closest(value, near)
}

// queryName is the name p's query searches by: what its filters and a
// trailing &*~` flag leave.
func queryName(p Params) string {
	name := strings.TrimRight(p.RawQuery, "&*~`")
	for _, field := range slices.Concat(p.UnknownSets, p.AppliedFilters) {
		name = replaceField(name, field, "")
	}
	return strings.Trim(collapseSpaces(name), `"`)
}

// printings are the cards p's query names, every printing of its exact
// name; named is false where the query has no name.
func printings(p Params) (cards []*matcher.CardObject, named bool) {
	name := queryName(p)
	if name == "" {
		return nil, false
	}
	uuids, err := p.Backend.SearchEquals(name)
	if err != nil {
		return nil, true
	}
	for _, uuid := range uuids {
		co, err := p.Backend.GetUUID(uuid)
		if err == nil {
			cards = append(cards, co)
		}
	}
	return cards, true
}

// setsFound are the sets a set filter may be rewritten to: those the
// query's name is printed in, or every set where it has no name. A sealed
// search takes the sets with sealed product, whatever it names.
func setsFound(p Params) []string {
	b := p.Backend
	if p.Sealed {
		return slices.DeleteFunc(slices.Clone(b.GetAllSets()), func(code string) bool {
			set, err := b.GetSet(code)
			return err != nil || len(set.SealedProduct) == 0
		})
	}
	cards, named := printings(p)
	if !named {
		return b.GetAllSets()
	}
	var codes []string
	for _, co := range cards {
		if !slices.Contains(codes, co.SetCode) {
			codes = append(codes, co.SetCode)
		}
	}
	return codes
}

// nearestSets returns the codes of the sets among codes nearest value,
// one edit from a code or a typo from a name, nearest first and at most
// fuzzy.MaxClosest, in lowercase.
func nearestSets(b *matcher.Backend, value string, codes []string) []string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
	nameLimit := len(value) / 4

	type ranked struct {
		code string
		dist int
	}
	var near []ranked
	for _, code := range codes {
		set, err := b.GetSet(code)
		if err != nil {
			continue
		}
		dist := fuzzy.Distance(value, strings.ToLower(code), 1)
		if dist > 1 {
			dist = fuzzy.Distance(value, strings.ToLower(set.Name), nameLimit)
			if nameLimit == 0 || dist > nameLimit {
				continue
			}
		}
		near = append(near, ranked{strings.ToLower(code), dist})
	}
	slices.SortStableFunc(near, func(a, b ranked) int { return a.dist - b.dist })
	var out []string
	for _, r := range near[:min(len(near), fuzzy.MaxClosest)] {
		out = append(out, r.code)
	}
	return out
}

// rewrites returns raw with the values of each field replaced by those
// nearest holds for them, a query per rank: the n-th takes the n-th
// nearest of each value, or its last.
func rewrites(raw string, fields []string, nearest [][][]string) []string {
	var count int
	for _, values := range nearest {
		for _, near := range values {
			count = max(count, len(near))
		}
	}
	var out []string
	for n := range count {
		query := raw
		for i, field := range fields {
			var values []string
			for _, near := range nearest[i] {
				values = append(values, near[min(n, len(near)-1)])
			}
			key, _, _ := strings.Cut(field, ":")
			query = replaceField(query, field, key+":"+strings.Join(values, ","))
		}
		out = append(out, query)
	}
	return out
}

// replaceField replaces the first field in query that stands as a term of
// its own, not inside a longer one, with value: in "s:atw s:at", s:at is
// the second term, not the start of the first.
func replaceField(query, field, value string) string {
	for from := 0; ; {
		at := strings.Index(query[from:], field)
		if at < 0 {
			return query
		}
		at += from
		end := at + len(field)
		if (at == 0 || query[at-1] == ' ') && (end == len(query) || strings.IndexByte(" &*~`", query[end]) >= 0) {
			return query[:at] + value + query[end:]
		}
		from = at + 1
	}
}

// SplitList splits a comma-separated list of values, keeping a comma
// inside double quotes as part of its value ("Warhammer 40,000 Commander").
// The quotes are left on each value.
func SplitList(code string) []string {
	var fields []string
	quoted := false
	start := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '"':
			quoted = !quoted
		case ',':
			if quoted {
				continue
			}
			fields = append(fields, code[start:i])
			start = i + 1
		}
	}
	return append(fields, code[start:])
}
