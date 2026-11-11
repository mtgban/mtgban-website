package suggest

import (
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
		for _, value := range strings.Split(values, ",") {
			near := nearestSets(p.Backend, value, codes)
			if len(near) == 0 {
				return nil
			}
			nearest[i] = append(nearest[i], near)
		}
	}
	return rewrites(p.RawQuery, p.UnknownSets, nearest)
}

// queryName is the name p's query searches by: what its filters leave.
func queryName(p Params) string {
	name := p.RawQuery
	for _, field := range slices.Concat(p.UnknownSets, p.AppliedFilters) {
		name = strings.Replace(name, field, "", 1)
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
			query = strings.Replace(query, field, key+":"+strings.Join(values, ","), 1)
		}
		out = append(out, query)
	}
	return out
}
