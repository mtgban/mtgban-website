package metricsreport

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/mtgban/mtgban-website/observability"
)

// Review is a feature review mark, one per key and instance.
type Review = observability.Review

// Lists are the open-ended value sets the registry validates by function.
type Lists struct{ Pages, Stores, Routes []string }

// Expand returns names with every function-validated kind made a list.
// A ScopePage name with a Page list takes that list as its scopes; the input is not modified.
func Expand(names []observability.Name, l Lists) []observability.Name {
	if names == nil {
		return nil
	}
	out := make([]observability.Name, len(names))
	for i, n := range names {
		switch n.Values {
		case observability.ValuePage:
			n.Enum = slices.Clone(l.Pages)
		case observability.ValueStore:
			n.Enum = slices.Clone(l.Stores)
		}
		switch n.Scope {
		case observability.ScopePage:
			if pages, every := pageList(n.Page); !every && len(pages) > 0 {
				n.Scopes = pages
			} else {
				n.Scopes = slices.Clone(l.Pages)
			}
		case observability.ScopeStore:
			n.Scopes = slices.Clone(l.Stores)
		case observability.ScopeRoute:
			n.Scopes = slices.Clone(l.Routes)
		}
		out[i] = n
	}
	return out
}

// pageList splits a Page field: every is true for "*", pages holds a trimmed list otherwise.
func pageList(page string) (pages []string, every bool) {
	page = strings.TrimSpace(page)
	if page == "*" {
		return nil, true
	}
	for _, p := range strings.Split(page, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pages = append(pages, p)
		}
	}
	return pages, false
}

// Unit is one removable thing: a candidate's key. An empty Scope or Value matches any.
type Unit struct{ Name, Scope, Value string }

// matches reports whether a row with this name, scope and value belongs to the unit.
func (u Unit) matches(name, scope, value string) bool {
	return name == u.Name && (u.Scope == "" || u.Scope == scope) && (u.Value == "" || u.Value == value)
}

// otherValue is where unknown values fold; it is a catch-all, not a feature.
const otherValue = "other"

// Units enumerates a candidate name's keys; nil for any other name.
// A name with no value or with bucket values is one unit; an enum value "other" is
// never one; an empty list counts as the single entry "".
func Units(n observability.Name) []Unit {
	if n.Report != observability.ReportCandidate {
		return nil
	}
	if n.Values == observability.ValueNone || n.Values == observability.ValueBucket {
		return []Unit{{Name: n.Name}}
	}
	var values []string
	for _, v := range n.Enum {
		if v != otherValue {
			values = append(values, v)
		}
	}
	if len(values) == 0 && len(n.Enum) > 0 && n.Unit != observability.UnitScope {
		return nil
	}
	values, scopes := orBlank(values), orBlank(n.Scopes)
	var out []Unit
	switch n.Unit {
	case observability.UnitScope:
		for _, s := range scopes {
			out = append(out, Unit{Name: n.Name, Scope: s})
		}
	case observability.UnitScopeAndValue:
		for _, s := range scopes {
			for _, v := range values {
				out = append(out, Unit{Name: n.Name, Scope: s, Value: v})
			}
		}
	default:
		for _, v := range values {
			out = append(out, Unit{Name: n.Name, Value: v})
		}
	}
	return out
}

// orBlank is list, or the single entry "" when it is empty.
func orBlank(list []string) []string {
	if len(list) == 0 {
		return []string{""}
	}
	return list
}

// TierLine is one key's split by tier, largest first: "Any 12, Legacy 3".
// It is empty when no row matches; ties go by tier name.
func TierLine(byTier []observability.DayTotal, u Unit) string {
	sums := map[string]int64{}
	for _, t := range byTier {
		if u.matches(t.Name, t.Scope, t.Value) {
			sums[t.Tier] += t.N
		}
	}
	tiers := make([]string, 0, len(sums))
	for tier := range sums {
		tiers = append(tiers, tier)
	}
	slices.SortFunc(tiers, func(a, b string) int {
		return cmp.Or(cmp.Compare(sums[b], sums[a]), cmp.Compare(a, b))
	})
	parts := make([]string, len(tiers))
	for i, tier := range tiers {
		label := tier
		if label == "" {
			label = "no tier"
		}
		parts[i] = fmt.Sprintf("%s %d", label, sums[tier])
	}
	return strings.Join(parts, ", ")
}
