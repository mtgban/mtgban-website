package main

import (
	"cmp"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
)

// slabGraders is the order the Graded page lists the graders in.
var slabGraders = []string{"PSA", "BGS", "CGC", "TAG"}

// otherSlabs is the group of the slabs with no grader the page can list them
// under: one it does not know, or no details at all.
const otherSlabs = mtgban.Condition("Other slabs")

// slabLabels is the order one score's labels run in, any other after them and
// the plain score last.
var slabLabels = []string{"Black Label", "Pristine"}

// rawSorts are the sorts the Graded page does not take, reading the prices
// and sales of raw copies.
var rawSorts = []string{"retail", "buylist", "velocity"}

// slabLabelRank is a label's place in its score.
func slabLabelRank(label string) int {
	if label == "" {
		return len(slabLabels) + 1
	}
	rank := slices.Index(slabLabels, label)
	if rank < 0 {
		return len(slabLabels)
	}
	return rank
}

// hasGradedStores says whether a loaded seller lists slabs.
func (p *prices) hasGradedStores() bool {
	return slices.ContainsFunc(p.sellers, func(seller mtgban.Seller) bool {
		return seller.Info().GradedMode
	})
}

// gradedSearch makes a search the Graded page's: of slabs alone, which no
// store has a buylist for.
func gradedSearch(config *SearchConfig) {
	config.GradedOnly = true
	config.SkipBuylist = true
}

// slabGroup is the group a row is listed under on the Graded page, and
// whether its slab has a grader to list it under.
func slabGroup(entry SearchEntry) (mtgban.Condition, bool) {
	if entry.Slab == nil || entry.Slab.Grader == "" {
		return otherSlabs, false
	}
	return mtgban.Condition(entry.SlabName()), true
}

// groupBySlab lists each card's offers under their slabs' grades rather than
// the conditions they fold to, and returns the grades in order: by grader,
// best score first, its labels above the plain score and one with no score
// below them all, the other slabs last. A grade's offers are cheapest first with byPrice, else
// in the order they came in.
func groupBySlab(found map[string]map[mtgban.Condition][]SearchEntry, byPrice bool) []mtgban.Condition {
	slabs := map[mtgban.Condition]mtgban.Slab{}
	other := false
	for cardID, conds := range found {
		groups := map[mtgban.Condition][]SearchEntry{}
		for _, cond := range AllConditions {
			for _, entry := range conds[cond] {
				group, graded := slabGroup(entry)
				if graded {
					slabs[group] = *entry.Slab
				} else {
					other = true
				}
				groups[group] = append(groups[group], entry)
			}
		}
		if byPrice {
			for _, entries := range groups {
				slices.SortStableFunc(entries, func(a, b SearchEntry) int {
					return cmp.Compare(a.Price, b.Price)
				})
			}
		}
		found[cardID] = groups
	}

	var keys []mtgban.Condition
	for group := range slabs {
		keys = append(keys, group)
	}
	slices.SortFunc(keys, func(a, b mtgban.Condition) int {
		x, y := slabs[a], slabs[b]
		return cmp.Or(
			cmp.Compare(slices.Index(slabGraders, x.Grader), slices.Index(slabGraders, y.Grader)),
			cmp.Compare(y.Score, x.Score),
			cmp.Compare(slabLabelRank(x.Label), slabLabelRank(y.Label)),
			strings.Compare(x.Label, y.Label),
		)
	})
	if other {
		keys = append(keys, otherSlabs)
	}
	return keys
}
