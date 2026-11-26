package main

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
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

// gradedSales is each card's Last Sold groups, as the Sales pane draws them:
// the sales of the grades a store lists it in, in the page's order of grades,
// or of every grade it sold in where no store lists it.
func gradedSales(snap *salesvelocity.GradedSnapshot, found map[string]map[mtgban.Condition][]SearchEntry, cardIDs []string, keys []mtgban.Condition) map[string][]salesvelocity.Group {
	out := map[string][]salesvelocity.Group{}
	for _, cardID := range cardIDs {
		sales := snap.For(cardID)
		if sales == nil || out[cardID] != nil {
			continue
		}
		listed := found[cardID]
		if len(listed) == 0 {
			var sold []mtgban.Slab
			for slab := range sales.Grades {
				if slab.Grader != "" {
					sold = append(sold, slab)
				}
			}
			slices.SortFunc(sold, slabOrder)
			for _, slab := range sold {
				out[cardID] = append(out[cardID], sales.Grades[slab].Group(slabName(&slab)))
			}
			continue
		}
		byGrade := map[mtgban.Condition]*salesvelocity.GradeSales{}
		for slab, grade := range sales.Grades {
			name, graded := slabGroup(&slab)
			if graded {
				byGrade[name] = grade
			}
		}
		for _, key := range keys {
			grade, found := byGrade[key]
			if found && len(listed[key]) > 0 {
				out[cardID] = append(out[cardID], grade.Group(string(key)))
			}
		}
	}
	return out
}

// gradedVelocity puts the slabs' Sales Velocity in place of the raw copies'
// on each card, none where no slab of it sold.
func gradedVelocity(m cardMetadata, snap *salesvelocity.GradedSnapshot, keys []string) {
	name := func(slab mtgban.Slab) string { return slabName(&slab) }
	var day time.Time
	if snap != nil {
		day = snap.Day
	}
	for _, cardID := range keys {
		card, found := m[cardID]
		if !found {
			continue
		}
		card.Velocity, card.VelocityDetail = snap.For(cardID).Velocity(day, name)
		card.VelocityPace, card.VelocityNote, card.VelocityRising = salesvelocity.PaceNone, "", false
		m[cardID] = card
	}
}

// slabOrder orders slabs as the Graded page lists them: by grader, best score
// first, its labels above the plain score and one with no score below them all.
func slabOrder(x, y mtgban.Slab) int {
	return cmp.Or(
		cmp.Compare(slices.Index(slabGraders, x.Grader), slices.Index(slabGraders, y.Grader)),
		cmp.Compare(y.Score, x.Score),
		cmp.Compare(slabLabelRank(x.Label), slabLabelRank(y.Label)),
		strings.Compare(x.Label, y.Label),
	)
}

// gradedKeys is the cards the Graded page lists of keys: those a graded store
// offers, and those a slab of sold, where sold is not nil.
func gradedKeys(stores *postStores, keys []string, sold *salesvelocity.GradedSnapshot) []string {
	offered := stores.offered(keys)
	if sold == nil {
		return offered
	}
	kept := map[string]bool{}
	for _, cardID := range offered {
		kept[cardID] = true
	}
	return slices.DeleteFunc(slices.Clone(keys), func(cardID string) bool {
		return !kept[cardID] && sold.For(cardID) == nil
	})
}

// slabGroup is the group a slab is listed under, on the Graded page and in
// the API, and whether it has a grader to list it under.
func slabGroup(slab *mtgban.Slab) (mtgban.Condition, bool) {
	if slab == nil || slab.Grader == "" {
		return otherSlabs, false
	}
	return mtgban.Condition(slabName(slab)), true
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
				group, graded := slabGroup(entry.Slab)
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
		return slabOrder(slabs[a], slabs[b])
	})
	if other {
		keys = append(keys, otherSlabs)
	}
	return keys
}

// slabShowcaseSize is how many slabs the Graded page's landing shows, and how
// many cards each graded store puts forward for it.
const slabShowcaseSize = 24

// showcaseSlab is a slab the Graded page's landing can show: the dearest a
// graded store lists of one card, every entry of an inventory being a copy
// in stock.
type showcaseSlab struct {
	cardID    string
	shorthand string
	entry     mtgban.InventoryEntry
}

// slabShowcase is what the graded stores among sellers put forward for the
// Graded page's landing, dearest first: each store's slabShowcaseSize dearest
// cards in stock, so a reader who hides some stores still fills the carousel
// from the others.
func slabShowcase(sellers []mtgban.Seller) []showcaseSlab {
	var out []showcaseSlab
	for _, seller := range sellers {
		info := seller.Info()
		if !info.GradedMode {
			continue
		}
		var dearest []showcaseSlab
		for cardID, entries := range seller.Inventory() {
			best := -1
			for i, entry := range entries {
				if entry.Price > 0 && (best < 0 || entry.Price > entries[best].Price) {
					best = i
				}
			}
			if best >= 0 {
				dearest = append(dearest, showcaseSlab{cardID, info.Shorthand, entries[best]})
			}
		}
		slices.SortFunc(dearest, compareShowcase)
		out = append(out, dearest[:min(len(dearest), slabShowcaseSize)]...)
	}
	slices.SortFunc(out, compareShowcase)
	return out
}

// compareShowcase orders slabs dearest first, the same way on every load.
func compareShowcase(a, b showcaseSlab) int {
	return cmp.Or(
		cmp.Compare(b.entry.Price, a.entry.Price),
		strings.Compare(a.cardID, b.cardID),
		strings.Compare(a.shorthand, b.shorthand),
	)
}

// slabShowcaseFor is the showcase over sellers, carried across from prev, as
// mkmIDsFor carries its map, where the graded stores are the same ones.
func slabShowcaseFor(prev *prices, sellers []mtgban.Seller) []showcaseSlab {
	raw := func(seller mtgban.Seller) bool { return !seller.Info().GradedMode }
	if prev != nil && slices.Equal(slices.DeleteFunc(slices.Clone(prev.sellers), raw), slices.DeleteFunc(slices.Clone(sellers), raw)) {
		return prev.showcase
	}
	return slabShowcase(sellers)
}

// fillSlabShowcase puts the Graded page's landing carousel on the page the
// way a search puts its results: the dearest slabs in stock at the stores the
// reader sees, one per card and under its grade, locked or left out where a
// search would lock or leave out that store.
func fillSlabShowcase(pageVars *PageVars, b *matcher.Backend, p *prices, blocked []string) {
	affiliates := Affiliates().List
	hide := Config().SearchHideNonAffiliates
	pageVars.FoundSellers = map[string]map[mtgban.Condition][]SearchEntry{}
	pageVars.Metadata = cardMetadata{}
	hidden := false
	for _, slab := range p.showcase {
		if len(pageVars.AllKeys) == slabShowcaseSize {
			break
		}
		_, shown := pageVars.FoundSellers[slab.cardID]
		if shown || slices.Contains(blocked, slab.shorthand) {
			continue
		}
		locked := pageVars.ListingLocked && !slices.Contains(affiliates, slab.shorthand)
		if locked && hide {
			hidden = true
			continue
		}
		group, _ := slabGroup(slab.entry.Slab)
		pageVars.FoundSellers[slab.cardID] = map[mtgban.Condition][]SearchEntry{
			group: {{
				ScraperName: p.scraperName(slab.shorthand),
				Shorthand:   slab.shorthand,
				Price:       slab.entry.Price,
				URL:         slab.entry.URL,
				Grade:       slab.entry.Conditions,
				Slab:        slab.entry.Slab,
				Locked:      locked,
			}},
		}
		pageVars.AllKeys = append(pageVars.AllKeys, slab.cardID)
		pageVars.Metadata.add(b, p, slab.cardID, false)
	}
	if hidden && len(pageVars.AllKeys) == 0 {
		pageVars.Notices = append(pageVars.Notices, SlabsLockedMessage)
	}
}
