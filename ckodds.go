package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// The chances CK's tooltips quote are measured every day by go-mtgban's
// cmd/ckodds, from the newspaper's history of CK's price list, and published
// beside the datastore with every CK product's category; ADR-0004 has what
// they measure. Until a load succeeds the tooltips carry their verdicts alone.
const ckOddsFile = "ck-odds.json.xz"

// ckOddsMaxAge is how old a load can be before the next refresh reads the
// file again; ckodds writes a new one every day.
const ckOddsMaxAge = 20 * time.Hour

// ckOddsPath is where the odds live: beside the datastore, like the TCGplayer
// catalog.
func ckOddsPath() string {
	p := Config.DatastorePath
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ckOddsFile
	}
	return p[:i+1] + ckOddsFile
}

// ckOddsTables is the file ckodds writes.
type ckOddsTables struct {
	Generated  time.Time         `json:"generated"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	Categories map[string]string `json:"categories"`
	Odds       []struct {
		Category string `json:"category"`
		Finish   string `json:"finish"`
		Rule     string `json:"rule"`
		Up       int    `json:"up"`
		Down     int    `json:"down"`
	} `json:"odds"`
	Pauses []struct {
		Category string `json:"category"`
		MinDays  int    `json:"min_days"`
		Week     int    `json:"week"`
		Month    int    `json:"month"`
	} `json:"pauses"`
}

// ckOddsKey names a cell of the odds: a card category ("all" for every
// card), a finish ("" for either) and a rule, or "typical" for every
// card-day of the category.
type ckOddsKey struct{ Category, Finish, Rule string }

// ckChances are the chances, in percent, of CK paying 5% more and 5% less
// or nothing two weeks on.
type ckChances struct{ Up, Down int }

// ckReopen are the chances, in percent, of CK buying a paused card again
// within 7 and 30 days, once the pause has lasted MinDays.
type ckReopen struct{ MinDays, Week, Month int }

// ckPauseTipKey names one of the pause tooltips; days stop at 30.
type ckPauseTipKey struct {
	Category string
	Days     int
	Wait     bool
}

// ckOdds is one load of the odds, with every tooltip written from them.
type ckOdds struct {
	Generated  time.Time
	From, To   string
	categories map[string]string // CK product id -> category
	chances    map[ckOddsKey]ckChances
	reopen     map[string][]ckReopen // by category, the longest pause first
	tips       map[ckOddsKey]string
	pauseTips  map[ckPauseTipKey]string
}

var ckOddsPtr atomic.Pointer[ckOdds]

// newCKOdds reads the tables and writes every tooltip once, so pages look
// them up rather than write them.
func newCKOdds(t ckOddsTables) *ckOdds {
	o := &ckOdds{
		Generated:  t.Generated,
		From:       t.From,
		To:         t.To,
		categories: t.Categories,
		chances:    map[ckOddsKey]ckChances{},
		reopen:     map[string][]ckReopen{},
		tips:       map[ckOddsKey]string{},
		pauseTips:  map[ckPauseTipKey]string{},
	}
	for _, row := range t.Odds {
		o.chances[ckOddsKey{row.Category, row.Finish, row.Rule}] = ckChances{row.Up, row.Down}
	}
	for _, row := range t.Pauses {
		o.reopen[row.Category] = append(o.reopen[row.Category], ckReopen{row.MinDays, row.Week, row.Month})
	}
	for category := range o.reopen {
		slices.SortFunc(o.reopen[category], func(a, b ckReopen) int { return b.MinDays - a.MinDays })
	}

	categories := []string{"all"}
	for _, category := range t.Categories {
		if !slices.Contains(categories, category) {
			categories = append(categories, category)
		}
	}
	for _, category := range categories {
		for _, finish := range []string{"foil", "nonfoil"} {
			for rule := range ckVerdicts {
				o.tips[ckOddsKey{category, finish, rule}] = o.tipFor(category, finish, rule)
			}
		}
		reopen, found := o.reopen[category]
		if !found {
			reopen = o.reopen["all"]
		}
		for days := 0; days <= 30; days++ {
			for _, wait := range []bool{false, true} {
				o.pauseTips[ckPauseTipKey{category, days, wait}] = ckPauseTip(reopen, days, wait)
			}
		}
	}
	return o
}

// oddsFor is a rule's chances for a card of category and finish, and the
// typical ones they compare with: by finish where that was measured, else
// by category, else over every card.
func (o *ckOdds) oddsFor(category, finish, rule string) (odds, typical ckChances, found bool) {
	for _, key := range []ckOddsKey{{category, finish, rule}, {category, "", rule}, {"all", "", rule}} {
		odds, found = o.chances[key]
		typical, hasTypical := o.chances[ckOddsKey{key.Category, key.Finish, "typical"}]
		if found && hasTypical {
			return odds, typical, true
		}
	}
	return ckChances{}, ckChances{}, false
}

// tipFor is a rule's tooltip on a card of category and finish: its verdict,
// then its chances next to the typical ones where they were measured.
func (o *ckOdds) tipFor(category, finish, rule string) string {
	odds, typical, found := o.oddsFor(category, finish, rule)
	if !found {
		return ckVerdicts[rule]
	}
	return ckVerdicts[rule] + "\n" +
		"Chances CK pays (two weeks from now):\n" +
		fmt.Sprintf("• 5%% more: **%d%%** instead of %d%%\n", odds.Up, typical.Up) +
		fmt.Sprintf("• 5%% less or stops buying: **%d%%** instead of %d%%", odds.Down, typical.Down)
}

// category is a CK product's category, or "all" where the odds do not know
// the product.
func (o *ckOdds) category(id string) string {
	category, found := o.categories[id]
	if !found {
		return "all"
	}
	return category
}

// tip is a rule's tooltip on a CK product of finish: its verdict alone
// until the odds are loaded.
func (o *ckOdds) tip(id, finish, rule string) string {
	if o == nil {
		return ckVerdicts[rule]
	}
	return o.tips[ckOddsKey{o.category(id), finish, rule}]
}

// pauseTip is the tooltip of a pause of days on a CK product.
func (o *ckOdds) pauseTip(id string, days int, wait bool) string {
	days = min(days, 30)
	if o == nil {
		return ckPauseTip(nil, days, wait)
	}
	return o.pauseTips[ckPauseTipKey{o.category(id), days, wait}]
}

// loadCKOdds reads the odds the path names.
func loadCKOdds(ctx context.Context, path string) (*ckOdds, error) {
	reader, err := openBucketPath(ctx, path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var t ckOddsTables
	err = json.NewDecoder(reader).Decode(&t)
	if err != nil {
		return nil, err
	}
	return newCKOdds(t), nil
}

// refreshCKOdds loads the odds when none are loaded or the loaded ones are
// a day old. A failed load keeps the last one.
func refreshCKOdds() {
	if Config.Game != DefaultGame {
		return
	}
	current := ckOddsPtr.Load()
	if current != nil && time.Since(current.Generated) < ckOddsMaxAge {
		return
	}
	odds, err := loadCKOdds(context.Background(), ckOddsPath())
	if err != nil {
		log.Println("ck odds:", err)
		return
	}
	ckOddsPtr.Store(odds)
	log.Println("ck odds: loaded, measured", odds.From, "to", odds.To, "for", len(odds.categories), "products")
}
