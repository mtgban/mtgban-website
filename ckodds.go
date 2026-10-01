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

// The chances CK's tooltips quote, and what the rules read about each CK
// product beyond its prices, are measured every day by ckodds in
// mtgban/ck-buylist-analysis from the newspaper and published beside the
// datastore; ADR-0004 has the rules. Until a load succeeds no CK offer is colored.
const ckOddsFile = "ck-odds-v2.json.xz"

// ckOddsMaxAge is how old a load can be before the next refresh reads the
// file again; ckodds writes a new one every day.
const ckOddsMaxAge = 20 * time.Hour

// A cell quotes its own chances from this many printings; a thinner one
// quotes its finish over every retail band.
const ckMinPrintings = 300

// ckOddsPath is where the odds live: beside the datastore, like the TCGplayer
// catalog.
func ckOddsPath() string {
	p := Config().DatastorePath
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ckOddsFile
	}
	return p[:i+1] + ckOddsFile
}

// ckOddsTables is the file ckodds writes.
type ckOddsTables struct {
	Generated time.Time `json:"generated"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Cells     []struct {
		Group     string `json:"group"`
		Finish    string `json:"finish"`
		Bucket    string `json:"bucket"`
		Verdict   string `json:"verdict"`
		WeekMore  int    `json:"week_more"`
		WeekLess  int    `json:"week_less"`
		MonthMore int    `json:"month_more"`
		MonthLess int    `json:"month_less"`
		Printings int    `json:"printings"`
	} `json:"cells"`
	Pauses []struct {
		Finish         string    `json:"finish"`
		MinDays        int       `json:"min_days"`
		BackMonth      int       `json:"back_month"`
		BackOverListed []float64 `json:"back_over_listed"`
	} `json:"pauses"`
	Products map[string]struct {
		Foil          bool    `json:"foil"`
		Exception     bool    `json:"exception"`
		SetReleased   string  `json:"set_released"`
		Reprinted     string  `json:"reprinted"`
		Market        float64 `json:"market"`
		MarketWeekAgo float64 `json:"market_week_ago"`
	} `json:"products"`
}

// ckCellKey names a cell of the odds: the group ("cohort", or "exceptions"
// for the Reserved List and sets through 1994), the finish, CK's retail band
// ("all" for every band) and the verdict, or "typical" for every card-day.
type ckCellKey struct{ Group, Finish, Bucket, Verdict string }

// ckChances are the chances, in percent, of CK paying more and less or
// nothing a week and a month on.
type ckChances struct{ WeekMore, WeekLess, MonthMore, MonthLess, Printings int }

// ckReopen is, for a pause of MinDays or more, the chance in percent of CK
// buying again within 30 days and the deciles of the price it comes back at
// over the price it lists.
type ckReopen struct {
	MinDays   int
	BackMonth int
	Deciles   []float64
}

// ckProduct is what the rules read about a CK product beyond its prices.
type ckProduct struct {
	Foil, Exception        bool
	SetReleased, Reprinted time.Time // zero when unknown or never
	Market, MarketWeekAgo  float64   // TCG Market; zero when unknown
}

// ckOdds is one load of the odds.
type ckOdds struct {
	Generated time.Time
	From, To  string
	chances   map[ckCellKey]ckChances
	reopen    map[string][]ckReopen // by finish, the longest pause first
	products  map[string]ckProduct
}

var ckOddsPtr atomic.Pointer[ckOdds]

func newCKOdds(t ckOddsTables) *ckOdds {
	o := &ckOdds{
		Generated: t.Generated,
		From:      t.From,
		To:        t.To,
		chances:   map[ckCellKey]ckChances{},
		reopen:    map[string][]ckReopen{},
		products:  map[string]ckProduct{},
	}
	for _, c := range t.Cells {
		o.chances[ckCellKey{c.Group, c.Finish, c.Bucket, c.Verdict}] = ckChances{c.WeekMore, c.WeekLess, c.MonthMore, c.MonthLess, c.Printings}
	}
	for _, p := range t.Pauses {
		o.reopen[p.Finish] = append(o.reopen[p.Finish], ckReopen{p.MinDays, p.BackMonth, p.BackOverListed})
	}
	for finish := range o.reopen {
		slices.SortFunc(o.reopen[finish], func(a, b ckReopen) int { return b.MinDays - a.MinDays })
	}
	for id, p := range t.Products {
		cp := ckProduct{Foil: p.Foil, Exception: p.Exception, Market: p.Market, MarketWeekAgo: p.MarketWeekAgo}
		cp.SetReleased, _ = time.Parse(time.DateOnly, p.SetReleased)
		cp.Reprinted, _ = time.Parse(time.DateOnly, p.Reprinted)
		o.products[id] = cp
	}
	return o
}

// ckBucketOf is the band of CK's retail the odds are quoted by, as ckodds
// measures them.
func ckBucketOf(retail float64) string {
	switch {
	case retail < 10:
		return "5-10"
	case retail < 20:
		return "10-20"
	case retail < 50:
		return "20-50"
	case retail < 100:
		return "50-100"
	case retail < 200:
		return "100-200"
	}
	return "200+"
}

// chancesFor are a verdict's chances for a card, the typical ones they
// compare with, and the cell they were read from: its group, finish and band
// where that cell counts ckMinPrintings, else its group and finish over every
// band, else every card of its finish. The exceptions are quoted over every
// band. found is false when the file lists none of them: a verdict that is
// not measured does not hold.
func (o *ckOdds) chancesFor(group, finish, bucket, verdict string) (cell ckCellKey, odds, typical ckChances, found bool) {
	if o == nil {
		return ckCellKey{}, ckChances{}, ckChances{}, false
	}
	keys := []ckCellKey{{group, finish, "all", verdict}, {"cohort", finish, "all", verdict}}
	if group == "cohort" {
		keys = append([]ckCellKey{{group, finish, bucket, verdict}}, keys...)
	}
	for _, key := range keys {
		c, ok := o.chances[key]
		t, okTypical := o.chances[ckCellKey{key.Group, key.Finish, key.Bucket, "typical"}]
		if ok && okTypical && c.Printings >= ckMinPrintings {
			return key, c, t, true
		}
	}
	return ckCellKey{}, ckChances{}, ckChances{}, false
}

// ckChanceLines are the table of a tooltip quoting a cell's chances: for a
// wait the chances CK pays more, for a sell or a new high those it pays less
// or nothing, a week and a month on, next to the typical ones; then, as its
// footnote, what they were measured on.
func ckChanceLines(cell ckCellKey, odds, typical ckChances) string {
	head, week, weekTypical, month, monthTypical := "CK pays more", odds.WeekMore, typical.WeekMore, odds.MonthMore, typical.MonthMore
	if cell.Verdict != "wait" {
		head, week, weekTypical, month, monthTypical = "CK pays less or nothing", odds.WeekLess, typical.WeekLess, odds.MonthLess, typical.MonthLess
	}
	measured := fmt.Sprintf("Measured on %d %ss", odds.Printings, cell.Finish)
	if cell.Bucket != "all" {
		measured += " at $" + cell.Bucket
	}
	if cell.Group == "exceptions" {
		measured += ", RL or pre-1995"
	}
	return "|# " + head + " | This card | Typical\n" +
		fmt.Sprintf("| In a week | **%d%%** | %d%%\n", week, weekTypical) +
		fmt.Sprintf("| In a month | **%d%%** | %d%%\n", month, monthTypical) +
		measured
}

// reopenFor is the pause cell of a finish for a pause of days, or nil.
func (o *ckOdds) reopenFor(finish string, days int) *ckReopen {
	if o == nil {
		return nil
	}
	for i, r := range o.reopen[finish] {
		if days >= r.MinDays {
			return &o.reopen[finish][i]
		}
	}
	return nil
}

// product is what the file says about a CK product, and whether it says
// anything.
func (o *ckOdds) product(id string) (ckProduct, bool) {
	if o == nil {
		return ckProduct{}, false
	}
	p, found := o.products[id]
	return p, found
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
	log.Println("ck odds: loaded, measured", odds.From, "to", odds.To, "for", len(odds.products), "products")
}
