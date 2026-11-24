package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

// salesVelocityStore holds the loaded sales. A request reads its snapshot once
// and hands it to the row, filters and sort.
var salesVelocityStore = &salesvelocity.Store{}

// refreshNewspaper reloads what the site reads from the newspaper: its pages,
// then the sales, which load only when the newspaper has a new sale day. Each
// is a job of its own, so the dashboard times them apart and neither panic
// stops the other.
func (s *site) refreshNewspaper() {
	tracked(jobNewspaper, s.cacheNewspaper)()
	tracked(jobSalesVelocity, s.loadSalesVelocity)()
}

// loadSalesVelocity loads the newspaper's last complete sale day once it is new.
func (s *site) loadSalesVelocity() {
	game, found := gameMap[Config().Game]
	if !found || SkipNewspaper || NewNewspaperDB == nil {
		return
	}
	b := s.backend()
	if len(b.GetUUIDs()) == 0 {
		// No datastore yet: its load runs this once it is in.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, problem := salesVelocityStore.Load(ctx, NewNewspaperDB, b, game)
	if result != "" || problem != "" {
		backgroundJobs.Report(jobSalesVelocity, result, problem)
	}
}

// recentSalesStore holds TCGplayer's recent orders per card. A request reads
// its snapshot once, like the velocity's.
var recentSalesStore = &salesvelocity.RecentStore{}

// loadRecentSales reads the orders the newspaper wrote since the last load, or
// all of them on a new day or datastore.
func (s *site) loadRecentSales() {
	game, found := gameMap[Config().Game]
	if !found || SkipNewspaper || NewNewspaperDB == nil {
		return
	}
	b := s.backend()
	if len(b.GetUUIDs()) == 0 {
		// No datastore yet: its load runs this once it is in.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, problem := recentSalesStore.Load(ctx, NewNewspaperDB, b, game, time.Now())
	if result != "" || problem != "" {
		backgroundJobs.Report(jobRecentSales, result, problem)
	}
}

// The Buyers column's two modes, as the SearchBuyersMode cookie stores them.
const (
	buyersBuylist = "buylist"
	buyersSales   = "sales"
)

// buyersMode is the mode the reader chose, else the game's default.
func buyersMode(chosen, gameDefault string) string {
	switch chosen {
	case buyersBuylist, buyersSales:
		return chosen
	}
	if gameDefault == buyersSales {
		return buyersSales
	}
	return buyersBuylist
}

// canSeeSales says whether the reader's signature grants the recent sales.
func canSeeSales(sig string) bool {
	canSales, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchSales"))
	return canSales || (DevMode && !SigCheck)
}

// fillRecentSales sets the Buyers column's mode for the reader and which
// cards have orders, the buylist and none for a reader the sales are hidden
// from. The search draws no sales: the page fetches the panes from
// /data/sales/ once it is on show in Sales, so no mode costs a search.
func fillRecentSales(v *SearchVars, recent *salesvelocity.RecentSnapshot, r *http.Request, sig string, keys []string) {
	v.CanSales = canSeeSales(sig)
	v.BuyersMode = buyersBuylist
	if !v.CanSales {
		return
	}
	v.BuyersMode = buyersMode(readCookie(r, "SearchBuyersMode"), Config().SearchBuyersDefault)
	v.HasSales = map[string]bool{}
	for _, cardID := range keys {
		_, found := recent.For(cardID)
		if found {
			v.HasSales[cardID] = true
		}
	}
}

// checkNewspaperSales reports on the job's row when the newspaper's sales pull
// looks signed out or stopped, which checkJobHealth then announces.
func checkNewspaperSales() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, problem := salesvelocity.CheckPull(ctx, NewNewspaperDB)
	backgroundJobs.Report(jobNewspaperSales, result, problem)
}

// cardFilterVelocityGreaterThan skips a card selling at most the rate asked,
// and one with no data, which is not the same as selling none.
func cardFilterVelocityGreaterThan(sales *salesvelocity.Snapshot, limit float64, co *matcher.CardObject) bool {
	v, found := sales.For(co.UUID)
	if !found {
		return true
	}
	return v.PerDay(salesvelocity.Window) <= limit
}

// cardFilterVelocityLessThan skips a card selling at least the rate asked, and
// one with no data.
func cardFilterVelocityLessThan(sales *salesvelocity.Snapshot, limit float64, co *matcher.CardObject) bool {
	v, found := sales.For(co.UUID)
	if !found {
		return true
	}
	return v.PerDay(salesvelocity.Window) >= limit
}

// A velocity filter parses locked and a locked one matches nothing, so no way
// into the parser reveals which cards sell without having read the reader's tier.
const lockedFilterPrefix = "locked_"

// unlockVelocity opens a query's velocity filters, those in its pools too, for
// a handler that checked the reader's signature, to judge cards by sales.
func unlockVelocity(filters []FilterElem, sales *salesvelocity.Snapshot) {
	for i := range filters {
		if filters[i].Pool != nil {
			unlockVelocity(filters[i].Pool.CardFilters, sales)
		}
		filters[i].Name = strings.TrimPrefix(filters[i].Name, lockedFilterPrefix)
		filters[i].Sales = sales
	}
}

// lockedVelocity reports whether a query holds a velocity filter still locked.
func lockedVelocity(filters []FilterElem) bool {
	for i := range filters {
		if strings.HasPrefix(filters[i].Name, lockedFilterPrefix) {
			return true
		}
		if filters[i].Pool != nil && lockedVelocity(filters[i].Pool.CardFilters) {
			return true
		}
	}
	return false
}
