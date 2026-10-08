package main

import (
	"context"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The Searches tab's windows, in days, and how far down the ranking it
// lists. The carousel's own window is the default.
var searchesWindows = []int{7, 30, 90}

const (
	searchesDefaultWindow = popularWindowDays
	searchesLimit         = 100
)

// SearchRow is one ranked key as the tab lists it: what kind of thing it
// names, how it was most often typed, its name linking to the search, and
// the user counts it ranked on.
type SearchRow struct {
	Rank        int
	Kind        string
	Query       string
	Label       string
	URL         string
	Users       int
	RecentUsers int
}

// SearchesDashboard is what /admin?page=searches shows for one window: the
// ranking with every key that got a vote, the window's totals, and the
// tiles the homepage carousel currently shows. Failed says a query did not
// answer, so an empty table is the store's silence, not a quiet week;
// Dropped is how many ranked keys the resolver did not know.
type SearchesDashboard struct {
	Instance string
	Window   int
	Windows  []int
	Since    time.Time
	Totals   observability.SearchVoteTotals
	Rows     []SearchRow
	Dropped  int
	Failed   bool
	Carousel []PopularTile
	RankedAt time.Time
}

type searchesCacheEntry struct {
	dash    *SearchesDashboard
	fetched time.Time
}

// searchesCache holds one entry per window, the only axis the tab varies
// on, with the same lock-covers-the-query rule as usageCache.
var searchesCache = struct {
	mu       sync.Mutex
	byWindow map[int]searchesCacheEntry
}{byWindow: map[int]searchesCacheEntry{}}

// searchesWindow reads the window a request asks for; anything but an
// offered one is the default.
func searchesWindow(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return searchesDefaultWindow
	}
	for _, w := range searchesWindows {
		if w == n {
			return w
		}
	}
	return searchesDefaultWindow
}

// loadSearchesDashboard ranks the window's votes for the tab, reusing a
// recent copy when there is one. The cached value is never handed out: the
// caller gets its own copy with the carousel section read fresh, since a
// request may still be rendering what an earlier one was given.
func loadSearchesDashboard(ctx context.Context, ds *datastore, store popularRankStore, window int) *SearchesDashboard {
	searchesCache.mu.Lock()
	defer searchesCache.mu.Unlock()

	entry, found := searchesCache.byWindow[window]
	if !found || time.Since(entry.fetched) >= usageCacheTTL {
		dash, failed := fetchSearchesDashboard(ctx, ds, store, window)
		entry = searchesCacheEntry{dash: dash, fetched: time.Now()}
		// A query that failed leaves its table empty, so let the next view
		// retry rather than serving the gap for the rest of the window.
		if !failed {
			searchesCache.byWindow[window] = entry
		}
	}
	dash := *entry.dash
	fillSearchesCarousel(&dash)
	return &dash
}

// fetchSearchesDashboard runs the window's queries; failed says one of them
// did not answer and the dashboard is missing its part.
func fetchSearchesDashboard(ctx context.Context, ds *datastore, store popularRankStore, window int) (dash *SearchesDashboard, failed bool) {
	now := time.Now().UTC()
	// A window of N days is N calendar dates, today included, as the
	// ranking job counts it.
	since := now.AddDate(0, 0, -(window - 1))
	recentSince := now.AddDate(0, 0, -(popularRecentDays - 1))
	dash = &SearchesDashboard{Instance: observabilityInstance, Window: window, Windows: searchesWindows, Since: since}

	ranks, err := store.TopSearches(ctx, observabilityInstance, since, recentSince, 1, searchesLimit)
	if err != nil {
		log.Println("searches: rank:", err)
		failed = true
	}
	dash.Rows, dash.Dropped = searchRows(ds, ranks)
	dash.Totals, err = store.SearchVoteTotals(ctx, observabilityInstance, since)
	if err != nil {
		log.Println("searches: totals:", err)
		failed = true
	}
	dash.Failed = failed
	return dash, failed
}

// searchRows turns a ranking into the tab's rows, each at the rank the
// store gave it, and counts the keys the tile resolver does not know
// rather than listing them bare.
func searchRows(ds *datastore, ranks []observability.SearchRank) (rows []SearchRow, dropped int) {
	for i, rank := range ranks {
		_, linkQuery, label := popularRankQuery(ds.backend, rank)
		if linkQuery == "" {
			dropped++
			continue
		}
		// The prefix is one popularRankQuery knows, having resolved it.
		kind, _, _ := strings.Cut(rank.Key, ":")
		rows = append(rows, SearchRow{
			Rank:        i + 1,
			Kind:        kind,
			Query:       rank.Query,
			Label:       label,
			URL:         "/search?q=" + url.QueryEscape(linkQuery),
			Users:       rank.Users,
			RecentUsers: rank.RecentUsers,
		})
	}
	return rows, dropped
}

// fillSearchesCarousel puts the published ranking, the one the homepage
// shows, on the dashboard; nothing before one is published.
func fillSearchesCarousel(dash *SearchesDashboard) {
	dash.Carousel, dash.RankedAt = nil, time.Time{}
	if snap := popularOrganicSnapshot(); snap != nil {
		dash.Carousel, dash.RankedAt = snap.Tiles, snap.At
	}
}
