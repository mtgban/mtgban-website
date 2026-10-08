package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The window comes from the query string and is one of the offered ones;
// anything else is the carousel's own 30 days.
func TestSearchesWindowReadsOnlyTheOfferedOnes(t *testing.T) {
	for in, want := range map[string]int{"7": 7, "30": 30, "90": 90, "": 30, "14": 30, "x": 30, "-7": 30} {
		if got := searchesWindow(in); got != want {
			t.Errorf("searchesWindow(%q) = %d, want %d", in, got, want)
		}
	}
}

// The tab lists every ranked key as a row the admin can follow: a card by
// its name, a set by its name, each linking to the search; a key the
// resolver does not know is left out rather than shown bare.
func TestSearchesDashboardRowsFollowTheRanking(t *testing.T) {
	skipWithoutDatastore(t)
	t.Cleanup(func() { searchesCache.byWindow = map[int]searchesCacheEntry{} })

	store := &fakeRankStore{
		ranks: []observability.SearchRank{
			{Key: "card:Black Lotus", Query: "black lotus", Users: 12, RecentUsers: 4},
			{Key: "moon:phase", Query: "?", Users: 10, RecentUsers: 1},
			{Key: "set:LEA", Query: "s:lea", Users: 9, RecentUsers: 9},
		},
		totals: observability.SearchVoteTotals{Votes: 40, Users: 15, Keys: 3},
	}
	dash := loadSearchesDashboard(context.Background(), currentDatastore(), store, 7)

	if dash.Window != 7 || dash.Totals != store.totals || dash.Failed {
		t.Fatalf("window %d totals %+v failed %v", dash.Window, dash.Totals, dash.Failed)
	}
	if dash.Dropped != 1 {
		t.Errorf("dropped %d keys, want the 1 the resolver does not know", dash.Dropped)
	}
	if store.minUsers != 1 || store.limit != searchesLimit {
		t.Errorf("asked for minUsers %d limit %d, want 1 and %d", store.minUsers, store.limit, searchesLimit)
	}
	if got := time.Since(store.since).Hours() / 24; got < 5.9 || got > 6.1 {
		t.Errorf("since is %.1f days ago, want 6 (a 7-day window is 7 dates, today included)", got)
	}
	if len(dash.Rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(dash.Rows), dash.Rows)
	}
	card, set := dash.Rows[0], dash.Rows[1]
	if card.Rank != 1 || card.Kind != "card" || card.Label != "Black Lotus" || card.URL != "/search?q=Black+Lotus" || card.Users != 12 || card.RecentUsers != 4 || card.Query != "black lotus" {
		t.Errorf("card row = %+v", card)
	}
	// The store's rank is kept, so a dropped key leaves a gap rather than
	// moving what follows it up.
	if set.Rank != 3 || set.Kind != "set" || set.Label != "Limited Edition Alpha" || set.URL != "/search?q=s%3ALEA" {
		t.Errorf("set row = %+v", set)
	}
}

// A window is read once and served from the copy for the next few
// minutes; another window is its own read.
func TestSearchesDashboardCachesPerWindow(t *testing.T) {
	skipWithoutDatastore(t)
	t.Cleanup(func() { searchesCache.byWindow = map[int]searchesCacheEntry{} })

	store := &fakeRankStore{}
	ctx := context.Background()
	ds := currentDatastore()
	loadSearchesDashboard(ctx, ds, store, 30)
	loadSearchesDashboard(ctx, ds, store, 30)
	if store.calls != 1 || store.totalsCalls != 1 {
		t.Errorf("30-day window read %d times and totalled %d times, want 1 and 1", store.calls, store.totalsCalls)
	}
	loadSearchesDashboard(ctx, ds, store, 90)
	if store.calls != 2 {
		t.Errorf("a second window read %d times in all, want 2", store.calls)
	}
}

// A query that failed is not cached, so the next view asks again; once
// the store answers, that answer is kept.
func TestSearchesDashboardDoesNotCacheAFailedRead(t *testing.T) {
	skipWithoutDatastore(t)
	t.Cleanup(func() { searchesCache.byWindow = map[int]searchesCacheEntry{} })

	store := &fakeRankStore{err: errors.New("down")}
	ctx := context.Background()
	ds := currentDatastore()
	loadSearchesDashboard(ctx, ds, store, 30)
	if dash := loadSearchesDashboard(ctx, ds, store, 30); !dash.Failed {
		t.Error("a failed read is not marked as one")
	}
	if store.calls != 2 {
		t.Errorf("a failed window read %d times, want 2", store.calls)
	}
	store.err = nil
	loadSearchesDashboard(ctx, ds, store, 30)
	if dash := loadSearchesDashboard(ctx, ds, store, 30); dash.Failed {
		t.Error("a served read is marked as failed")
	}
	if store.calls != 3 {
		t.Errorf("after the store recovered, read %d times in all, want 3", store.calls)
	}
}

// A cache hit still shows the ranking published since, on a copy: what an
// earlier request was handed is never written to under it.
func TestSearchesDashboardRefreshesTheCarouselOnACopy(t *testing.T) {
	skipWithoutDatastore(t)
	t.Cleanup(func() { searchesCache.byWindow = map[int]searchesCacheEntry{} })
	t.Cleanup(func() { popularOrganicPtr.Store(nil) })
	popularOrganicPtr.Store(nil)

	store := &fakeRankStore{}
	ctx := context.Background()
	ds := currentDatastore()
	first := loadSearchesDashboard(ctx, ds, store, 30)
	if len(first.Carousel) != 0 {
		t.Fatalf("before a ranking: %d tiles", len(first.Carousel))
	}

	popularOrganicPtr.Store(&popularOrganic{At: time.Now().UTC(), Tiles: []PopularTile{{Key: "card:Black Lotus"}}})
	second := loadSearchesDashboard(ctx, ds, store, 30)
	if store.calls != 1 {
		t.Errorf("a cache hit read the store, %d calls", store.calls)
	}
	if len(second.Carousel) != 1 {
		t.Errorf("the hit shows %d tiles, want the 1 published since", len(second.Carousel))
	}
	if len(first.Carousel) != 0 || !first.RankedAt.IsZero() || first == second {
		t.Error("the first request's dashboard was written to")
	}
}

// The carousel section is the published ranking as the homepage shows it,
// and nothing before one is published.
func TestSearchesDashboardShowsTheCarouselSnapshot(t *testing.T) {
	skipWithoutDatastore(t)
	t.Cleanup(func() { searchesCache.byWindow = map[int]searchesCacheEntry{} })
	t.Cleanup(func() { popularOrganicPtr.Store(nil) })

	popularOrganicPtr.Store(nil)
	dash := loadSearchesDashboard(context.Background(), currentDatastore(), &fakeRankStore{}, 30)
	if len(dash.Carousel) != 0 || !dash.RankedAt.IsZero() {
		t.Fatalf("before a ranking: %d tiles, ranked at %v", len(dash.Carousel), dash.RankedAt)
	}

	searchesCache.byWindow = map[int]searchesCacheEntry{}
	at := time.Now().UTC().Truncate(time.Second)
	popularOrganicPtr.Store(&popularOrganic{At: at, Tiles: []PopularTile{{Key: "card:Black Lotus", Users: 3}}})
	dash = loadSearchesDashboard(context.Background(), currentDatastore(), &fakeRankStore{}, 30)
	if len(dash.Carousel) != 1 || dash.Carousel[0].Key != "card:Black Lotus" || !dash.RankedAt.Equal(at) {
		t.Errorf("after a ranking: %+v ranked at %v", dash.Carousel, dash.RankedAt)
	}
}

// The Searches panel is filled only when it is the tab being asked for,
// like the Usage panel, and lists the rows and the carousel it was given.
func TestAdminSearchesPanelOnlyOnItsOwnPage(t *testing.T) {
	at := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	dash := &SearchesDashboard{
		Instance: "magic", Window: 30, Windows: searchesWindows,
		Totals:   observability.SearchVoteTotals{Votes: 40, Users: 15, Keys: 3},
		Rows:     []SearchRow{{Rank: 1, Kind: "card", Query: "black lotus", Label: "Black Lotus", URL: "/search?q=Black+Lotus", Users: 12, RecentUsers: 4}},
		Dropped:  1,
		Carousel: []PopularTile{{PopularSearch: PopularSearch{Label: "Black Lotus", URL: "/search?q=Black+Lotus"}, Query: "black lotus", Users: 12, RecentUsers: 4}},
		RankedAt: at,
	}

	onSearches := renderAdminPage(t, PageVars{Page: "searches", AdminVars: AdminVars{SearchStats: dash}})
	// html/template writes a plus in an attribute as &#43;.
	for _, want := range []string{"Most searched", "On the carousel now", "40 votes from 15 users over 3 keys", "1 of 3 keys, 1 unresolved", `href="/search?q=Black&#43;Lotus"`, "black lotus", "ranked 2026-10-08 09:30 UTC", `href="?page=searches&amp;window=90"`} {
		if !strings.Contains(onSearches, want) {
			t.Errorf("the searches tab does not contain %q", want)
		}
	}
	if strings.Contains(onSearches, "did not answer") {
		t.Error("a served dashboard warns that the store did not answer")
	}
	// A failed read with no rows warns once; the empty row under the
	// warning does not call it a quiet week.
	dash.Failed, dash.Rows = true, nil
	failed := renderAdminPage(t, PageVars{Page: "searches", AdminVars: AdminVars{SearchStats: dash}})
	if !strings.Contains(failed, "The vote store did not answer") {
		t.Error("a failed read is not shown to the admin")
	}
	if strings.Contains(failed, "No votes in this window yet") {
		t.Error("the empty row under a failed read still reads as no votes")
	}

	onDashboard := renderAdminPage(t, PageVars{Page: "dashboard"})
	for _, absent := range []string{"Most searched", "Search votes are not enabled"} {
		if strings.Contains(onDashboard, absent) {
			t.Errorf("the dashboard tab still contains %q", absent)
		}
	}
	if !strings.Contains(onDashboard, "location.href='?page=searches'") {
		t.Error("the Searches tab does not navigate to ?page=searches")
	}
}
