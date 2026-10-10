package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/observability"
)

func TestFirstUnusedPopularCardSkipsDuplicateAndMissingArt(t *testing.T) {
	resolved := map[string]GenericCard{
		"duplicate": {UUID: "duplicate", ImageURL: "used.jpg"},
		"missing":   {UUID: "missing"},
		"unique":    {UUID: "unique", ImageURL: "unique.jpg"},
	}

	card, ok := firstUnusedPopularCard(
		[]string{"duplicate", "missing", "unique"},
		map[string]struct{}{"used.jpg": {}},
		func(id string) GenericCard { return resolved[id] },
	)
	if !ok {
		t.Fatal("firstUnusedPopularCard returned no card")
	}
	if card.UUID != "unique" {
		t.Fatalf("firstUnusedPopularCard chose %q, want unique", card.UUID)
	}
}

func TestFirstUnusedPopularCardReturnsFalseWhenAllArtIsUsed(t *testing.T) {
	card, ok := firstUnusedPopularCard(
		[]string{"one", "two"},
		map[string]struct{}{"same.jpg": {}},
		func(id string) GenericCard {
			return GenericCard{UUID: id, ImageURL: "same.jpg"}
		},
	)
	if ok {
		t.Fatalf("firstUnusedPopularCard returned %q for used art", card.UUID)
	}
}

func TestPopularKey(t *testing.T) {
	edition := func(negate bool, values ...string) FilterElem {
		return FilterElem{Name: "edition", Negate: negate, Values: values}
	}
	for _, tc := range []struct {
		name   string
		config SearchConfig
		top    GenericCard
		want   string
	}{
		{"card name", SearchConfig{CleanQuery: "black lotus"}, GenericCard{Name: "Black Lotus"}, "card:Black Lotus"},
		{"card name with filter", SearchConfig{CleanQuery: "black lotus", CardFilters: []FilterElem{edition(false, "LEA")}}, GenericCard{Name: "Black Lotus"}, "card:Black Lotus"},
		{"card name, no top", SearchConfig{CleanQuery: "zzz"}, GenericCard{}, ""},
		{"single edition", SearchConfig{CardFilters: []FilterElem{edition(false, "lea")}}, GenericCard{Name: "Balance"}, "set:LEA"},
		{"negated edition", SearchConfig{CardFilters: []FilterElem{edition(true, "LEA")}}, GenericCard{Name: "Balance"}, ""},
		{"two editions", SearchConfig{CardFilters: []FilterElem{edition(false, "LEA", "LEB")}}, GenericCard{Name: "Balance"}, ""},
		{"edition and rarity", SearchConfig{CardFilters: []FilterElem{edition(false, "LEA"), {Name: "rarity", Values: []string{"mythic"}}}}, GenericCard{Name: "Balance"}, ""},
		{"rarity only", SearchConfig{CardFilters: []FilterElem{{Name: "rarity", Values: []string{"mythic"}}}}, GenericCard{Name: "Balance"}, ""},
		{"empty", SearchConfig{}, GenericCard{}, ""},
	} {
		if got := popularKey(tc.config, tc.top); got != tc.want {
			t.Errorf("%s: popularKey = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPopularKeyShape(t *testing.T) {
	edition := func(negate bool, values ...string) FilterElem {
		return FilterElem{Name: "edition", Negate: negate, Values: values}
	}
	for _, tc := range []struct {
		name   string
		config SearchConfig
		want   bool
	}{
		{"card name", SearchConfig{CleanQuery: "black lotus"}, true},
		{"card name with filter", SearchConfig{CleanQuery: "black lotus", CardFilters: []FilterElem{edition(false, "LEA")}}, true},
		{"single edition", SearchConfig{CardFilters: []FilterElem{edition(false, "LEA")}}, true},
		{"negated edition", SearchConfig{CardFilters: []FilterElem{edition(true, "LEA")}}, false},
		{"two edition values", SearchConfig{CardFilters: []FilterElem{edition(false, "LEA", "LEB")}}, false},
		{"empty edition value", SearchConfig{CardFilters: []FilterElem{edition(false, "")}}, false},
		{"rarity only", SearchConfig{CardFilters: []FilterElem{{Name: "rarity", Values: []string{"mythic"}}}}, false},
		{"two filters", SearchConfig{CardFilters: []FilterElem{edition(false, "LEA"), {Name: "rarity", Values: []string{"mythic"}}}}, false},
		{"empty", SearchConfig{}, false},
	} {
		if got := popularKeyShape(tc.config); got != tc.want {
			t.Errorf("%s: popularKeyShape = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMergePopular(t *testing.T) {
	tile := func(n string) PopularSearch {
		return PopularSearch{Label: n, URL: "/search?q=" + n, ImageURL: n + ".jpg"}
	}
	curated := []PopularSearch{tile("c1"), tile("c2"), tile("c3"), tile("c4")}
	urls := func(in []PopularSearch) []string {
		var out []string
		for _, t := range in {
			out = append(out, t.Label)
		}
		return out
	}
	same := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// No organic: curated comes back unchanged, even above the floor.
	if got := mergePopular(nil, curated, 2); !same(urls(got), []string{"c1", "c2", "c3", "c4"}) {
		t.Fatalf("no organic: %v", urls(got))
	}
	// Organic first, curated pads to the floor in config order.
	got := mergePopular([]PopularSearch{tile("o1"), tile("o2")}, curated, 4)
	if !same(urls(got), []string{"o1", "o2", "c1", "c2"}) {
		t.Fatalf("pad to floor: %v", urls(got))
	}
	// A curated tile whose link or art an organic tile already has is skipped.
	dupURL := PopularSearch{Label: "o1 again", URL: "/search?q=o1", ImageURL: "x.jpg"}
	dupArt := PopularSearch{Label: "same art", URL: "/search?q=other", ImageURL: "o2.jpg"}
	got = mergePopular([]PopularSearch{tile("o1"), tile("o2")}, []PopularSearch{dupURL, dupArt, tile("c1")}, 3)
	if !same(urls(got), []string{"o1", "o2", "c1"}) {
		t.Fatalf("dedupe: %v", urls(got))
	}
	// A tile with no art does not block another artless tile.
	noArt := func(n string) PopularSearch { return PopularSearch{Label: n, URL: "/search?q=" + n} }
	got = mergePopular([]PopularSearch{noArt("o1")}, []PopularSearch{noArt("c1")}, 2)
	if !same(urls(got), []string{"o1", "c1"}) {
		t.Fatalf("no art: %v", urls(got))
	}
	// Organic above the floor is not cut.
	organic := []PopularSearch{tile("o1"), tile("o2"), tile("o3")}
	if got := mergePopular(organic, curated, 2); !same(urls(got), []string{"o1", "o2", "o3"}) {
		t.Fatalf("above floor: %v", urls(got))
	}
}

func TestPopularRankQuery(t *testing.T) {
	empty := &mtgmatcher.Backend{}
	search, link, label := popularRankQuery(empty, observability.SearchRank{Key: "card:Black Lotus"})
	if search != "Black Lotus" || link != "Black Lotus" || label != "Black Lotus" {
		t.Fatalf("card: %q %q %q", search, link, label)
	}
	// An unknown set keeps its code as the label.
	search, link, label = popularRankQuery(empty, observability.SearchRank{Key: "set:ZZZ"})
	if search != "s:ZZZ sort:retail" || link != "s:ZZZ" || label != "ZZZ" {
		t.Fatalf("set: %q %q %q", search, link, label)
	}
	if search, _, _ = popularRankQuery(empty, observability.SearchRank{Key: "weird:x"}); search != "" {
		t.Fatalf("unknown key resolved to %q", search)
	}
}

func TestPopularRankQueryNamesTheSet(t *testing.T) {
	skipWithoutDatastore(t)
	_, _, label := popularRankQuery(backend(), observability.SearchRank{Key: "set:LEA"})
	if label != "Limited Edition Alpha" {
		t.Fatalf("label = %q", label)
	}
}

// fakeRankStore serves a fixed ranking and records what the job asked for.
type fakeRankStore struct {
	ranks                   []observability.SearchRank
	err                     error
	instance, pruneInstance string
	since, recentSince      time.Time
	pruneBefore             time.Time

	// What the Searches tab asked for and is told.
	minUsers, limit    int
	calls, totalsCalls int
	totals             observability.SearchVoteTotals
}

func (f *fakeRankStore) TopSearches(_ context.Context, instance string, since, recentSince time.Time, minUsers, limit int) ([]observability.SearchRank, error) {
	f.instance, f.since, f.recentSince = instance, since, recentSince
	f.minUsers, f.limit = minUsers, limit
	f.calls++
	return f.ranks, f.err
}

func (f *fakeRankStore) SearchVoteTotals(_ context.Context, _ string, _ time.Time) (observability.SearchVoteTotals, error) {
	f.totalsCalls++
	return f.totals, f.err
}

func (f *fakeRankStore) PruneSearchVotes(_ context.Context, instance string, before time.Time) (int64, error) {
	f.pruneInstance, f.pruneBefore = instance, before
	return 0, nil
}

// rankSite is a site on the real datastore whose job reads store; the
// published ranking is cleared after the test.
func rankSite(t *testing.T, store *fakeRankStore) *site {
	t.Helper()
	skipWithoutDatastore(t)
	t.Cleanup(func() { popularOrganicPtr.Store(nil) })
	prevInstance := observabilityInstance
	observabilityInstance = "test-instance"
	t.Cleanup(func() { observabilityInstance = prevInstance })
	s := newSite()
	s.ds.Store(currentDatastore())
	s.popularRanks = store
	return s
}

func popularJobProblem(t *testing.T) string {
	t.Helper()
	for _, row := range backgroundJobs.Rows() {
		if row.Name == jobPopular {
			return row.Problem
		}
	}
	t.Fatal("no popular searches job row")
	return ""
}

func TestRefreshPopularSearchesPublishesInRankOrder(t *testing.T) {
	store := &fakeRankStore{ranks: []observability.SearchRank{
		{Key: "card:Black Lotus", Users: 5},
		{Key: "card:Lightning Bolt", Users: 4},
	}}
	s := rankSite(t, store)
	s.refreshPopularSearches()

	snap := popularOrganicSnapshot()
	if snap == nil || len(snap.Tiles) != 2 {
		t.Fatalf("snapshot = %+v, want two tiles", snap)
	}
	for i, want := range []PopularSearch{
		{Label: "Black Lotus", URL: "/search?q=Black+Lotus"},
		{Label: "Lightning Bolt", URL: "/search?q=Lightning+Bolt"},
	} {
		got := snap.Tiles[i]
		if got.Label != want.Label || got.URL != want.URL || got.ImageURL == "" {
			t.Errorf("tile %d = %+v, want %q at %q with art", i, got.PopularSearch, want.Label, want.URL)
		}
	}
	if store.instance != observabilityInstance || store.pruneInstance != observabilityInstance {
		t.Errorf("instance = %q, prune instance = %q, want %q", store.instance, store.pruneInstance, observabilityInstance)
	}
}

func TestRefreshPopularSearchesWindowsCountToday(t *testing.T) {
	store := &fakeRankStore{}
	s := rankSite(t, store)
	s.refreshPopularSearches()

	today := time.Now().UTC()
	day := func(tm time.Time) string { return tm.UTC().Format("2006-01-02") }
	// A window of N days is N dates, today included.
	if got, want := day(store.since), day(today.AddDate(0, 0, -(popularWindowDays-1))); got != want {
		t.Errorf("since = %s, want %s", got, want)
	}
	if got, want := day(store.recentSince), day(today.AddDate(0, 0, -(popularRecentDays-1))); got != want {
		t.Errorf("recentSince = %s, want %s", got, want)
	}
	if got, want := day(store.pruneBefore), day(today.AddDate(0, 0, -popularRetentionDays)); got != want {
		t.Errorf("prune before = %s, want %s", got, want)
	}
}

func TestRefreshPopularSearchesSkipsUnresolvedKeys(t *testing.T) {
	store := &fakeRankStore{ranks: []observability.SearchRank{
		{Key: "weird:x"},
		{Key: "card:zzzz no such card zzzz"},
		{Key: "card:Black Lotus"},
	}}
	s := rankSite(t, store)
	s.refreshPopularSearches()

	snap := popularOrganicSnapshot()
	if snap == nil || len(snap.Tiles) != 1 || snap.Tiles[0].Key != "card:Black Lotus" {
		t.Fatalf("snapshot = %+v, want only card:Black Lotus", snap)
	}
}

// A basic land's tile would search every one of its thousand printings, so
// it is left out; a set wider than that is a set tile, and stays.
func TestRefreshPopularSearchesSkipsBasicLands(t *testing.T) {
	store := &fakeRankStore{ranks: []observability.SearchRank{
		{Key: "card:Island", Users: 9},
		{Key: "card:Sol Ring", Users: 8},
		{Key: "set:MH3", Users: 7},
	}}
	s := rankSite(t, store)
	s.refreshPopularSearches()

	snap := popularOrganicSnapshot()
	var keys []string
	if snap != nil {
		for _, tile := range snap.Tiles {
			keys = append(keys, tile.Key)
		}
	}
	if !slices.Equal(keys, []string{"card:Sol Ring", "set:MH3"}) {
		t.Errorf("tiles = %q, want Sol Ring and MH3 without Island", keys)
	}
}

func TestRefreshPopularSearchesKeepsTheRankingOnError(t *testing.T) {
	store := &fakeRankStore{ranks: []observability.SearchRank{{Key: "card:Black Lotus"}}}
	s := rankSite(t, store)
	s.refreshPopularSearches()
	before := popularOrganicSnapshot()
	if before == nil {
		t.Fatal("no ranking published")
	}

	store.err = errors.New("db down")
	s.refreshPopularSearches()
	if after := popularOrganicSnapshot(); after != before {
		t.Fatalf("snapshot replaced on error: %p, was %p", after, before)
	}
	if p := popularJobProblem(t); !strings.Contains(p, "db down") {
		t.Errorf("problem = %q, want the store error", p)
	}
}

func TestRefreshPopularSearchesReportsNothingResolved(t *testing.T) {
	store := &fakeRankStore{ranks: []observability.SearchRank{
		{Key: "weird:x"},
		{Key: "card:zzzz no such card zzzz"},
	}}
	s := rankSite(t, store)
	s.refreshPopularSearches()

	if snap := popularOrganicSnapshot(); snap == nil || len(snap.Tiles) != 0 {
		t.Fatalf("snapshot = %+v, want an empty ranking", snap)
	}
	if p := popularJobProblem(t); p != "none of 2 ranked keys resolved" {
		t.Errorf("problem = %q", p)
	}
}
