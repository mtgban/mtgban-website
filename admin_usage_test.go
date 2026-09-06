package main

import (
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// The sub-view table used to come back from its own query: the TopPages one
// with `AND (path LIKE 'newspaper/%' OR path LIKE 'sleepers/%')` bolted on.
// These cases pin the Go filter to the rows that SQL selected, the trailing
// slash included - `LIKE 'newspaper/%'` never matched a bare "newspaper".
func TestSubViewsOfSelectsWhatTheQueryDid(t *testing.T) {
	all := []observability.PathAgg{
		{Path: "search", Hits: 1130017, Uniques: 173},
		{Path: "sleepers/mismatch", Hits: 1207, Uniques: 26},
		{Path: "sets", Hits: 893, Uniques: 49},
		{Path: "newspaper/index", Hits: 700, Uniques: 54},
		{Path: "newspaper", Hits: 400, Uniques: 12},
		{Path: "sleepers", Hits: 300, Uniques: 9},
		{Path: "admin", Hits: 215, Uniques: 4},
		{Path: "newspaper/syp", Hits: 21, Uniques: 11},
	}

	want := []observability.PathAgg{
		{Path: "sleepers/mismatch", Hits: 1207, Uniques: 26},
		{Path: "newspaper/index", Hits: 700, Uniques: 54},
		{Path: "newspaper/syp", Hits: 21, Uniques: 11},
	}

	got := subViewsOf(all)
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TopPages orders by hits and the filter keeps that order, so the sub-view
// table stays sorted without a second sort.
func TestSubViewsOfKeepsInputOrder(t *testing.T) {
	all := []observability.PathAgg{
		{Path: "newspaper/a", Hits: 30},
		{Path: "search", Hits: 25},
		{Path: "sleepers/b", Hits: 20},
		{Path: "newspaper/c", Hits: 10},
	}

	got := subViewsOf(all)
	for i := 1; i < len(got); i++ {
		if got[i-1].Hits < got[i].Hits {
			t.Errorf("order broken at %d: %v before %v", i, got[i-1], got[i])
		}
	}
}

func TestSubViewsOfEmptyInput(t *testing.T) {
	if got := subViewsOf(nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := subViewsOf([]observability.PathAgg{{Path: "search"}}); got != nil {
		t.Errorf("got %v, want nil when nothing matches", got)
	}
}
