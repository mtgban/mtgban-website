package main

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

func TestFoldDirectKeyLandsOnTheFinish(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	// A card the datastore prints in both finishes.
	nonfoil, err := b.Match(&mtgmatcher.InputCard{Name: "Lightning Bolt", Edition: "Magic 2010"})
	if err != nil {
		t.Fatal(err)
	}
	foil, err := b.Match(&mtgmatcher.InputCard{Name: "Lightning Bolt", Edition: "Magic 2010", Foil: true})
	if err != nil {
		t.Fatal(err)
	}
	base := timeseries.NormalizeUUID(nonfoil)

	if got, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: base}); !ok || got != nonfoil {
		t.Errorf("nonfoil: %q %v, want %q", got, ok, nonfoil)
	}
	if got, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: base, IsFoil: true}); !ok || got != foil {
		t.Errorf("foil: %q %v, want %q", got, ok, foil)
	}
	if _, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: base, IsEtched: true}); ok {
		t.Error("an etched printing the datastore lacks was kept")
	}
	if _, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: "not-a-uuid"}); ok {
		t.Error("an unknown uuid was kept")
	}
}

// firstSingleFinish finds the first printing, in id order, sold only in the
// finish want picks: its bare uuid is that finish, with no sibling.
func firstSingleFinish(b *mtgmatcher.Backend, want func(co *mtgmatcher.CardObject) bool) (string, bool) {
	var found string
	for id, co := range b.UUIDs {
		if len(id) != 36 || co.Sealed || !want(co) {
			continue
		}
		if found == "" || id < found {
			found = id
		}
	}
	return found, found != ""
}

func TestFoldDirectKeySingleFinishPrintings(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()

	foilOnly, ok := firstSingleFinish(b, func(co *mtgmatcher.CardObject) bool { return co.Foil && !co.Etched })
	if !ok {
		t.Fatal("no foil-only printing in the datastore")
	}
	if got, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: foilOnly, IsFoil: true}); !ok || got != foilOnly {
		t.Errorf("foil-only %s: %q %v, want its bare id", foilOnly, got, ok)
	}
	if _, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: foilOnly}); ok {
		t.Errorf("foil-only %s: a nonfoil key was kept", foilOnly)
	}

	etchedOnly, ok := firstSingleFinish(b, func(co *mtgmatcher.CardObject) bool { return co.Etched })
	if !ok {
		t.Skip("no etched-only printing in the datastore")
	}
	if got, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: etchedOnly, IsEtched: true}); !ok || got != etchedOnly {
		t.Errorf("etched-only %s: %q %v, want its bare id", etchedOnly, got, ok)
	}
	if _, ok := foldDirectKey(b, timeseries.AggregatePriceKey{MtgjsonUUID: etchedOnly}); ok {
		t.Errorf("etched-only %s: a nonfoil key was kept", etchedOnly)
	}
}

func TestDirectHistoryReport(t *testing.T) {
	if got := directHistoryResult(nil); got != "" {
		t.Errorf("no snapshot: %q", got)
	}
	empty := &directHistory{Prices: map[string]float64{}}
	if got := directHistoryProblem(empty); got != "no Direct prices in the window" {
		t.Errorf("empty problem: %q", got)
	}
	one := &directHistory{Prices: map[string]float64{"a": 1}}
	if got := directHistoryResult(one); got != "1 cards over 7 days" {
		t.Errorf("result: %q", got)
	}
	if got := directHistoryProblem(one); got != "" {
		t.Errorf("problem: %q", got)
	}
}

func TestBuildDirectHistoryAppliesTheFloor(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	bolt, err := b.Match(&mtgmatcher.InputCard{Name: "Lightning Bolt", Edition: "Magic 2010"})
	if err != nil {
		t.Fatal(err)
	}
	growth, err := b.Match(&mtgmatcher.InputCard{Name: "Giant Growth", Edition: "Magic 2010"})
	if err != nil {
		t.Fatal(err)
	}
	averages := map[timeseries.AggregatePriceKey]timeseries.WindowAverage{
		{MtgjsonUUID: timeseries.NormalizeUUID(bolt)}:   {Average: 2.5, Samples: 3},
		{MtgjsonUUID: timeseries.NormalizeUUID(growth)}: {Average: 0.3, Samples: 1},
		{MtgjsonUUID: "not-a-uuid"}:                     {Average: 9, Samples: 9},
	}
	h := buildDirectHistory(b, averages, 2)
	if got, ok := h.Prices[bolt]; !ok || got != 2.5 {
		t.Errorf("bolt: %v %v", got, ok)
	}
	if _, ok := h.Prices[growth]; ok {
		t.Error("one sample kept past a floor of 2")
	}
	if len(h.Prices) != 1 {
		t.Errorf("entries: %d", len(h.Prices))
	}
	h = buildDirectHistory(b, averages, 1)
	if _, ok := h.Prices[growth]; !ok {
		t.Error("one sample dropped at a floor of 1")
	}
}

func TestDirectHistoryForMissesWithNoSnapshot(t *testing.T) {
	prev := directHistoryPtr.Load()
	t.Cleanup(func() { directHistoryPtr.Store(prev) })
	directHistoryPtr.Store(nil)
	if _, ok := directHistoryFor("anything"); ok {
		t.Error("a lookup hit with no snapshot")
	}
	directHistoryPtr.Store(&directHistory{Prices: map[string]float64{"a": 1.5}, Loaded: time.Now()})
	if got, ok := directHistoryFor("a"); !ok || got != 1.5 {
		t.Errorf("lookup: %v %v", got, ok)
	}
}

func TestLoadDirectHistoryNeedsTheArchive(t *testing.T) {
	prev := directHistoryPtr.Load()
	t.Cleanup(func() { directHistoryPtr.Store(prev) })
	directHistoryPtr.Store(nil)
	saved := PricesArchiveDB
	PricesArchiveDB = nil
	t.Cleanup(func() { PricesArchiveDB = saved })
	newSite().loadDirectHistory()
	if directHistoryPtr.Load() != nil {
		t.Error("a snapshot was published with no archive")
	}
}
