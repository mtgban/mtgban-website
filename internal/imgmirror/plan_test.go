package imgmirror

import (
	"reflect"
	"testing"
)

func planFixture() (State, map[string]Card) {
	state := State{
		"uuid-done":    {Digest: "d1", Source: "https://cards.scryfall.io/a.jpg"},
		"uuid-moved":   {Digest: "d2", Source: "https://cards.scryfall.io/old.jpg"},
		"uuid-orphan":  {Digest: "d9", Source: "https://cards.scryfall.io/z.jpg"},
	}
	want := map[string]Card{
		"uuid-done":  {URL: "https://cards.scryfall.io/a.jpg", SetCode: "NEO"},
		"uuid-moved": {URL: "https://cards.scryfall.io/new.jpg", SetCode: "NEO"},
		"uuid-new":   {URL: "https://cards.scryfall.io/b.jpg", SetCode: "NEO"},
		"uuid-slx":   {URL: "https://product-images.tcgplayer.com/1.jpg", SetCode: "SLX", Sealed: true},
	}
	return state, want
}

func TestNeedFetch(t *testing.T) {
	state, want := planFixture()
	got := NeedFetch(state, want)
	wantIDs := []string{"uuid-moved", "uuid-new", "uuid-slx"}
	if !reflect.DeepEqual(got, wantIDs) {
		t.Errorf("NeedFetch = %v, want %v", got, wantIDs)
	}
}

func TestSetDigestsSkipsUnfetched(t *testing.T) {
	state, want := planFixture()
	got := SetDigests(state, want)
	wantMap := map[string]map[string]string{
		"NEO": {"uuid-done": "d1", "uuid-moved": "d2"},
	}
	if !reflect.DeepEqual(got, wantMap) {
		t.Errorf("SetDigests = %v, want %v", got, wantMap)
	}
}

func TestBundlesToRebuild(t *testing.T) {
	digests := map[string]map[string]string{
		"NEO": {"uuid-a": "d1"},
		"MID": {"uuid-b": "d2"},
		"VOW": {"uuid-c": "d3"},
	}
	m := Manifest{
		"NEO": {Hash: BundleHash(digests["NEO"]), Count: 1, Bytes: 10},
		"MID": {Hash: "stale", Count: 1, Bytes: 10},
	}
	got := BundlesToRebuild(m, digests)
	want := []string{"MID", "VOW"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BundlesToRebuild = %v, want %v", got, want)
	}
}

func TestDomains(t *testing.T) {
	_, want := planFixture()
	got := Domains(want)
	wantMap := map[string]int{
		"cards.scryfall.io":            3,
		"product-images.tcgplayer.com": 1,
	}
	if !reflect.DeepEqual(got, wantMap) {
		t.Errorf("Domains = %v, want %v", got, wantMap)
	}
}
