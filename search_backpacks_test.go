package main

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"

	"github.com/mtgban/mtgban-website/userstate"
)

// on: names a backpack by its name, any case, without the quotes and commas
// a filter value cannot carry, or every backpack as on:backpack; the sealed
// tab keeps only its products.
func TestBackpackSearchFindsTheBackpacksCards(t *testing.T) {
	b := fixtureBackend("FX", "Fixture Edition", "2020-01-01", [][2]string{{"Fixture One", "1"}, {"Fixture Two", "2"}, {"Fixture Three", "3"}})
	b.UUIDs["FX-box"] = &matcher.CardObject{Card: matcher.Card{UUID: "FX-box", Name: "Fixture Box", SetCode: "FX"}, Sealed: true}
	s := newSite()
	s.ds.Store(s.newDatastore(b, time.Now()))
	ds := s.datastore()
	packs := backpackMembers([]userstate.Backpack{
		{Name: `My "Deck", v2`, Cards: []string{"FX-1", "FX-box"}},
		{Name: "Trade", Cards: []string{"FX-2"}},
		{Name: "Empty"},
	})

	cases := []struct {
		query  string
		sealed bool
		want   []string
	}{
		{`on:"my deck v2"`, false, []string{"FX-1", "FX-box"}},
		{`on:TRADE`, false, []string{"FX-2"}},
		{`on:"trade","My Deck v2"`, false, []string{"FX-1", "FX-2", "FX-box"}},
		{`on:backpack`, false, []string{"FX-1", "FX-2", "FX-box"}},
		{`on:"my deck v2"`, true, []string{"FX-box"}},
		{`in:(on:trade)`, false, []string{"FX-2"}},
		{`in:(on:backpack) -on:trade`, false, []string{"FX-1", "FX-box"}},
	}
	for _, tc := range cases {
		config := parseSearchPage(ds, tc.query, tc.sealed, false, nil, nil, nil)
		if tc.sealed {
			config.SearchMode = "sealed"
		}
		applyBackpacks(b, &config, packs)
		got, err := searchAndFilter(ds, config)
		slices.Sort(got)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s (sealed %v) = %v, %v; want %v", tc.query, tc.sealed, got, err, tc.want)
		}
	}

	// An empty backpack holds no cards, as an empty in: does.
	config := parseSearchPage(ds, "on:empty", false, false, nil, nil, nil)
	applyBackpacks(b, &config, packs)
	if _, err := searchAndFilter(ds, config); !errors.Is(err, errEmptyPool) {
		t.Errorf("on:empty = %v, want errEmptyPool", err)
	}
}

// A backpack named beside a list of the site's own keeps the cards of
// either; a name no backpack has stays the site's, and -on: leaves the
// backpack's cards out.
func TestBackpackFilterBesideOtherLists(t *testing.T) {
	packs := backpackMembers([]userstate.Backpack{{Name: "Trade", Cards: []string{"FX-2"}}})
	one := &matcher.CardObject{Card: matcher.Card{UUID: "FX-1"}}
	two := &matcher.CardObject{Card: matcher.Card{UUID: "FX-2"}}

	config := SearchConfig{CardFilters: []FilterElem{{Name: "on", Values: fixupOnNG("nosuch,trade")}}}
	applyBackpacks(nil, &config, packs)
	f := config.CardFilters[0]
	if f.Name != "on" || !slices.Equal(f.Values, []string{"nosuch"}) {
		t.Fatalf("on:nosuch,trade = %s %v, want on [nosuch]", f.Name, f.Values)
	}
	if shouldSkipCard(nil, two, config.CardFilters) || !shouldSkipCard(nil, one, config.CardFilters) {
		t.Error("on:nosuch,trade should keep the backpack's card alone")
	}

	config = SearchConfig{CardFilters: []FilterElem{{Name: "on", Negate: true, Values: fixupOnNG("trade")}}}
	applyBackpacks(nil, &config, packs)
	if !shouldSkipCard(nil, two, config.CardFilters) || shouldSkipCard(nil, one, config.CardFilters) {
		t.Error("-on:trade should leave the backpack's card out")
	}

	config = SearchConfig{CardFilters: []FilterElem{{Name: "on", Values: fixupOnNG("nosuch")}}}
	applyBackpacks(nil, &config, packs)
	if f := config.CardFilters[0]; f.Name != "on" || f.Members != nil {
		t.Errorf("on:nosuch = %s %v, want on with no members", f.Name, f.Members)
	}
}

// Two backpacks whose names read alike are one name to on:, which keeps
// the cards of both.
func TestBackpacksSharingAName(t *testing.T) {
	packs := backpackMembers([]userstate.Backpack{{Name: "Trade", Cards: []string{"a"}}, {Name: `"trade,"`, Cards: []string{"b"}}})
	if len(packs["trade"]) != 2 {
		t.Errorf("on:trade = %v, want both backpacks' cards", packs["trade"])
	}
}

// A backpack called "backpack" is that one, not all of them.
func TestBackpackNamedBackpack(t *testing.T) {
	packs := backpackMembers([]userstate.Backpack{{Name: "Backpack", Cards: []string{"a"}}, {Name: "Other", Cards: []string{"b"}}})
	if len(packs["backpack"]) != 1 || !packs["backpack"]["a"] {
		t.Errorf("on:backpack = %v, want the backpack called that", packs["backpack"])
	}
}
