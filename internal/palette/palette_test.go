package palette

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestRarityListFollowsTheGame pins the rarity list: the game's order, only
// what a printing carries, each labelled as its datastore published it, and
// a letter only where it names that rarity alone.
func TestRarityListFollowsTheGame(t *testing.T) {
	b := mtgmatcher.NewBackend()
	for uuid, rarity := range map[string]string{
		"a": "Super Rare", "b": "Super Rare", "c": "special", "d": "Legend Rare", "e": "Common",
	} {
		co := &mtgmatcher.CardObject{}
		co.UUID = uuid
		co.Rarity = b.AddRarity(rarity)
		b.UUIDs[uuid] = co
		b.AllUUIDs = append(b.AllUUIDs, uuid)
	}
	slices.Sort(b.AllUUIDs)
	b.Rarities = mtgmatcher.RarityNames([]string{"Special", "Legend Rare", "Super Rare", "Rare", "Common"})

	got := RarityList(b)
	want := []Rarity{
		{Value: "special", Label: "Special", Count: 1},
		{Value: "legendrare", Label: "Legend Rare", Letter: "l", Count: 1},
		{Value: "superrare", Label: "Super Rare", Count: 2},
		{Value: "common", Label: "Common", Letter: "c", Count: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("RarityList =\n %+v\nwant\n %+v", got, want)
	}
}

// TestColorListFollowsTheGame pins the colour list: the colours the sets
// list, in the game's order rather than the sets', any the order leaves out
// after it by name, and colorless and multicolor last.
func TestColorListFollowsTheGame(t *testing.T) {
	b := &mtgmatcher.Backend{Sets: map[string]*mtgmatcher.Set{
		"AAA": {Code: "AAA", Colors: []string{"mind", "fury", "colorless"}},
		"BBB": {Code: "BBB", Colors: []string{"order", "calm", "fury", "spirit", "multicolor"}},
		"CCC": {Code: "CCC"},
	}}
	b.AllSets = []string{"AAA", "BBB", "CCC"}
	b.Colors = []string{"fury", "calm", "mind", "body", "chaos", "order", "colorless"}

	var got []string
	for _, color := range ColorList(b) {
		got = append(got, color.Value+"="+color.Label)
	}
	want := []string{"fury=Fury", "calm=Calm", "mind=Mind", "order=Order", "spirit=Spirit", "colorless=Colorless", "multicolor=Multicolor"}
	if !slices.Equal(got, want) {
		t.Errorf("ColorList = %v, want %v", got, want)
	}
}

func TestSetMark(t *testing.T) {
	for _, tc := range []struct{ code, name, want string }{
		{"PTHB", "Theros Beyond Death Promos", "★"},
		{"THB", "Theros Beyond Death", ""},
		{"FBB", "Foreign Black Border", "BB"},
		{"4BB", "Fourth Edition Foreign Black Border", "BB"},
		{"LEGITA", "Legends Italian", "ITA"},
		{"4EDALT", "Alternate Fourth Edition", "ALT"},
		{"CED", "Collectors' Edition", "CED"},
		{"CEI", "Intl. Collectors' Edition", "CEI"},
		{"CMB1", "Mystery Booster Playtest Cards 2019", "2019"},
		{"CMB2", "Mystery Booster Playtest Cards 2021", "2021"},
		{"PUMA", "Ultimate Box Topper", "⬒"},
		{"H1R", "Modern Horizons 1 Timeshifts", "⧗"},
		{"H2R", "Modern Horizons 2 Timeshifts", "⧗"},
		{"OC13", "Commander 2013 Oversized", "O"},
		{"OAFC", "Forgotten Realms Commander Display Commanders", "O"},
		{"PTC", "Pro Tour Collector Set", "1996"},
		{"WC97", "World Championship Decks 1997", "1997"},
		{"WC00", "World Championship Decks 2000", "2000"},
		{"EVG", "Duel Decks Anthology: Elves vs. Goblins", "A"},
		{"TGVL", "Duel Decks Anthology: Garruk vs. Liliana Tokens", "A"},
		{"DD1", "Duel Decks: Elves vs. Goblins", ""},
		{"SLD", "Secret Lair Drop", ""},
		{"SLX", "Universes Within", "◎"},
		{"SLU", "Secret Lair: Ultimate Edition", "Ω"},
		{"J14", "Judge Gift Cards 2014", "owl"},
		{"PW24", "Wizards Play Network 2024", "WPN"},
		{"PF31", "MagicFest 2031", "⚑"},
		{"PL25", "Year of the Snake 2025", "✿"},
		{"PLNY", "Lunar New Year 2018", "✿"},
		{"PRCQ", "Regional Championship Qualifiers 2022", "♜"},
		{"PSS4", "MKM Standard Showdown", "✕"},
		{"UGIN", "Ugin's Fate", "⬢"},
		{"PXTC", "XLN Treasure Chest", "▣"},
		{"PCMD", "Commander 2011 Launch Party", "★"},
		{"MGB", "Multiverse Gift Box", "❖"},
		{"TGK1", "GRN Guild Kit Tokens", "⌂"},
		{"PS14", "San Diego Comic-Con 2014", "✎"},
		{"PS18", "San Diego Comic-Con 2018", "✎"},
		{"PROMOS", "Promos of Theros", ""},
	} {
		got := SetMark(tc.code, tc.name)
		if got != tc.want {
			t.Errorf("SetMark(%q, %q) = %q, want %q", tc.code, tc.name, got, tc.want)
		}
	}
}

// TestSealedOffersPicksOnlyWhereAnOpeningHoldsCards pins hasPicks: a product
// whose contents open to nothing, as one listing no contents does, offers no
// pack pull, while one holding a booster does.
func TestSealedOffersPicksOnlyWhereAnOpeningHoldsCards(t *testing.T) {
	b := mtgmatcher.NewBackend()
	b.UUIDs["c1"] = &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: "c1", SetCode: "AAA"}}
	// Decoded the way a datastore is, so a field added upstream does not
	// break the test.
	var booster mtgmatcher.Booster
	err := json.Unmarshal([]byte(`{
		"boosters": [{"contents": {"common": 1}, "weight": 1}],
		"boostersTotalWeight": 1,
		"sheets": {"common": {"cards": {"c1": 1}, "totalWeight": 1}}
	}`), &booster)
	if err != nil {
		t.Fatal(err)
	}
	set := &mtgmatcher.Set{Code: "AAA", Booster: map[string]mtgmatcher.Booster{"draft": booster}}
	set.SealedProduct = []mtgmatcher.SealedProduct{
		{UUID: "empty", Name: "Empty"},
		{UUID: "pack", Name: "Pack", Contents: map[string][]mtgmatcher.SealedContent{
			"pack": {{Set: "aaa", Code: "draft"}},
		}},
	}
	for _, product := range set.SealedProduct {
		b.UUIDs[product.UUID] = &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: product.UUID, SetCode: "AAA"}, Sealed: true}
	}
	b.Sets = map[string]*mtgmatcher.Set{"AAA": set}
	s := &Service{Backend: func() *mtgmatcher.Backend { return b }}

	for uuid, want := range map[string]bool{"empty": false, "pack": true} {
		w := httptest.NewRecorder()
		s.Sealed(w, httptest.NewRequest(http.MethodGet, "/api/palette/sealed/"+uuid, nil))
		var resp SealedMetaResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Found || resp.HasPicks != want {
			t.Errorf("%s: found %v, hasPicks %v, want found and hasPicks %v", uuid, resp.Found, resp.HasPicks, want)
		}
	}
}
