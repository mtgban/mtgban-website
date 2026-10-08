package main

import "testing"

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
