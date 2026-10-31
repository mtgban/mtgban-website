package userstate

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// The backpacks come out named and ordered as js/backpack.js draws its
// tabs, each holding its live cards once.
func TestBackpacksFollowTheTabStrip(t *testing.T) {
	tabs := func(list string) json.RawMessage {
		raw, _ := json.Marshal(map[string]string{backpackTabsKey: list})
		return raw
	}
	cases := []struct {
		name  string
		pack  string
		prefs json.RawMessage
		want  string
	}{
		{"no tabs is backpack 1", `[{"id":"a"},{"id":"b","cond":"LP"},{"id":"a","cond":"MP"}]`, nil, `[Backpack 1:[a b]]`},
		{"nothing at all is backpack 1, empty", `[]`, nil, `[Backpack 1:[]]`},
		{"removed cards are gone", `[{"id":"a","del":5},{"id":"b","del":0}]`, nil, `[Backpack 1:[b]]`},
		{"tabs in strip order", `[{"id":"a"},{"id":"b","pack":2}]`, tabs(`[{"pack":2,"name":"Deck"},{"pack":1,"name":"Trade"}]`), `[Deck:[b] Trade:[a]]`},
		{"a tab without a name", `[{"id":"a","pack":"2"}]`, tabs(`[{"pack":1,"name":"Trade"},{"pack":2}]`), `[Trade:[] Backpack 2:[a]]`},
		{"a removed tab", `[{"id":"a"}]`, tabs(`[{"pack":1,"name":"Trade"},{"pack":2,"name":"Old","del":7}]`), `[Trade:[a]]`},
		{"only removed tabs is backpack 1", `[{"id":"a"}]`, tabs(`[{"pack":2,"name":"Old","del":7}]`), `[Backpack 1:[a]]`},
		{"cards the strip does not name", `[{"id":"a","pack":3},{"id":"b"}]`, tabs(`[{"pack":1,"name":"Trade"}]`), `[Trade:[b] Backpack 3:[a]]`},
		{"a strip that does not parse", `[{"id":"a"}]`, tabs(`[{`), `[Backpack 1:[a]]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := State{Backpack: json.RawMessage(tc.pack), Preferences: tc.prefs}
			var got []string
			for _, pack := range Backpacks(st) {
				got = append(got, fmt.Sprint(pack.Name, ":", pack.Cards))
			}
			if fmt.Sprint(got) != tc.want {
				t.Errorf("Backpacks = %v, want %s", got, tc.want)
			}
		})
	}
}

func TestBackpacksKeepsTheFirstTabForAPack(t *testing.T) {
	prefs, _ := json.Marshal(map[string]string{backpackTabsKey: `[{"pack":1,"name":"First"},{"pack":1,"name":"Second"}]`})
	got := Backpacks(State{Backpack: json.RawMessage(`[]`), Preferences: prefs})
	if len(got) != 1 || got[0].Name != "First" || !slices.Equal(got[0].Cards, nil) {
		t.Errorf("Backpacks = %+v, want one backpack named First", got)
	}
}
