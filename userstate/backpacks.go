package userstate

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// backpackTabsKey is the preference js/backpack.js keeps its tab strip in,
// a JSON list of {pack, name, del} stored as a string.
const backpackTabsKey = "mtgban_backpack_tabs"

// Backpack is one of a reader's backpacks: its name as the tab strip shows
// it, and the ids of the cards it holds, each once.
type Backpack struct {
	Name  string
	Cards []string
}

// Backpacks returns st's backpacks in strip order, named as js/backpack.js
// names its tabs: the synced strip, backpack 1 alone when there is none,
// then any backpack holding cards the strip does not name, "Backpack N"
// wherever a tab has no name.
func Backpacks(st State) []Backpack {
	var entries []struct {
		ID   string `json:"id"`
		Del  any    `json:"del"`
		Pack any    `json:"pack"`
	}
	// A list that does not parse is empty, as js/list-storage.js reads it.
	err := json.Unmarshal(st.Backpack, &entries)
	if err != nil {
		entries = nil
	}
	cards := map[int][]string{}
	for _, e := range entries {
		if e.ID == "" || !isLive(e.Del) {
			continue
		}
		p := backpackPack(e.Pack)
		if !slices.Contains(cards[p], e.ID) {
			cards[p] = append(cards[p], e.ID)
		}
	}

	var prefs map[string]any
	var tabs []struct {
		Name string `json:"name"`
		Del  any    `json:"del"`
		Pack any    `json:"pack"`
	}
	err = json.Unmarshal(st.Preferences, &prefs)
	raw, isString := prefs[backpackTabsKey].(string)
	if err == nil && isString {
		err = json.Unmarshal([]byte(raw), &tabs)
		if err != nil {
			tabs = nil
		}
	}

	var out []Backpack
	named := map[int]bool{}
	for _, t := range tabs {
		p := backpackPack(t.Pack)
		if !isLive(t.Del) || named[p] {
			continue
		}
		named[p] = true
		name := t.Name
		if name == "" {
			name = fmt.Sprint("Backpack ", p)
		}
		out = append(out, Backpack{Name: name, Cards: cards[p]})
	}
	if len(out) == 0 {
		named[1] = true
		out = append(out, Backpack{Name: "Backpack 1", Cards: cards[1]})
	}
	for _, p := range slices.Sorted(maps.Keys(cards)) {
		if !named[p] {
			out = append(out, Backpack{Name: fmt.Sprint("Backpack ", p), Cards: cards[p]})
		}
	}
	return out
}

// isLive says an entry's del stamp is unset, as js/list-storage.js reads a
// falsy one.
func isLive(del any) bool {
	return del == nil || del == false || del == 0.0 || del == ""
}
