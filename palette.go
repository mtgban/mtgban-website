package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type PaletteSet struct {
	Code     string   `json:"code"`
	Name     string   `json:"name"`
	Released string   `json:"released,omitempty"`
	Keyrune  string   `json:"keyrune,omitempty"`
	Rarities []string `json:"rarities,omitempty"`
	Colors   []string `json:"colors,omitempty"`
}

var (
	paletteSetsCache     []byte
	paletteSetsCacheMu   sync.RWMutex
	paletteStoresCacheMu sync.RWMutex
)

// buildPaletteSetsCache rebuilds the JSON-serialized sets cache from mtgmatcher.
// Called on datastore load.
func buildPaletteSetsCache() {
	sets := []PaletteSet{}
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil || set == nil {
			continue
		}
		entry := PaletteSet{
			Code:     set.Code,
			Name:     set.Name,
			Released: set.ReleaseDate,
			Keyrune:  strings.ToLower(set.KeyruneCode),
		}
		var rarities []string
		if len(set.Rarities) > 1 {
			rarities = make([]string, len(set.Rarities))
			copy(rarities, set.Rarities)
			sort.Strings(rarities)
		}
		entry.Rarities = rarities
		var colors []string
		if len(set.Colors) > 1 {
			colors = make([]string, len(set.Colors))
			copy(colors, set.Colors)
			sort.Strings(colors)
		}
		entry.Colors = colors
		sets = append(sets, entry)
	}
	sort.Slice(sets, func(i, j int) bool {
		if sets[i].Released != sets[j].Released {
			return sets[i].Released > sets[j].Released
		}
		return sets[i].Code < sets[j].Code
	})
	data, err := json.Marshal(sets)
	if err != nil {
		return
	}
	paletteSetsCacheMu.Lock()
	paletteSetsCache = data
	paletteSetsCacheMu.Unlock()
}

// PaletteCardMeta returns metadata (printings, rarities, colors, types)
// for a card name, used by the chip-based filter builder.
func PaletteCardMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write([]byte(`{"error":"not implemented"}`))
}

// PaletteSets returns all known set codes with display metadata.
func PaletteSets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	paletteSetsCacheMu.RLock()
	data := paletteSetsCache
	paletteSetsCacheMu.RUnlock()
	if data == nil {
		w.Write([]byte(`[]`))
		return
	}
	w.Write(data)
}

// PaletteStores returns seller and vendor shorthand lists.
func PaletteStores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Write([]byte(`{"sellers":[],"vendors":[]}`))
}
