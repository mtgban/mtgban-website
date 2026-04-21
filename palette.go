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

type PaletteCardMetaResponse struct {
	Name      string   `json:"name"`
	Found     bool     `json:"found"`
	Printings []string `json:"printings,omitempty"`
	Rarities  []string `json:"rarities,omitempty"`
	Colors    []string `json:"colors,omitempty"`
	Types     []string `json:"types,omitempty"`
}

// PaletteCardMeta returns metadata (printings, rarities, colors, types)
// for a card name, used by the chip-based filter builder.
func PaletteCardMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	name := strings.TrimPrefix(r.URL.Path, "/api/palette/card/")
	if name == "" {
		json.NewEncoder(w).Encode(PaletteCardMetaResponse{Found: false})
		return
	}
	// Handle legacy `+` -> space encoding from some clients.
	name = strings.ReplaceAll(name, "+", " ")

	resp := PaletteCardMetaResponse{Name: name}

	printings, err := mtgmatcher.Printings4Card(name)
	if err != nil || len(printings) == 0 {
		json.NewEncoder(w).Encode(resp)
		return
	}
	resp.Found = true
	resp.Printings = printings

	rarityMap := map[string]bool{}
	colorMap := map[string]bool{}
	typeMap := map[string]bool{}
	uuids, _ := mtgmatcher.SearchEquals(name)
	for _, uuid := range uuids {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if co.Rarity != "" {
			rarityMap[strings.ToLower(co.Rarity)] = true
		}
		for _, c := range co.Colors {
			colorMap[c] = true
		}
		for _, t := range co.Supertypes {
			typeMap[t] = true
		}
		for _, t := range co.Types {
			typeMap[t] = true
		}
	}
	for rarity := range rarityMap {
		resp.Rarities = append(resp.Rarities, rarity)
	}
	for c := range colorMap {
		resp.Colors = append(resp.Colors, c)
	}
	for t := range typeMap {
		resp.Types = append(resp.Types, t)
	}
	sort.Strings(resp.Rarities)
	sort.Strings(resp.Colors)
	sort.Strings(resp.Types)

	json.NewEncoder(w).Encode(resp)
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

type PaletteStore struct {
	Shorthand string `json:"shorthand"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Sealed    bool   `json:"sealed,omitempty"`
}

type PaletteStoresResponse struct {
	Sellers []PaletteStore `json:"sellers"`
	Vendors []PaletteStore `json:"vendors"`
}

// PaletteStores returns seller and vendor shorthand lists.
func PaletteStores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=600")

	out := PaletteStoresResponse{
		Sellers: []PaletteStore{},
		Vendors: []PaletteStore{},
	}
	seen := map[string]bool{}
	for _, s := range Sellers {
		if s == nil {
			continue
		}
		info := s.Info()
		if seen["s:"+info.Shorthand] {
			continue
		}
		seen["s:"+info.Shorthand] = true
		out.Sellers = append(out.Sellers, PaletteStore{
			Shorthand: info.Shorthand,
			Name:      info.Name,
			Country:   info.CountryFlag,
			Sealed:    info.SealedMode,
		})
	}
	seen = map[string]bool{}
	for _, v := range Vendors {
		if v == nil {
			continue
		}
		info := v.Info()
		if seen["v:"+info.Shorthand] {
			continue
		}
		seen["v:"+info.Shorthand] = true
		out.Vendors = append(out.Vendors, PaletteStore{
			Shorthand: info.Shorthand,
			Name:      info.Name,
			Country:   info.CountryFlag,
			Sealed:    info.SealedMode,
		})
	}
	sort.Slice(out.Sellers, func(i, j int) bool { return out.Sellers[i].Shorthand < out.Sellers[j].Shorthand })
	sort.Slice(out.Vendors, func(i, j int) bool { return out.Vendors[i].Shorthand < out.Vendors[j].Shorthand })

	json.NewEncoder(w).Encode(out)
}
