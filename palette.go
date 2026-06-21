package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
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

	escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/api/palette/card/")
	if escaped == "" {
		json.NewEncoder(w).Encode(PaletteCardMetaResponse{Found: false})
		return
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	name := strings.ReplaceAll(decoded, "+", " ")

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
	paletteSetsCacheMu.RLock()
	data := paletteSetsCache
	paletteSetsCacheMu.RUnlock()
	// cache not warm - dont serve [] for an hour
	if len(data) == 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`[]`))
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
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
	for _, s := range GetSellers() {
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
	for _, v := range GetVendors() {
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

type PaletteNavTarget struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Group string `json:"group,omitempty"`
}

type PaletteArbitTargets struct {
	Filters []PaletteNavTarget `json:"filters"`
	Sorts   []PaletteNavTarget `json:"sorts"`
}

// paletteNewspaperTargetsJSON returns JSON for all newspaper page views.
func paletteNewspaperTargetsJSON() template.JS {
	out := []PaletteNavTarget{}
	titleCounts := map[string]int{}

	// First pass: count title occurrences so we know which need disambiguation.
	newspaperPages := GetNewspaperPages()
	for _, p := range newspaperPages {
		if p.Option == "" || p.Option == "options" {
			continue
		}
		titleCounts[p.Title]++
	}

	for _, p := range newspaperPages {
		if p.Option == "" || p.Option == "options" {
			continue
		}
		group := "Other"
		switch {
		case strings.Contains(p.Option, "spike"):
			group = "Spike Analysis"
		case strings.Contains(p.Option, "listings"):
			group = "Inventory Trends"
		case strings.Contains(p.Option, "buylist") || strings.Contains(p.Option, "ck_buy"):
			group = "Buylist Levels"
		case strings.Contains(p.Option, "stock"):
			group = "Stock Movement"
		}

		// Disambiguate duplicate titles by source.
		// TCG-sourced options:  greatest_*, *_buylist, *_listings
		// CK-sourced options:   buylist_*, stock_*, ck_buy*
		label := p.Title
		if titleCounts[p.Title] > 1 {
			label = label + " " + paletteNewspaperSourceSuffix(p.Option)
		}

		out = append(out, PaletteNavTarget{
			Value: p.Option,
			Label: label,
			Group: group,
		})
	}
	// Include Newspaper SubPages from the nav tree that aren't in NewspaperPages
	out = append(out, PaletteNavTarget{
		Value: "syp",
		Label: "TCG Syp List",
		Group: "Other",
	})
	data, _ := json.Marshal(out)
	return template.JS(data)
}

// paletteNewspaperSourceSuffix returns "(TCG)" or "(CK)" based on the option key.
// Falls back to "(<option>)" for novel keys so duplicates always render distinctly.
func paletteNewspaperSourceSuffix(option string) string {
	switch {
	case strings.HasPrefix(option, "greatest_"),
		strings.HasSuffix(option, "_buylist"),
		strings.HasSuffix(option, "_listings"):
		return "(TCG)"
	case strings.HasPrefix(option, "buylist_"),
		strings.HasPrefix(option, "stock_"),
		strings.HasPrefix(option, "ck_buy"):
		return "(CK)"
	default:
		return "(" + option + ")"
	}
}

func paletteSleepersTargetsJSON() template.JS {
	out := []PaletteNavTarget{
		{Value: "bulk", Label: "Bulk Me Up"},
		{Value: "reprint", Label: "Long Time No Reprint"},
		{Value: "mismatch", Label: "Market Mismatch"},
		{Value: "gap", Label: "Ocean Gap"},
		{Value: "hotlist", Label: "Highest Buylist Growth"},
	}
	data, _ := json.Marshal(out)
	return template.JS(data)
}

// paletteArbitTargetsJSON produces targets for /arbit. variant adjusts
// visibility: "reverse" hides ArbitOnly filters; "global" shows only those
// relevant to the global view.
func paletteArbitTargetsJSON(variant string) template.JS {
	out := PaletteArbitTargets{
		Filters: []PaletteNavTarget{},
		Sorts: []PaletteNavTarget{
			{Value: "profitability", Label: "Profitability"},
			{Value: "spread", Label: "Spread %"},
			{Value: "diff", Label: "Price Difference"},
			{Value: "available", Label: "Quantity"},
			{Value: "sell_price", Label: "Sell Price"},
			{Value: "buy_price", Label: "Buy Price"},
			{Value: "edition", Label: "Edition"},
			{Value: "alpha", Label: "Alphabetical"},
		},
	}
	for _, key := range FilterOptKeys {
		cfg, ok := FilterOptConfig[key]
		if !ok {
			continue
		}
		if variant == "global" && cfg.ArbitOnly {
			continue
		}
		out.Filters = append(out.Filters, PaletteNavTarget{
			Value: key,
			Label: cfg.Title,
		})
	}
	data, _ := json.Marshal(out)
	return template.JS(data)
}

type PaletteSealedMetaResponse struct {
	Name        string `json:"name"`
	Found       bool   `json:"found"`
	UUID        string `json:"uuid,omitempty"`
	SetCode     string `json:"setCode,omitempty"`
	HasContents bool   `json:"hasContents"`
	HasPicks    bool   `json:"hasPicks"`
}

// PaletteSealed reports availability of contents-mode and pack-pull-mode searches
// for a sealed product, used by the palette to gate action rows.
func PaletteSealed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/api/palette/sealed/")
	if escaped == "" {
		json.NewEncoder(w).Encode(PaletteSealedMetaResponse{Found: false})
		return
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	name := strings.ReplaceAll(decoded, "+", " ")

	resp := PaletteSealedMetaResponse{Name: name}

	// Direct UUID lookup first; fall back to name resolution via the sealed-name index.
	co, err := mtgmatcher.GetUUID(name)
	if err != nil || co == nil {
		co, err = mtgmatcher.GetUUID(sealedname2uuid(name))
		if err != nil || co == nil {
			json.NewEncoder(w).Encode(resp)
			return
		}
	}
	if !co.Sealed {
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp.Found = true
	resp.UUID = co.UUID
	resp.SetCode = co.SetCode

	// hasContents and hasPicks both check actual data availability via mtgmatcher;
	// a "found+sealed" product can still legitimately have neither (e.g., a Case that
	// contains other sealed products but no decklist of its own).
	if _, contentsErr := mtgmatcher.GetDecklist(co.SetCode, co.UUID); contentsErr == nil {
		resp.HasContents = true
	}
	if _, picksErr := mtgmatcher.GetPicksForSealed(co.SetCode, co.UUID); picksErr == nil {
		resp.HasPicks = true
	}

	json.NewEncoder(w).Encode(resp)
}
