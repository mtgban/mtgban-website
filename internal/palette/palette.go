// Package palette serves the command-palette data endpoints and nav-target
// lists: set/store/card/sealed metadata the palette's filter builder and
// jump actions are built from.
package palette

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// NewspaperPage is the slice of a newspaper page the palette needs to build
// a jump target.
type NewspaperPage struct {
	Title  string
	Option string
}

// ArbitFilter is one arbitrage filter option offered as a palette target.
type ArbitFilter struct {
	Key       string
	Title     string
	ArbitOnly bool
}

// Service exposes the palette endpoints, wired to the host's live scraper
// and page registries via callbacks so it always reflects current state.
type Service struct {
	// Backend returns the current card datastore.
	Backend func() *mtgmatcher.Backend
	// Sellers and Vendors return the live scraper lists for the stores
	// endpoint.
	Sellers func() []mtgban.Seller
	Vendors func() []mtgban.Vendor

	// NewspaperPages returns the newspaper views offered as jump targets.
	NewspaperPages func() []NewspaperPage

	// ArbitFilters returns the arbitrage filter options, in display order.
	ArbitFilters func() []ArbitFilter

	// PromoAliases returns the shorthands a promo type also answers to, so
	// the endpoint can offer them beside the type itself.
	PromoAliases func() map[string]string

	// FinishLabel spells a finish name the way a person writes it, since the
	// matcher stores one as a single lowercase word. Called with the backend
	// being listed, which during a pre-publish build is not yet the live one.
	FinishLabel func(b *mtgmatcher.Backend, finish string) string

	// FinishNames are the names the finish filter reaches a printing by, so
	// the list offers what f: accepts and nothing else.
	FinishNames func(*mtgmatcher.CardObject) []string

	// Snapshot returns the sets, promos and finishes lists built alongside
	// the datastore currently served, nil before the first load.
	Snapshot func() *Snapshot
}

func (s *Service) backend() *mtgmatcher.Backend {
	if s.Backend != nil {
		if backend := s.Backend(); backend != nil {
			return backend
		}
	}
	return &mtgmatcher.Backend{}
}

// Set is one edition as the frontend palette lists it.
type Set struct {
	Code     string   `json:"code"`
	Name     string   `json:"name"`
	Released string   `json:"released,omitempty"`
	Keyrune  string   `json:"keyrune,omitempty"`
	Rarities []string `json:"rarities,omitempty"`
	Colors   []string `json:"colors,omitempty"`
}

// Snapshot is the sets, promo and finish lists the palette serves, built
// from one datastore alongside it.
type Snapshot struct {
	sets, promos, finishes []byte
}

// NewSnapshot builds the lists from b.
func (s *Service) NewSnapshot(b *mtgmatcher.Backend) *Snapshot {
	return &Snapshot{
		sets:     s.buildSets(b),
		promos:   s.buildPromos(b),
		finishes: s.buildFinishes(b),
	}
}

// buildSets is the JSON-serialized sets list, built from b. A marshal error
// leaves it nil, same as the unbuilt list before the first load.
func (s *Service) buildSets(b *mtgmatcher.Backend) []byte {
	sets := []Set{}
	for _, code := range b.GetAllSets() {
		set, err := b.GetSet(code)
		if err != nil || set == nil {
			continue
		}
		entry := Set{
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
		return nil
	}
	return data
}

// Promo is a promo type as the palette and the guide offer it: the token an
// "is:" query carries, the words a reader is shown, and how much of the game
// wears it.
type Promo struct {
	Value   string   `json:"value"`
	Label   string   `json:"label"`
	Count   int      `json:"count"`
	Aliases []string `json:"aliases,omitempty"`
}

// buildPromos is the promo type list, built from the game b holds.
//
// The list is the loaded game's own: Magic answers with its 129 types,
// Riftbound with 10, One Piece with 464. Nothing here knows which game it is
// serving, which is the point - the guide and the palette can offer what the
// datastore actually holds instead of a table written for one game.
func (s *Service) buildPromos(b *mtgmatcher.Backend) []byte {
	// One pass over the printings, rather than a scan per type: with a few
	// hundred types and a few thousand printings the difference is real.
	counts := map[string]int{}
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		for _, promoType := range co.PromoTypes {
			counts[promoType]++
		}
	}

	var aliases map[string]string
	if s.PromoAliases != nil {
		aliases = s.PromoAliases()
	}

	promos := []Promo{}
	for _, promoType := range b.AllPromoTypes {
		entry := Promo{
			Value: promoType,
			Label: b.PromoTypeLabel(promoType),
			Count: counts[promoType],
		}
		for shorthand, target := range aliases {
			if target == promoType {
				entry.Aliases = append(entry.Aliases, shorthand)
			}
		}
		sort.Strings(entry.Aliases)
		promos = append(promos, entry)
	}
	// Commonest first, so a caller showing only the head of the list shows
	// the types most of the game actually wears.
	sort.Slice(promos, func(i, j int) bool {
		if promos[i].Count != promos[j].Count {
			return promos[i].Count > promos[j].Count
		}
		return promos[i].Value < promos[j].Value
	})

	data, err := json.Marshal(promos)
	if err != nil {
		return nil
	}
	return data
}

// serveCached writes a list built alongside the datastore it describes.
// Until the first load completes, the answer is an empty list the browser
// must not keep for an hour.
func serveCached(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(data) == 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`[]`))
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}

// snapshot returns the lists built alongside the datastore currently
// served, or an empty Snapshot before the first load.
func (s *Service) snapshot() *Snapshot {
	if s.Snapshot == nil {
		return &Snapshot{}
	}
	snap := s.Snapshot()
	if snap == nil {
		return &Snapshot{}
	}
	return snap
}

// Promos returns the loaded game's promo types.
func (s *Service) Promos(w http.ResponseWriter, r *http.Request) {
	serveCached(w, s.snapshot().promos)
}

// Finish is one finish the loaded game prints, as the palette lists it.
type Finish struct {
	Value   string   `json:"value"`
	Label   string   `json:"label"`
	Count   int      `json:"count"`
	Aliases []string `json:"aliases,omitempty"`
}

// buildFinishes is the JSON-serialized finish list, built from b.
func (s *Service) buildFinishes(b *mtgmatcher.Backend) []byte {
	data, err := json.Marshal(s.FinishList(b))
	if err != nil {
		return nil
	}
	return data
}

// FinishList is every name the finish filter reaches b's printings by,
// commonest first, each with how many printings it reaches.
//
// Read off the printings rather than from a table, because the vocabulary is
// the game's: Lorcana prints cold foil and holofoil, Flesh and Blood rainbow
// and cold, Yu-Gi-Oh prices print runs, and a game added tomorrow brings its
// own.
func (s *Service) FinishList(b *mtgmatcher.Backend) []Finish {
	finishes := []Finish{}
	if s.FinishNames == nil {
		return finishes
	}
	counts := map[string]int{}
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		for _, name := range s.FinishNames(co) {
			counts[name]++
		}
	}

	// A short form rides with the treatment it stands for, as the promo
	// types carry theirs, rather than being listed a second time
	var aliases map[string]string
	if s.PromoAliases != nil {
		aliases = s.PromoAliases()
	}
	shortForms := map[string][]string{}
	for value := range counts {
		target := aliases[value]
		if target != "" && counts[target] > 0 {
			shortForms[target] = append(shortForms[target], value)
		}
	}
	for _, shorts := range shortForms {
		for _, short := range shorts {
			delete(counts, short)
		}
		sort.Strings(shorts)
	}

	for value, count := range counts {
		label := value
		if s.FinishLabel != nil {
			label = s.FinishLabel(b, value)
		}
		finishes = append(finishes, Finish{Value: value, Label: label, Count: count, Aliases: shortForms[value]})
	}
	sort.Slice(finishes, func(i, j int) bool {
		if finishes[i].Count != finishes[j].Count {
			return finishes[i].Count > finishes[j].Count
		}
		return finishes[i].Value < finishes[j].Value
	})
	return finishes
}

// Finishes returns the loaded game's finishes.
func (s *Service) Finishes(w http.ResponseWriter, r *http.Request) {
	serveCached(w, s.snapshot().finishes)
}

// CardMetaResponse describes one card for the frontend.
type CardMetaResponse struct {
	Name      string   `json:"name"`
	Found     bool     `json:"found"`
	Printings []string `json:"printings,omitempty"`
	Rarities  []string `json:"rarities,omitempty"`
	Colors    []string `json:"colors,omitempty"`
	Types     []string `json:"types,omitempty"`
}

// CardMeta returns metadata (printings, rarities, colors, types) for a card
// name, used by the chip-based filter builder.
func (s *Service) CardMeta(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/api/palette/card/")
	if escaped == "" {
		json.NewEncoder(w).Encode(CardMetaResponse{Found: false})
		return
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	name := strings.ReplaceAll(decoded, "+", " ")

	resp := CardMetaResponse{Name: name}

	printings, err := b.Printings4Card(name)
	if err != nil || len(printings) == 0 {
		json.NewEncoder(w).Encode(resp)
		return
	}
	resp.Found = true
	resp.Printings = printings

	rarityMap := map[string]bool{}
	colorMap := map[string]bool{}
	typeMap := map[string]bool{}
	uuids, _ := b.SearchEquals(name)
	for _, uuid := range uuids {
		co, err := b.GetUUID(uuid)
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

// Sets returns all known set codes with display metadata.
func (s *Service) Sets(w http.ResponseWriter, r *http.Request) {
	serveCached(w, s.snapshot().sets)
}

// Store is one scraper as the frontend lists it.
type Store struct {
	Shorthand string `json:"shorthand"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Sealed    bool   `json:"sealed,omitempty"`
}

// StoresResponse lists the enabled sellers and vendors.
type StoresResponse struct {
	Sellers []Store `json:"sellers"`
	Vendors []Store `json:"vendors"`
}

// Stores returns seller and vendor shorthand lists.
func (s *Service) Stores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=600")

	out := StoresResponse{
		Sellers: []Store{},
		Vendors: []Store{},
	}
	seen := map[string]bool{}
	for _, seller := range s.Sellers() {
		if seller == nil {
			continue
		}
		info := seller.Info()
		if seen["s:"+info.Shorthand] {
			continue
		}
		seen["s:"+info.Shorthand] = true
		out.Sellers = append(out.Sellers, Store{
			Shorthand: info.Shorthand,
			Name:      info.Name,
			Country:   info.CountryFlag,
			Sealed:    info.SealedMode,
		})
	}
	seen = map[string]bool{}
	for _, vendor := range s.Vendors() {
		if vendor == nil {
			continue
		}
		info := vendor.Info()
		if seen["v:"+info.Shorthand] {
			continue
		}
		seen["v:"+info.Shorthand] = true
		out.Vendors = append(out.Vendors, Store{
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

// NavTarget is one option of a frontend selector.
type NavTarget struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Group string `json:"group,omitempty"`
}

// ArbitTargets is the arbit page's filter and sort options.
type ArbitTargets struct {
	Filters []NavTarget `json:"filters"`
	Sorts   []NavTarget `json:"sorts"`
}

// NewspaperTargetsJSON returns JSON for all newspaper page views.
func (s *Service) NewspaperTargetsJSON() template.JS {
	out := []NavTarget{}
	titleCounts := map[string]int{}

	// First pass: count title occurrences so we know which need disambiguation.
	newspaperPages := s.NewspaperPages()
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
			label = label + " " + newspaperSourceSuffix(p.Option)
		}

		out = append(out, NavTarget{
			Value: p.Option,
			Label: label,
			Group: group,
		})
	}
	// Include Newspaper SubPages from the nav tree that aren't in NewspaperPages
	out = append(out, NavTarget{
		Value: "syp",
		Label: "TCG Syp List",
		Group: "Other",
	})
	data, _ := json.Marshal(out)
	return template.JS(data)
}

// newspaperSourceSuffix returns "(TCG)" or "(CK)" based on the option key.
// Falls back to "(<option>)" for novel keys so duplicates always render distinctly.
func newspaperSourceSuffix(option string) string {
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

// SleepersTargetsJSON returns the static sleepers page views.
func SleepersTargetsJSON() template.JS {
	out := []NavTarget{
		{Value: "bulk", Label: "Bulk Me Up"},
		{Value: "reprint", Label: "Long Time No Reprint"},
		{Value: "mismatch", Label: "Market Mismatch"},
		{Value: "gap", Label: "Ocean Gap"},
		{Value: "hotlist", Label: "Highest Buylist Growth"},
	}
	data, _ := json.Marshal(out)
	return template.JS(data)
}

// ArbitTargetsJSON produces targets for /arbit. variant adjusts visibility:
// "reverse" hides ArbitOnly filters; "global" shows only those relevant to
// the global view.
func (s *Service) ArbitTargetsJSON(variant string) template.JS {
	out := ArbitTargets{
		Filters: []NavTarget{},
		Sorts: []NavTarget{
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
	for _, filter := range s.ArbitFilters() {
		if variant == "global" && filter.ArbitOnly {
			continue
		}
		out.Filters = append(out.Filters, NavTarget{
			Value: filter.Key,
			Label: filter.Title,
		})
	}
	data, _ := json.Marshal(out)
	return template.JS(data)
}

// SealedMetaResponse describes one sealed product for the frontend.
type SealedMetaResponse struct {
	Name        string `json:"name"`
	Found       bool   `json:"found"`
	UUID        string `json:"uuid,omitempty"`
	SetCode     string `json:"setCode,omitempty"`
	HasContents bool   `json:"hasContents"`
	HasPicks    bool   `json:"hasPicks"`
}

// Sealed reports availability of contents-mode and pack-pull-mode searches
// for a sealed product, used by the palette to gate action rows.
func (s *Service) Sealed(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/api/palette/sealed/")
	if escaped == "" {
		json.NewEncoder(w).Encode(SealedMetaResponse{Found: false})
		return
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	name := strings.ReplaceAll(decoded, "+", " ")

	resp := SealedMetaResponse{Name: name}

	// Direct UUID lookup first; fall back to name resolution via the sealed-name index.
	co, err := b.GetUUID(name)
	if err != nil || co == nil {
		co, err = b.GetUUID(s.sealedname2uuid(b, name))
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
	if _, contentsErr := b.GetDecklist(co.SetCode, co.UUID); contentsErr == nil {
		resp.HasContents = true
	}
	if _, picksErr := b.GetPicksForSealed(co.SetCode, co.UUID); picksErr == nil {
		resp.HasPicks = true
	}

	json.NewEncoder(w).Encode(resp)
}

// sealedname2uuid resolves a sealed product name to its uuid, or "".
func (s *Service) sealedname2uuid(b *mtgmatcher.Backend, name string) string {
	name = strings.TrimSpace(strings.Trim(name, "\""))
	res, err := b.SearchSealedEquals(name)
	if err != nil {
		return ""
	}
	return res[0]
}
