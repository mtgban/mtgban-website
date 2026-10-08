package main

import (
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PopularSearch is a resolved featured tile shown on the landing page: a
// card thumbnail that links to a ready-made query.
type PopularSearch struct {
	Label    string
	ImageURL string
	URL      string
}

// PopularSearchEntry is a configured featured search. The list is loaded
// from the config file's "popular_searches" key (and picked up again on a
// config reload). Label is optional and falls back to the resolved card's
// edition; Card optionally names the card (or a search query) whose image
// is used for the thumbnail, otherwise the query's top result is used.
type PopularSearchEntry struct {
	Query string `json:"query"`
	Label string `json:"label"`
	Card  string `json:"card,omitempty"`
}

// The ranking's budgets. Not config: no deployment needs them to differ.
const (
	popularDailyBudget   = 30
	popularMinUsers      = 3
	popularWindowDays    = 30
	popularRecentDays    = 7
	popularLimit         = 24
	popularFloor         = 8
	popularRetentionDays = 90
)

// PopularTile is an organic tile: a PopularSearch plus the vote key and
// counts it was ranked on.
type PopularTile struct {
	PopularSearch
	Key         string
	Query       string
	Users       int
	RecentUsers int
}

// popularOrganic is one ranking's resolved tiles, published whole.
type popularOrganic struct {
	At    time.Time
	Tiles []PopularTile
}

var popularOrganicPtr atomic.Pointer[popularOrganic]

var (
	popularSearchesMu      sync.Mutex
	popularSearchesCache   []PopularSearch
	popularSearchesCfgSnap []PopularSearchEntry

	// When a build comes up empty (datastore or prices still warming up),
	// the next attempt is delayed so the landing page doesn't re-run every
	// configured search on each view in the meantime.
	popularSearchesRetryAt time.Time
)

// popularOrganicSnapshot is the last published ranking, nil before one.
func popularOrganicSnapshot() *popularOrganic {
	return popularOrganicPtr.Load()
}

// popularKeyShape reports whether a parsed query's shape can ever yield a
// vote key: a plain name search, or exactly one non-negated, single-value
// edition filter and nothing else. resolvePopularKey checks this before
// running the search at all, so the two rules cannot drift apart.
func popularKeyShape(config SearchConfig) bool {
	if config.CleanQuery != "" {
		return true
	}
	if len(config.CardFilters) != 1 {
		return false
	}
	f := config.CardFilters[0]
	return f.Name == "edition" && !f.Negate && len(f.Values) == 1 && f.Values[0] != ""
}

// popularKey names what a search was for, as the ranking counts it: the
// top result's card for a named card, the set for a bare edition filter,
// nothing for anything else.
func popularKey(config SearchConfig, top GenericCard) string {
	if !popularKeyShape(config) {
		return ""
	}
	if config.CleanQuery != "" {
		if top.Name == "" {
			return ""
		}
		return "card:" + top.Name
	}
	return "set:" + strings.ToUpper(config.CardFilters[0].Values[0])
}

// mergePopular puts organic tiles first and pads with curated ones, in
// their order, up to floor, skipping any whose link or art is already shown.
func mergePopular(organic, curated []PopularSearch, floor int) []PopularSearch {
	if len(organic) == 0 {
		return curated
	}
	out := append([]PopularSearch{}, organic...)
	// An empty link or art matches nothing, so an artless tile blocks none.
	seen := make(map[string]struct{}, 2*len(out))
	mark := func(t PopularSearch) {
		for _, v := range []string{t.URL, t.ImageURL} {
			if v != "" {
				seen[v] = struct{}{}
			}
		}
	}
	shown := func(t PopularSearch) bool {
		for _, v := range []string{t.URL, t.ImageURL} {
			if _, dup := seen[v]; v != "" && dup {
				return true
			}
		}
		return false
	}
	for _, t := range out {
		mark(t)
	}
	for _, t := range curated {
		if len(out) >= floor {
			break
		}
		if shown(t) {
			continue
		}
		mark(t)
		out = append(out, t)
	}
	return out
}

// getPopularSearches is the landing strip: the organic ranking first, the
// curated config list padding it to popularFloor.
func getPopularSearches(ds *datastore) []PopularSearch {
	curated := curatedPopularSearches(ds)
	var organic []PopularSearch
	if snap := popularOrganicSnapshot(); snap != nil {
		for _, t := range snap.Tiles {
			organic = append(organic, t.PopularSearch)
		}
	}
	return mergePopular(organic, curated, max(popularFloor, len(curated)))
}

// curatedPopularSearches resolves each configured query to a representative card
// thumbnail, reusing the regular search pipeline. The result is cached and
// rebuilt whenever the configured queries change (e.g. after a config
// reload) or while the datastore is still loading.
func curatedPopularSearches(ds *datastore) []PopularSearch {
	cfg := Config().PopularSearches

	popularSearchesMu.Lock()
	defer popularSearchesMu.Unlock()

	// Reuse the cache while it was built from the current config; a config
	// reload forces a rebuild, and an empty result retries on a delay.
	if slices.Equal(popularSearchesCfgSnap, cfg) {
		if len(popularSearchesCache) > 0 {
			return popularSearchesCache
		}
		if time.Now().Before(popularSearchesRetryAt) {
			return nil
		}
	}

	var out []PopularSearch
	usedImages := make(map[string]struct{})
	for _, q := range cfg {
		config := parseSearchOptionsNG(ds.backend, q.Query, nil, nil, nil)
		uuids, err := searchAndFilter(ds, config)
		if err != nil || len(uuids) == 0 {
			continue
		}
		// searchAndFilter doesn't apply sort:retail (that needs live
		// prices), so sort here and take the top-retail card as the tile.
		if config.SortMode == "retail" {
			sortData := resolveSortingData(ds.backend, uuids)
			prices := resolveBestPrices(uuids, defaultSellerPriorityOpt, price4seller)
			sort.Slice(uuids, func(i, j int) bool {
				priceI, priceJ := prices[uuids[i]], prices[uuids[j]]
				if priceI == priceJ {
					return cmpSets(sortData[uuids[i]], sortData[uuids[j]])
				}
				return priceI > priceJ
			})
		}
		candidateIDs := uuids
		// An explicit Card (name or query) overrides which card supplies the
		// thumbnail; fall back to the query's results when unresolved or when
		// its images are already used by another tile.
		if q.Card != "" {
			if ids, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, q.Card, nil, nil, nil)); err == nil && len(ids) > 0 {
				candidateIDs = append(append([]string{}, ids...), uuids...)
			}
		}
		card, ok := firstUnusedPopularCard(candidateIDs, usedImages, func(id string) GenericCard {
			return uuid2card(ds.backend, id, false)
		})
		if !ok {
			continue
		}
		usedImages[card.ImageURL] = struct{}{}
		label := q.Label
		if label == "" {
			label = card.Edition
		}
		out = append(out, PopularSearch{
			Label:    label,
			ImageURL: card.ImageURL,
			URL:      "/search?q=" + url.QueryEscape(q.Query),
		})
	}

	popularSearchesCfgSnap = cfg
	popularSearchesCache = out
	if len(out) == 0 {
		popularSearchesRetryAt = time.Now().Add(time.Minute)
	}
	return out
}

// firstUnusedPopularCard keeps the carousel's resolved images distinct while
// allowing a duplicate top result to fall through to another result. The
// resolver is injected so this selection rule remains testable without a
// datastore-backed search.
func firstUnusedPopularCard(ids []string, usedImages map[string]struct{}, resolve func(string) GenericCard) (GenericCard, bool) {
	for _, id := range ids {
		card := resolve(id)
		if card.ImageURL == "" {
			continue
		}
		if _, used := usedImages[card.ImageURL]; used {
			continue
		}
		return card, true
	}
	return GenericCard{}, false
}
