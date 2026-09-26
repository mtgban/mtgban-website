package main

import (
	"net/url"
	"slices"
	"sort"
	"sync"
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

var (
	popularSearchesMu      sync.Mutex
	popularSearchesCache   []PopularSearch
	popularSearchesCfgSnap []PopularSearchEntry

	// When a build comes up empty (datastore or prices still warming up),
	// the next attempt is delayed so the landing page doesn't re-run every
	// configured search on each view in the meantime.
	popularSearchesRetryAt time.Time
)

// getPopularSearches resolves each configured query to a representative card
// thumbnail, reusing the regular search pipeline. The result is cached and
// rebuilt whenever the configured queries change (e.g. after a config
// reload) or while the datastore is still loading.
func getPopularSearches(ds *datastore) []PopularSearch {
	cfg := Config.PopularSearches

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
			return uuid2card(ds.backend, id, true, false, false)
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
