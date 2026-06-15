package main

import (
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/fuzzy"
)

// closestCardName returns the canonical card (or sealed product) name
// closest to query, used to power "did you mean..." suggestions.
func closestCardName(query string, sealed bool) string {
	return fuzzy.Closest(query, mtgmatcher.AllNames("canonical", sealed))
}

// AltSearch is a suggested query offered when a search yields no results,
// pointing at a broader version of what the user typed.
type AltSearch struct {
	Label string
	Query string
}

// collapseSpaces trims and squeezes runs of whitespace into single spaces.
func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// relaxedSearches builds broader versions of a filtered query: the bare
// card name on its own, and — when more than one filter is present — the
// query with each individual filter removed. The original query is never
// suggested back.
func relaxedSearches(rawQuery, cleanQuery string, appliedFilters []string) []AltSearch {
	if len(appliedFilters) == 0 {
		return nil
	}

	seen := map[string]bool{collapseSpaces(rawQuery): true}
	var out []AltSearch

	if bare := collapseSpaces(cleanQuery); bare != "" && !seen[bare] {
		out = append(out, AltSearch{Label: bare, Query: bare})
		seen[bare] = true
	}

	// With a single filter, removing it is the same as the bare name above
	if len(appliedFilters) > 1 {
		for _, filter := range appliedFilters {
			query := collapseSpaces(strings.Replace(rawQuery, filter, "", 1))
			if query == "" || seen[query] {
				continue
			}
			out = append(out, AltSearch{Label: "without " + filter, Query: query})
			seen[query] = true
		}
	}
	return out
}

// buildSearchSuggestions returns a "did you mean..." card name and a list
// of broader searches to show when a query returns nothing. Hashing (UUID)
// searches are skipped since they aren't user-typed names.
func buildSearchSuggestions(rawQuery string, config SearchConfig, sealed bool) (string, []AltSearch) {
	if config.SearchMode == "hashing" {
		return "", nil
	}

	var didYouMean string
	if config.CleanQuery != "" {
		didYouMean = closestCardName(config.CleanQuery, sealed)
	}
	return didYouMean, relaxedSearches(rawQuery, config.CleanQuery, config.AppliedFilters)
}
