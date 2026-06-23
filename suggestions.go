package main

import (
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/fuzzy"
)

// sealedTypeKeywords are product-type words people append to a set name
// when searching sealed products free-form (e.g. "lost caverns booster").
// Each maps straight to a t: filter, which the sealed search matches
// against a product's layout/name. Kept to unambiguous product words —
// format-y words that commonly appear inside set names (e.g. "commander")
// are deliberately excluded to avoid false set-name collisions.
var sealedTypeKeywords = []string{
	"booster", "box", "bundle", "pack", "collector", "draft", "set",
	"jumpstart", "deck", "case", "prerelease", "starter", "fat", "gift",
	"tournament", "spellbook",
}

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

// sealedQuerySuggestion turns a free-text sealed query that matched nothing
// into a structured "<set> t:<type>" suggestion. People type things like
// "lost caverns booster" meaning the set "The Lost Caverns of Ixalan" plus
// a booster type filter; whole-name fuzzy matching can't bridge a fragment
// of a long product name, so we split the words into product-type keywords
// (mapped to t: filters) and a set-name fragment (containment-matched
// against sets that actually carry sealed product), then rebuild a query
// the sealed engine understands. Returns nil when no set can be identified.
func sealedQuerySuggestion(rawQuery string) *AltSearch {
	fields := strings.Fields(strings.ToLower(rawQuery))
	if len(fields) == 0 {
		return nil
	}

	// Separate recognized product-type words from the set-name fragment.
	var typeWords, nameWords []string
	for _, f := range fields {
		if slices.Contains(sealedTypeKeywords, f) {
			typeWords = append(typeWords, f)
		} else {
			nameWords = append(nameWords, f)
		}
	}
	if len(nameWords) == 0 {
		// Only product-type words — too broad to anchor a suggestion.
		return nil
	}

	// Find the set whose name contains every remaining token. Prefer the
	// shortest matching name, which tends to be the most direct match and
	// avoids longer sets that merely happen to include the same words.
	var bestName, bestCode string
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil || len(set.SealedProduct) == 0 {
			continue
		}
		lower := strings.ToLower(set.Name)
		matched := true
		for _, w := range nameWords {
			if !strings.Contains(lower, w) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		if bestName == "" || len(set.Name) < len(bestName) {
			bestName = set.Name
			bestCode = code
		}
	}
	if bestCode == "" {
		return nil
	}

	// Build "s:<code>" plus a t: filter per recognized product-type word,
	// with a human-readable label echoing what the user was after.
	query := "s:" + bestCode
	label := bestName
	for _, t := range typeWords {
		query += " t:" + t
		label += " " + t
	}
	return &AltSearch{Label: label, Query: query}
}

// buildSearchSuggestions returns a "did you mean..." card name and a list
// of alternative searches to show when a query returns nothing. Hashing
// (UUID) searches are skipped since they aren't user-typed names.
func buildSearchSuggestions(rawQuery string, config SearchConfig, sealed bool) (string, []AltSearch) {
	if config.SearchMode == "hashing" {
		return "", nil
	}

	var didYouMean string
	if config.CleanQuery != "" {
		didYouMean = closestCardName(config.CleanQuery, sealed)
	}

	alts := relaxedSearches(rawQuery, config.CleanQuery, config.AppliedFilters)

	// For a free-text sealed search (no filters typed) that found nothing,
	// offer a decomposed set + product-type query as the first suggestion.
	if sealed && len(config.AppliedFilters) == 0 {
		if s := sealedQuerySuggestion(rawQuery); s != nil {
			alts = append([]AltSearch{*s}, alts...)
		}
	}

	return didYouMean, alts
}
