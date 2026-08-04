package main

import (
	"context"
	"sort"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// Aliases so the search/discord code keeps its historical names.
type (
	EmbedSearchResult = embed.SearchResult
	EmbedField        = embed.Field
)

// embedService renders oEmbed previews and Discord panels. Instances always
// serve under their instance name (the mtgban.com subdomain), so redirect
// links anchor to it; dev runs point at the local server instead.
var embedService = &embed.Service{
	BaseURL: func() string {
		if DevMode {
			return "http://localhost:" + Config.Port
		}
		return "https://" + Config.InstanceName + ".mtgban.com"
	},
	EditionTitle: editionTitle,
	LastSold: func(ctx context.Context, cardId string) ([]tcgplayer.LatestSalesData, error) {
		return getLastSold(ctx, cardId, false)
	},
}

// searchEntries2embed converts the picked offers into the embed input shape.
func searchEntries2embed(results []SearchEntry) []embed.Entry {
	if results == nil {
		return nil
	}
	out := make([]embed.Entry, 0, len(results))
	for _, entry := range results {
		out = append(out, embed.Entry{
			ScraperName: entry.ScraperName,
			Shorthand:   entry.Shorthand,
			Price:       entry.Price,
			Ratio:       entry.Ratio,
		})
	}
	return out
}

// Retrieve cards from Sellers using the very first result
func ProcessEmbedSearchResultsSellers(foundSellers map[string]map[string][]SearchEntry, index bool) []embed.Entry {
	if len(foundSellers) == 0 {
		return nil
	}
	var results []SearchEntry

	sortedKeysSeller := make([]string, 0, len(foundSellers))
	for cardId := range foundSellers {
		sortedKeysSeller = append(sortedKeysSeller, cardId)
	}
	if len(sortedKeysSeller) > 1 {
		sortData := resolveSortingData(sortedKeysSeller)
		sort.Slice(sortedKeysSeller, func(i, j int) bool {
			return cmpSets(sortData[sortedKeysSeller[i]], sortData[sortedKeysSeller[j]])
		})
	}

	cardId := sortedKeysSeller[0]
	if index {
		results = foundSellers[cardId]["INDEX"]

		// Add the TCGplayer Direct to the Index section too, considering conditions
		for _, cond := range []string{"NM", "SP"} {
			done := false
			foundResults := foundSellers[cardId][cond]
			for _, result := range foundResults {
				if result.ScraperName == "TCGDirect" {
					results = append(results, result)
					done = true
					break
				}
			}
			if done {
				break
			}
		}
	} else {
		founders := map[string]string{}
		// Query results with the known (ordered) conditions
		for _, cond := range mtgban.DefaultGradeTags {
			foundResults := foundSellers[cardId][cond]

			// Loop through the results, keep track of the precessed
			// elements in the map (and skip lower condition ones)
			for _, result := range foundResults {
				_, found := founders[result.ScraperName]
				if found {
					continue
				}
				founders[result.ScraperName] = cond
				// If not NM, add a small tag
				if cond != "NM" {
					result.ScraperName += " (" + cond + ")"
				}
				results = append(results, result)
			}
		}
	}

	if len(results) > 0 {
		// Drop duplicates by looking at the last one as they are alredy sorted
		tmp := append(results[:0], results[0])
		for i := range results {
			if results[i].ScraperName != tmp[len(tmp)-1].ScraperName {
				tmp = append(tmp, results[i])
			}
		}
		results = tmp
	}
	return searchEntries2embed(results)
}

// Retrieve cards from Vendors using the very first result
func ProcessEmbedSearchResultsVendors(foundVendors map[string]map[string][]SearchEntry) []embed.Entry {
	if len(foundVendors) == 0 {
		return nil
	}

	sortedKeysVendor := make([]string, 0, len(foundVendors))
	for cardId := range foundVendors {
		sortedKeysVendor = append(sortedKeysVendor, cardId)
	}
	if len(sortedKeysVendor) > 1 {
		sortData := resolveSortingData(sortedKeysVendor)
		sort.Slice(sortedKeysVendor, func(i, j int) bool {
			return cmpSets(sortData[sortedKeysVendor[i]], sortData[sortedKeysVendor[j]])
		})
	}

	return searchEntries2embed(foundVendors[sortedKeysVendor[0]]["NM"])
}
