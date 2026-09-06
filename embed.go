package main

import (
	"net/http"
	"sort"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// Aliases so the search/discord code keeps its historical names.
type (
	EmbedSearchResult = embed.SearchResult
	EmbedField        = embed.Field
)

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

// firstEmbedCard names the card an embed speaks for when it can only speak
// for one: the earliest by set, over every card the search found.
func firstEmbedCard(found map[string]map[string][]SearchEntry) string {
	sortedKeys := make([]string, 0, len(found))
	for cardID := range found {
		sortedKeys = append(sortedKeys, cardID)
	}
	if len(sortedKeys) > 1 {
		sortData := resolveSortingData(sortedKeys)
		sort.Slice(sortedKeys, func(i, j int) bool {
			return cmpSets(sortData[sortedKeys[i]], sortData[sortedKeys[j]])
		})
	}
	return sortedKeys[0]
}

// Retrieve cards from Sellers using the very first result
func ProcessEmbedSearchResultsSellers(foundSellers map[string]map[string][]SearchEntry, index bool) []embed.Entry {
	if len(foundSellers) == 0 {
		return nil
	}
	return EmbedSellerEntries(foundSellers, firstEmbedCard(foundSellers), index)
}

// EmbedSellerEntries picks the offers an embed shows for one named card.
func EmbedSellerEntries(foundSellers map[string]map[string][]SearchEntry, cardID string, index bool) []embed.Entry {
	var results []SearchEntry

	if index {
		results = foundSellers[cardID]["INDEX"]

		// Add the TCGplayer Direct to the Index section too, considering conditions
		for _, cond := range []string{"NM", "SP"} {
			done := false
			foundResults := foundSellers[cardID][cond]
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
			foundResults := foundSellers[cardID][cond]

			// Loop through the results, keep track of the processed
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
		// Drop duplicates by looking at the last one as they are already
		// sorted. Into a slice of its own: results can still be the INDEX
		// slice the map holds, and compacting that in place would rewrite
		// the rows the page is about to render.
		tmp := make([]SearchEntry, 0, len(results))
		tmp = append(tmp, results[0])
		for _, result := range results {
			if result.ScraperName != tmp[len(tmp)-1].ScraperName {
				tmp = append(tmp, result)
			}
		}
		results = tmp
	}
	return searchEntries2embed(results)
}

// lastSales2embed converts the scraper's sales into the embed input shape.
func lastSales2embed(sales []tcgplayer.LatestSalesData) []embed.Sale {
	out := make([]embed.Sale, 0, len(sales))
	for _, sale := range sales {
		out = append(out, embed.Sale{
			Language:      sale.Language,
			PurchasePrice: sale.PurchasePrice,
			ShippingPrice: sale.ShippingPrice,
			OrderDate:     sale.OrderDate,
		})
	}
	return out
}

// Retrieve cards from Vendors using the very first result
func ProcessEmbedSearchResultsVendors(foundVendors map[string]map[string][]SearchEntry) []embed.Entry {
	if len(foundVendors) == 0 {
		return nil
	}

	return searchEntries2embed(foundVendors[firstEmbedCard(foundVendors)]["NM"])
}

// externalURL is the origin this site is reachable at: what an oEmbed
// consumer records as the provider, and what an embed's price links point
// at. ServerURL is latched from the first request on a host we trust, so it
// can still be empty behind one we do not - and a bot message can go out
// before any request has come in at all.
func externalURL() string {
	if ServerURL != "" {
		return ServerURL
	}
	return "https://mtgban.com"
}

// oembedError answers an oEmbed request with a status and nothing else. The
// consumer asked for json and cannot read a rendered search page, which is
// what the regular no-results paths would hand it.
func oembedError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{}`))
}

// sellerReference names a reference seller and its price for a card, or
// nothing at all where this site does not carry that seller.
func sellerReference(cardID, shorthand string) (string, float64) {
	for _, seller := range GetSellers() {
		if !strings.EqualFold(seller.Info().Shorthand, shorthand) {
			continue
		}
		return seller.Info().Name, price4seller(cardID, shorthand)
	}
	return "", 0
}

// vendorReference is sellerReference for a buylist. Card Kingdom answers to
// the same shorthand on both sides, so asking the wrong one reads a retail
// price out under a buylist label.
func vendorReference(cardID, shorthand string) (string, float64) {
	for _, vendor := range GetVendors() {
		if !strings.EqualFold(vendor.Info().Shorthand, shorthand) {
			continue
		}
		return vendor.Info().Name, price4vendor(cardID, shorthand)
	}
	return "", 0
}
