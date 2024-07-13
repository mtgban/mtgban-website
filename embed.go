package main

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
)

const (
	// Overflow prevention for field.Value size
	MaxCustomEntries = 7

	// Discord API constants
	MaxEmbedFieldsValueLength = 1024
	MaxEmbedFieldsNumber      = 25

	// Timeout before cancelling a last sold price request
	LastSoldTimeout = 30
)

type EmbedSearchResult struct {
	Invalid         bool
	CardId          string
	ResultsIndex    []SearchEntry
	ResultsSellers  []SearchEntry
	ResultsVendors  []SearchEntry
	EditionSearched string
}

type EmbedField struct {
	Name   string
	Value  string
	Inline bool
}

var EmbedFieldsNames = []string{
	"Index", "Retail", "Buylist",
}

func FormatEmbedSearchResult(searchRes *EmbedSearchResult) (fields []EmbedField) {
	// Add two embed fields, one for retail and one for buylist
	for i, results := range [][]SearchEntry{
		searchRes.ResultsIndex, searchRes.ResultsSellers, searchRes.ResultsVendors,
	} {
		field := EmbedField{
			Name: EmbedFieldsNames[i],
		}
		if EmbedFieldsNames[i] != "Index" {
			field.Inline = true
		}

		// Results look really bad after MaxCustomEntries, and too much info
		// does not help, so sort by best price, trim, then sort back to original
		if len(results) > MaxCustomEntries {
			if EmbedFieldsNames[i] == "Retail" {
				sort.Slice(results, func(i, j int) bool {
					return results[i].Price < results[j].Price
				})
			} else if EmbedFieldsNames[i] == "Buylist" {
				sort.Slice(results, func(i, j int) bool {
					return results[i].Price > results[j].Price
				})
			}
			results = results[:MaxCustomEntries]
		}
		sort.Slice(results, func(i, j int) bool {
			return results[i].ScraperName < results[j].ScraperName
		})

		// Alsign to the longest name by appending whitespaces
		alignLength := longestName(results)
		for _, entry := range results {
			extraSpaces := ""
			for i := len(entry.ScraperName); i < alignLength; i++ {
				extraSpaces += " "
			}
			// Build url for our redirect
			kind := strings.ToLower(string(EmbedFieldsNames[i][0]))
			store := strings.Replace(entry.Shorthand, " ", "%20", -1)
			link := "https://" + DefaultHost + "/" + path.Join("go", kind, store, searchRes.CardId)

			// Set the custom field
			value := fmt.Sprintf("• **[`%s%s`](%s)** $%0.2f", entry.ScraperName, extraSpaces, link, entry.Price)
			if entry.Ratio > 60 {
				value += " 🔥"
			}
			if EmbedFieldsNames[i] == "Index" {
				// Handle alignment manually
				extraSpaces = ""
				// Split the Value string so that we can edit each of them separately
				subs := strings.Split(field.Value, "\n")
				// Determine which index we're merging
				tag := strings.Fields(entry.ScraperName)[0]
				// Merge status, normally just add the price
				merged := false
				for j := range subs {
					// Check what kind of replacement needs to be done
					if entry.ScraperName == TCG_DIRECT {
						extraSpaces = "      "
					} else if strings.Contains(subs[j], tag) {
						// Adjust the name
						if tag == "TCG" {
							subs[j] = strings.Replace(subs[j], "TCG Low", "TCG (Low/Market)", 1)
						} else if tag == "MKM" {
							subs[j] = strings.Replace(subs[j], "MKM Low", "MKM (Low/Trend) ", 1)
						}
						// Append the other price
						subs[j] += fmt.Sprintf(" / $%0.2f", entry.Price)
						merged = true
					}
				}
				if merged {
					// Rebuild the Value and move to the next item
					field.Value = strings.Join(subs, "\n")
					continue
				}
				value = fmt.Sprintf("• **[`%s%s`](%s)** $%0.2f", entry.ScraperName, extraSpaces, link, entry.Price)
			} else if EmbedFieldsNames[i] == "Buylist" {
				alarm := false
				for _, subres := range searchRes.ResultsSellers {
					// 90% of sell price is the minimum for arbit
					if subres.Price < entry.Price*0.9 {
						alarm = true
						break
					}
				}
				if alarm {
					value += " 🚨"
				}
			}
			value += "\n"

			// If we go past the maximum value for embed field values,
			// make a new field for any spillover, as long as we are within
			// the limits of the number of embeds allowed
			if len(field.Value)+len(value) > MaxEmbedFieldsValueLength && len(fields) < MaxEmbedFieldsNumber {
				fields = append(fields, field)
				field = EmbedField{
					Name:   EmbedFieldsNames[i] + " (cont'd)",
					Inline: true,
				}
			}
			field.Value += value
		}
		if len(results) == 0 {
			field.Value = "N/A"
			// The very first item is allowed not to have entries
			if EmbedFieldsNames[i] == "Index" {
				continue
			}
		}

		fields = append(fields, field)
	}

	return
}

// Obtain the length of the scraper with the longest name
func longestName(results []SearchEntry) (out int) {
	for _, entry := range results {
		probe := len(entry.ScraperName)
		if probe > out {
			out = probe
		}
	}
	return
}

func grabLastSold(cardId string, lang string) ([]EmbedField, error) {
	var fields []EmbedField

	lastSales, err := getLastSold(cardId)
	if err != nil {
		return nil, err
	}

	var hasValues bool
	for _, entry := range lastSales {
		// Skip any language non matching the requested language
		if entry.Language != lang {
			continue
		}

		value := "-"
		if entry.PurchasePrice != 0 {
			hasValues = true
			value = fmt.Sprintf("$%0.2f", entry.PurchasePrice)
			if entry.ShippingPrice != 0 {
				value += fmt.Sprintf(" (+$%0.2f)", entry.ShippingPrice)
			}
		}
		fields = append(fields, EmbedField{
			Name:   entry.OrderDate.Format("2006-01-02"),
			Value:  value,
			Inline: true,
		})

		if len(fields) > 5 {
			break
		}
	}

	// No prices received, this is not an error,
	// but print a message warning the user
	if !hasValues {
		return nil, nil
	}

	return fields, nil
}

// Retrieve cards from Sellers using the very first result
func ProcessEmbedSearchResultsSellers(foundSellers map[string]map[string][]SearchEntry, index bool) []SearchEntry {
	if len(foundSellers) == 0 {
		return nil
	}
	var results []SearchEntry

	sortedKeysSeller := make([]string, 0, len(foundSellers))
	for cardId := range foundSellers {
		sortedKeysSeller = append(sortedKeysSeller, cardId)
	}
	if len(sortedKeysSeller) > 1 {
		sort.Slice(sortedKeysSeller, func(i, j int) bool {
			return sortSets(sortedKeysSeller[i], sortedKeysSeller[j])
		})
	}

	cardId := sortedKeysSeller[0]
	if index {
		results = foundSellers[cardId]["INDEX"]

		// Add the TCG_DIRECT to the Index section too, considering conditions
		for _, cond := range []string{"NM", "SP"} {
			done := false
			foundResults := foundSellers[cardId][cond]
			for _, result := range foundResults {
				if result.ScraperName == TCG_DIRECT {
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
	return results
}

// Retrieve cards from Vendors using the very first result
func ProcessEmbedSearchResultsVendors(foundVendors map[string]map[string][]SearchEntry) []SearchEntry {
	if len(foundVendors) == 0 {
		return nil
	}

	sortedKeysVendor := make([]string, 0, len(foundVendors))
	for cardId := range foundVendors {
		sortedKeysVendor = append(sortedKeysVendor, cardId)
	}
	if len(sortedKeysVendor) > 1 {
		sort.Slice(sortedKeysVendor, func(i, j int) bool {
			return sortSets(sortedKeysVendor[i], sortedKeysVendor[j])
		})
	}

	return foundVendors[sortedKeysVendor[0]]["NM"]
}
