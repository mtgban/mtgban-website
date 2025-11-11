package main

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

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

type OEmbed struct {
	Version         string `json:"version"`
	ProviderName    string `json:"provider_name"`
	ProviderURL     string `json:"provider_url"`
	Title           string `json:"title"`
	Type            string `json:"type"`
	HTML            string `json:"html"`
	ThumbnailURL    string `json:"thumbnail_url"`
	ThumbnailWidth  int    `json:"thumbnail_width"`
	ThumbnailHeight int    `json:"thumbnail_height"`
}

type EmbedSearchResult struct {
	Invalid         bool
	CardId          string
	ResultsIndex    []SearchEntry
	ResultsSellers  []SearchEntry
	ResultsVendors  []SearchEntry
	EditionSearched string
	NamesOverride   []string
}

type EmbedField struct {
	Name   string
	Values []EmbedFieldValue
	Raw    string
	Length int
	Inline bool
}

type EmbedFieldValue struct {
	ScraperName string
	Tag         string
	ExtraSpaces string
	Link        string
	Price       string
	SuffixEmoji string
}

func embedfieldlength(value EmbedFieldValue) int {
	// Buffer for formatting
	extra := 12
	return len(value.ScraperName) + len(value.Tag) + len(value.ExtraSpaces) + len(value.Link) + len(value.Price) + len(value.SuffixEmoji) + extra
}

var EmbedFieldsNames = []string{
	"Index", "Retail", "Buylist",
}

func FormatEmbedSearchResult(searchRes *EmbedSearchResult) (fields []EmbedField) {
	// Add two embed fields, one for retail and one for buylist
	for i, results := range [][]SearchEntry{
		searchRes.ResultsIndex, searchRes.ResultsSellers, searchRes.ResultsVendors,
	} {
		// Skip amepty results
		if results == nil {
			continue
		}

		// Assign name or override
		fieldName := EmbedFieldsNames[i]
		if len(searchRes.NamesOverride) > i {
			fieldName = searchRes.NamesOverride[i]
		}
		field := EmbedField{
			Name: fieldName,
		}
		if EmbedFieldsNames[i] != "Index" {
			field.Inline = true
		}

		// Results look really bad after MaxCustomEntries, and too much info
		// does not help, so sort by best price, trim, then sort back to original
		if len(results) > MaxCustomEntries {
			if fieldName == "Retail" {
				sort.Slice(results, func(i, j int) bool {
					return results[i].Price < results[j].Price
				})
			} else if fieldName == "Buylist" {
				sort.Slice(results, func(i, j int) bool {
					return results[i].Price > results[j].Price
				})
			}
			// Do not crop the first section, indexes are good price indicators
			if i != 0 {
				results = results[:MaxCustomEntries]
			}
		}
		sort.Slice(results, func(i, j int) bool {
			return results[i].ScraperName < results[j].ScraperName
		})

		// Alsign to the longest name by appending whitespaces
		alignLength := longestName(results)
		for _, entry := range results {
			var value EmbedFieldValue

			for i := len(entry.ScraperName); i < alignLength; i++ {
				value.ExtraSpaces += " "
			}
			value.ScraperName = entry.ScraperName
			value.Price = fmt.Sprintf("$%0.2f", entry.Price)

			// Build url for our redirect
			kind := strings.ToLower(string(EmbedFieldsNames[i][0]))
			store := entry.Shorthand
			link := ServerURL
			if DevMode && link == "" {
				link = DefaultServerURL
			}
			value.Link = link + "/" + path.Join("go", kind, store, searchRes.CardId)

			if entry.Ratio > 60 {
				value.SuffixEmoji += "🔥"
			}
			if EmbedFieldsNames[i] == "Index" {
				var shouldSkip bool
				var j int
				var newScraperName string
				var newTag string

				isSealed := strings.Contains(value.ScraperName, "EV") || strings.Contains(value.ScraperName, "Sim")

				// Determine which index we're merging (either 'TCG' or 'MKM')
				// since the scraper names are ('TCG Low' and 'TCG Market')
				fields := strings.Fields(value.ScraperName)
				if len(fields) < 2 || (fields[1] == "Direct" && !isSealed) {
					continue
				}

				found := false
				for j = range field.Values {
					// Look if an existing tag is present
					if (!isSealed && !strings.HasPrefix(field.Values[j].ScraperName, fields[0])) ||
						(isSealed && !strings.HasPrefix(field.Values[j].ScraperName, strings.Join(fields[0:2], " "))) {
						continue
					}

					newScraperName = fields[0]
					newTag = fmt.Sprintf("Low/%s", fields[1])

					// Sealed case, since results are in order, if one is found, append a new tag
					if isSealed {
						// Skip in case Mediam is equal to EV
						if field.Values[j].Price == value.Price {
							shouldSkip = true
							field.Values[j].ExtraSpaces = ""
							break
						}
						newScraperName = field.Values[j].ScraperName
						newTag = "EV/Sim"
						if field.Values[j].Tag == newTag {
							newTag = "EV/Sim/Std"
						}
					}
					found = true
					break
				}

				if shouldSkip {
					continue
				}

				// If found, then edit the exiting one instead of appending a new value
				if found {
					field.Length -= embedfieldlength(field.Values[j])

					// Rebuild the Value and move to the next item
					field.Values[j] = EmbedFieldValue{
						// Update the name
						ScraperName: newScraperName,
						// Update the tags
						Tag: newTag,
						// Handle alignment manually
						ExtraSpaces: "",
						// Append the second price
						Price: fmt.Sprintf("%s / %s", field.Values[j].Price, value.Price),
						// Either is fine
						Link: value.Link,
					}

					field.Length += embedfieldlength(field.Values[j])
					continue
				}
			} else if EmbedFieldsNames[i] == "Buylist" {
				if entry.Shorthand == "CK" {
					_, found := Infos["hotlist"][searchRes.CardId]
					if found {
						value.SuffixEmoji += "🌟"
					}
				}
				for _, subres := range searchRes.ResultsSellers {
					// 90% of sell price is the minimum for arbit
					if subres.Price < entry.Price*0.9 {
						value.SuffixEmoji += "🚨"
						break
					}
				}
			}

			length := embedfieldlength(value)
			// If we go past the maximum value for embed field values,
			// make a new field for any spillover, as long as we are within
			// the limits of the number of embeds allowed
			if field.Length+length > MaxEmbedFieldsValueLength && len(fields) < MaxEmbedFieldsNumber {
				fields = append(fields, field)
				field = EmbedField{
					Name:   EmbedFieldsNames[i] + " (cont'd)",
					Inline: true,
				}
			}
			field.Values = append(field.Values, value)
			field.Length += length
		}

		// Rename scrapers, yes the space is intentional
		for i := range field.Values {
			if field.Values[i].ScraperName == "TCG Direct (net) EV" {
				field.Values[i].ScraperName = "Direct EV "
			}
		}

		if len(results) == 0 {
			field.Raw = "N/A"
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

// Called from a discord session, so there is no context information available
func grabLastSold(cardId string, lang string) ([]EmbedField, error) {
	var fields []EmbedField

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lastSales, err := getLastSold(ctx, cardId, false)
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
			Raw:    value,
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
