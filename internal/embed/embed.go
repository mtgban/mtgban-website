// Package embed renders search results into share-friendly panels: the
// oEmbed preview served for link unfurls and the field lists Discord
// messages are built from.
package embed

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/unistyle"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

const (
	// Overflow prevention for field.Value size
	MaxCustomEntries = 7

	// Discord API constants
	MaxEmbedFieldsValueLength = 1024
	MaxEmbedFieldsNumber      = 25

	// Maximum number of printings shown before truncating the list
	MaxPrintings = 12
)

// Service renders embeds, wired to the host's link building and data lookups.
type Service struct {
	// BaseURL returns the absolute origin used for redirect links.
	BaseURL func() string

	// EditionTitle renders a card id's edition line.
	EditionTitle func(cardId string) string

	// LastSold returns the latest TCGplayer sales for a card.
	LastSold func(ctx context.Context, cardId string) ([]tcgplayer.LatestSalesData, error)
}

// Entry is the slice of one store offer an embed renders. The host picks
// which offers to show and converts them from its own result type.
type Entry struct {
	ScraperName string
	Shorthand   string
	Price       float64
	Ratio       float64
}

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

type SearchResult struct {
	Invalid         bool
	CardId          string
	ResultsIndex    []Entry
	ResultsSellers  []Entry
	ResultsVendors  []Entry
	EditionSearched string
	NamesOverride   []string
}

type Field struct {
	Name   string
	Values []FieldValue
	Raw    string
	Length int
	Inline bool
}

type FieldValue struct {
	ScraperName string
	Tag         string
	ExtraSpaces string
	Link        string
	Price       string
	SuffixEmoji string
}

func fieldValueLength(value FieldValue) int {
	// Buffer for formatting
	extra := 12
	return len(value.ScraperName) + len(value.Tag) + len(value.ExtraSpaces) + len(value.Link) + len(value.Price) + len(value.SuffixEmoji) + extra
}

var fieldNames = []string{
	"Index", "Retail", "Buylist",
}

// PrintingsLine joins a printings list for display, truncating long ones.
func PrintingsLine(printings []string) string {
	line := strings.Join(printings, ", ")
	if len(printings) > MaxPrintings {
		line = strings.Join(printings[:MaxPrintings], ", ") + " and more"
	}
	return line
}

func (s *Service) FormatSearchResult(searchRes *SearchResult) (fields []Field) {
	// Add two embed fields, one for retail and one for buylist
	for i, results := range [][]Entry{
		searchRes.ResultsIndex, searchRes.ResultsSellers, searchRes.ResultsVendors,
	} {
		// Skip amepty results
		if results == nil {
			continue
		}

		// Assign name or override
		fieldName := fieldNames[i]
		if len(searchRes.NamesOverride) > i {
			fieldName = searchRes.NamesOverride[i]
		}
		field := Field{
			Name: fieldName,
		}
		if fieldNames[i] != "Index" {
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
			var value FieldValue

			for i := len(entry.ScraperName); i < alignLength; i++ {
				value.ExtraSpaces += " "
			}
			value.ScraperName = entry.ScraperName
			value.Price = fmt.Sprintf("$%0.2f", entry.Price)

			// Build url for our redirect
			kind := strings.ToLower(string(fieldNames[i][0]))
			store := entry.Shorthand
			value.Link = s.BaseURL() + "/" + path.Join("go", kind, store, searchRes.CardId)

			if entry.Ratio > 60 {
				value.SuffixEmoji += "🔥"
			}
			if fieldNames[i] == "Index" {
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
					field.Length -= fieldValueLength(field.Values[j])

					// Rebuild the Value and move to the next item
					field.Values[j] = FieldValue{
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

					field.Length += fieldValueLength(field.Values[j])
					continue
				}
			} else if fieldNames[i] == "Buylist" {
				for _, subres := range searchRes.ResultsSellers {
					// 90% of sell price is the minimum for arbit
					if subres.Price < entry.Price*0.9 {
						value.SuffixEmoji += "🚨"
						break
					}
				}
			}

			length := fieldValueLength(value)
			// If we go past the maximum value for embed field values,
			// make a new field for any spillover, as long as we are within
			// the limits of the number of embeds allowed
			if field.Length+length > MaxEmbedFieldsValueLength && len(fields) < MaxEmbedFieldsNumber {
				fields = append(fields, field)
				field = Field{
					Name:   fieldNames[i] + " (cont'd)",
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
			if fieldNames[i] == "Index" {
				continue
			}
		}

		fields = append(fields, field)
	}

	// Pad now that the values are final. The first pass sizes the padding
	// from the scraper name alone, but the index merge then rewrites a pair
	// of rows into one carrying a tag ("TCG" + "Low/Market"), clears the
	// padding it no longer describes, and the rename below changes a width
	// again - so what was measured up there is not what gets printed.
	for i := range fields {
		alignValues(&fields[i])
	}

	return
}

// renderedNameWidth is how wide a value's name reads once the bot prints it:
// the scraper name, and the tag beside it in its own brackets, both inside a
// single code span (see the format string in prepareCard).
func renderedNameWidth(value FieldValue) int {
	width := len(value.ScraperName)
	if value.Tag != "" {
		width += len(value.Tag) + len(" ()")
	}
	return width
}

// alignValues pads every value in a field out to the widest one, so the prices
// start in the same column. Field.Length is kept in step because it decides
// where the value spills into a continuation field.
func alignValues(field *Field) {
	var longest int
	for _, value := range field.Values {
		if width := renderedNameWidth(value); width > longest {
			longest = width
		}
	}
	for i := range field.Values {
		field.Length -= fieldValueLength(field.Values[i])
		field.Values[i].ExtraSpaces = strings.Repeat(" ", longest-renderedNameWidth(field.Values[i]))
		field.Length += fieldValueLength(field.Values[i])
	}
}

// Obtain the length of the scraper with the longest name
func longestName(results []Entry) (out int) {
	for _, entry := range results {
		probe := len(entry.ScraperName)
		if probe > out {
			out = probe
		}
	}
	return
}

// LastSoldFields renders the latest sales for a card in the given language.
// Called from a discord session, so there is no context information available.
func (s *Service) LastSoldFields(cardId string, lang string) ([]Field, error) {
	var fields []Field

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lastSales, err := s.LastSold(ctx, cardId)
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
		fields = append(fields, Field{
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

// Generate builds the oEmbed preview panel for a search result page.
// indexResults carries the index-price offers picked by the host; every
// card shown shares the same list, matching the historical behavior.
func (s *Service) Generate(allKeys []string, indexResults []Entry) *OEmbed {
	title := "Search Preview"
	img := ""
	htmlBody := ""
	var results []SearchResult

	for i, cardId := range allKeys {
		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			continue
		}

		if i == 0 {
			title = co.Name
			if co.Sealed {
				title += " 📦"
			} else if co.Etched {
				title += " 💫"
			} else if co.Foil {
				title += " ✨"
			}
			if len(co.Printings) > 0 {
				htmlBody += fmt.Sprintf("Printed in %s.\n\n", PrintingsLine(co.Printings))
			}
			img = co.Images["full"]
		}

		fieldName := fmt.Sprintf("[%s] %s - %s", co.SetCode, co.Name, s.EditionTitle(cardId))

		results = append(results, SearchResult{
			CardId:        cardId,
			ResultsIndex:  indexResults,
			NamesOverride: []string{fieldName},
		})

		if i > MaxCustomEntries {
			break
		}
	}

	for _, result := range results {
		fields := s.FormatSearchResult(&result)

		for _, field := range fields {
			htmlBody += unistyle.BoldSans(field.Name) + "\n"
			if field.Raw != "" {
				htmlBody += field.Raw + "\n"
			}

			for _, value := range field.Values {
				tag := ""
				if value.Tag != "" {
					tag = fmt.Sprintf(" (%s)", value.Tag)
				}
				htmlBody += "• " + value.ScraperName + tag + ": " + value.Price + "\n"
			}
			htmlBody += "\n"
		}
	}

	// Trim any extra space or carriage feed from the final response
	htmlBody = strings.TrimSpace(htmlBody)

	return &OEmbed{
		Version:         "1.0",
		ProviderName:    "MTGBAN Price Search",
		ProviderURL:     "https://mtgban.com",
		Title:           title,
		Type:            "link",
		HTML:            htmlBody,
		ThumbnailURL:    img,
		ThumbnailWidth:  488,
		ThumbnailHeight: 680,
	}
}
