// Package embed renders search results into share-friendly panels: the
// oEmbed preview served for link unfurls and the field lists Discord
// messages are built from.
package embed

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/unistyle"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	// MaxCustomEntries caps the rows one embed field carries, keeping its
	// value under Discord's size limit.
	MaxCustomEntries = 7

	// MaxEmbedFieldsValueLength is Discord's cap on one field's value.
	MaxEmbedFieldsValueLength = 1024
	// MaxEmbedFieldsNumber is Discord's cap on fields per embed.
	MaxEmbedFieldsNumber = 25

	// MaxPrintings is how many printings are listed before the line
	// truncates to "and more".
	MaxPrintings = 12

	// MaxPreviewCards is how many cards one preview panel lists. Distinct
	// from MaxCustomEntries, which counts rows within a single field.
	MaxPreviewCards = 8
)

// Entry is the slice of one store offer an embed renders. The host picks
// which offers to show and converts them from its own result type.
type Entry struct {
	ScraperName string
	Shorthand   string
	Price       float64
	Ratio       float64
}

// OEmbed is the oEmbed envelope Discord fetches to unfurl a link.
type OEmbed struct {
	Version         string `json:"version"`
	ProviderName    string `json:"provider_name"`
	ProviderURL     string `json:"provider_url"`
	Title           string `json:"title"`
	Type            string `json:"type"`
	HTML            string `json:"html"`
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	ThumbnailURL    string `json:"thumbnail_url,omitempty"`
	ThumbnailWidth  int    `json:"thumbnail_width,omitempty"`
	ThumbnailHeight int    `json:"thumbnail_height,omitempty"`
}

// A card scan is always this size, so a preview of one can say so. A sealed
// product's photo is not card-shaped and carries no dimensions at all.
const (
	cardImageWidth  = 488
	cardImageHeight = 680
)

// SearchResult is one search summarized for an embed: the index, retail
// and buylist rows found for a card.
type SearchResult struct {
	Invalid         bool
	CardID          string
	ResultsIndex    []Entry
	ResultsSellers  []Entry
	ResultsVendors  []Entry
	EditionSearched string
	NamesOverride   []string
}

// Sale is one recorded sale a last-sold panel lists: the four values it
// prints and nothing else. Declared here rather than taken from the
// scraper's own type, which would have a formatting package carrying an
// http client and a tls stack to name them.
type Sale struct {
	Language      string
	PurchasePrice float64
	ShippingPrice float64
	OrderDate     time.Time
}

// Field is one embed field, a titled column of aligned rows.
type Field struct {
	Name   string
	Values []FieldValue
	Raw    string
	Length int
	Inline bool
}

// FieldValue is one row of a field: a store, its price, and where the
// price links to.
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

// FormatSearchResult renders a search as embed fields, one each for the
// index, retail and buylist results. baseURL is the origin the price links
// point at.
func FormatSearchResult(baseURL string, searchRes *SearchResult) (fields []Field) {
	// Add two embed fields, one for retail and one for buylist
	for i, results := range [][]Entry{
		searchRes.ResultsIndex, searchRes.ResultsSellers, searchRes.ResultsVendors,
	} {
		// Skip empty results
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

		// Padding is left to alignValues at the end: the index merge below
		// rewrites pairs of rows into one and the rename after it changes a
		// width again, so nothing measured here would survive anyway.
		for _, entry := range results {
			var value FieldValue

			value.ScraperName = entry.ScraperName
			value.Price = fmt.Sprintf("$%0.2f", entry.Price)

			// Build url for our redirect
			kind := strings.ToLower(string(fieldNames[i][0]))
			store := entry.Shorthand
			value.Link = baseURL + "/" + path.Join("go", kind, store, searchRes.CardID)

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
				nameParts := strings.Fields(value.ScraperName)
				if len(nameParts) < 2 || (nameParts[1] == "Direct" && !isSealed) {
					continue
				}

				found := false
				for j = range field.Values {
					// Look if an existing tag is present
					if (!isSealed && !strings.HasPrefix(field.Values[j].ScraperName, nameParts[0])) ||
						(isSealed && !strings.HasPrefix(field.Values[j].ScraperName, strings.Join(nameParts[0:2], " "))) {
						continue
					}

					newScraperName = nameParts[0]
					newTag = fmt.Sprintf("Low/%s", nameParts[1])

					// Sealed case, since results are in order, if one is found, append a new tag
					if isSealed {
						// Skip in case Median is equal to EV
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

				// If found, then edit the existing one instead of appending a new value
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

// LastSoldFields renders sales already fetched, in the given language. The
// fetch stays with the caller: it is the half that needs a context, a
// timeout and an error to report, and none of that is formatting.
func LastSoldFields(lastSales []Sale, lang string) []Field {
	var fields []Field

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
		return nil
	}

	return fields
}

// Generate builds the oEmbed preview panel for a search result page.
// providerURL is the origin this instance publishes as its own, which the
// consumer records as the provider - not BaseURL, which pins redirect links
// to the instance name whatever host the reader arrived through. editionTitle
// renders a card's edition line, and indexFor returns the index-price offers
// for one card, so every card in the panel is quoted with its own prices.
func Generate(providerURL string, allKeys []string, editionTitle func(cardID string) string, indexFor func(cardID string) []Entry) *OEmbed {
	title := "Search Preview"
	img := ""
	htmlBody := ""
	sealed := false
	var results []SearchResult

	for _, cardID := range allKeys {
		co, err := mtgmatcher.GetUUID(cardID)
		if err != nil {
			continue
		}

		// Title and thumbnail come from the first card that resolves, not
		// from allKeys[0]: one id the datastore cannot place would otherwise
		// leave the preview with neither.
		if len(results) == 0 {
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
			sealed = co.Sealed
		}

		fieldName := fmt.Sprintf("[%s] %s - %s", co.SetCode, co.Name, editionTitle(cardID))

		var index []Entry
		if indexFor != nil {
			index = indexFor(cardID)
		}

		results = append(results, SearchResult{
			CardID:        cardID,
			ResultsIndex:  index,
			NamesOverride: []string{fieldName},
		})

		if len(results) == MaxPreviewCards {
			break
		}
	}

	for _, result := range results {
		// The panel prints names and prices and never a link, so the origin
		// handed over here only ever shows up if that changes.
		fields := FormatSearchResult(providerURL, &result)

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

	out := &OEmbed{
		Version:      "1.0",
		ProviderName: "MTGBAN Price Search",
		ProviderURL:  providerURL,
		Title:        title,
		// The panel travels in html, which oEmbed allows for a rich type
		// only - and a rich type has to declare its size.
		Type:         "rich",
		HTML:         htmlBody,
		Width:        cardImageWidth,
		Height:       cardImageHeight,
		ThumbnailURL: img,
	}
	if img != "" && !sealed {
		out.ThumbnailWidth = cardImageWidth
		out.ThumbnailHeight = cardImageHeight
	}
	return out
}
