// Package docparse turns uploaded inventory lists (CSV/XLS rows, decklist
// lines) into matched card entries. It recognizes the column layouts of the
// mtgban export format and the common deckbuilding/store tools, and resolves
// each row through mtgmatcher by uuid, TCGplayer SKU, or name.
package docparse

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// ErrDecklist reports that the input has no header row and should be
// reprocessed line-by-line as a decklist.
var ErrDecklist = errors.New("decklist")

// ErrReloadFirstRow reports that no field could be recognized in the first
// row, which should be reprocessed as a data row.
var ErrReloadFirstRow = errors.New("firstrow")

// Entry is a single uploaded row, matched to a card when possible.
type Entry struct {
	// A reference to the parsed card
	Card mtgmatcher.InputCard

	// The UUID of the card
	CardID string

	// Error when mtgmatcher.Match() fails
	MismatchError error

	// Error when multiple results are found
	MismatchAlias bool

	// UUIDs of possible alternatives
	PossibleAliases []string

	// Price as found in the source data
	OriginalPrice float64

	// Condition as found in the source data
	OriginalCondition string

	// Whether source data had Quantity information
	HasQuantity bool

	// Quantity as found in the source data
	Quantity int

	// Value exported as-is (up to 1024 characters) from the source data
	Notes string

	// Unpacked marks a sealed product that was opened into the cards it
	// holds, which are in the list beside it. The row is kept so the results
	// still say where those cards came from, and counts for nothing: not
	// towards a total, not towards a store's summary, and not into the
	// optimizer, which would otherwise be told to buy the box as well as its
	// contents.
	Unpacked bool

	// UnpackedFrom is the uuid of the product this card came out of, set on
	// every card an Unpacked row produced. It is what keeps a card with the
	// box it was in once the list has been sorted and split, so the results
	// can be read a product at a time.
	UnpackedFrom string
}

// Parser matches uploaded rows against the card database. The zero value is
// usable; the optional fields hook it up to the host's services.
type Parser struct {
	// Logf receives diagnostic lines about header detection. Optional.
	Logf func(format string, v ...any)

	// TCGSkuToUUID resolves a TCGplayer SKU (instance id) to a card uuid,
	// returning "" for unknown SKUs. Optional; without it SKU columns are
	// ignored.
	TCGSkuToUUID func(sku string) string

	// TCGSkuToCondition resolves a TCGplayer SKU to the condition it encodes
	// (NM/SP/MP/HP/PO), returning "" when unknown. Optional; used to infer the
	// condition for SKU uploads that carry no explicit condition column.
	TCGSkuToCondition func(sku string) string

	// PreferredPrinting orders alias candidates when a name matches several
	// printings; the first in the resulting order wins. Optional; without it
	// candidates keep the match order.
	PreferredPrinting func(uuidA, uuidB string) bool
}

func (p *Parser) logf(format string, v ...any) {
	if p.Logf != nil {
		p.Logf(format, v...)
	}
}

// GetQuantity parses a quantity field, accepting a trailing "x" ("4x").
func GetQuantity(qty string) (int, error) {
	qty = strings.TrimSuffix(qty, "x")
	qty = strings.TrimSpace(qty)
	return strconv.Atoi(qty)
}

// PartitionEntries splits entries into singles, sealed, and notFound. Entries
// with a match error go to notFound; matched entries split by membership in
// sealedIds.
func PartitionEntries(entries []Entry, sealedIDs []string) (singles, sealed, notFound []Entry) {
	sealedSet := make(map[string]bool, len(sealedIDs))
	for _, id := range sealedIDs {
		sealedSet[id] = true
	}

	for _, e := range entries {
		switch {
		case e.MismatchError != nil:
			notFound = append(notFound, e)
		case sealedSet[e.CardID]:
			sealed = append(sealed, e)
		default:
			singles = append(singles, e)
		}
	}
	return singles, sealed, notFound
}

// MergeIdenticalEntries collapses rows with the same card and condition into
// one entry, accumulating quantities.
func MergeIdenticalEntries(uploadedData []Entry) []Entry {
	var uploadedDataClean []Entry
	duplicatedHashes := map[string]bool{}

	for i := range uploadedData {
		// Preserve empty results (for errors and whatnot)
		if uploadedData[i].CardID == "" {
			uploadedDataClean = append(uploadedDataClean, uploadedData[i])
			continue
		}

		// Use id + condition to mimic a "sku", and the product it came out of
		// where there is one: two precons holding the same staple hold one
		// each, and a view that reads a box at a time has to say so in both.
		sku := uploadedData[i].CardID + uploadedData[i].OriginalCondition + uploadedData[i].UnpackedFrom

		if duplicatedHashes[sku] {
			qty := 1
			if uploadedData[i].HasQuantity {
				qty = uploadedData[i].Quantity
			}

			// Iterate on the already added cards to update the quantity
			for j := range uploadedDataClean {
				if uploadedData[i].CardID == uploadedDataClean[j].CardID &&
					uploadedData[i].OriginalCondition == uploadedDataClean[j].OriginalCondition &&
					uploadedData[i].UnpackedFrom == uploadedDataClean[j].UnpackedFrom {
					if uploadedDataClean[j].Quantity == 0 {
						uploadedDataClean[j].Quantity++
					}
					uploadedDataClean[j].Quantity += qty
					uploadedDataClean[j].HasQuantity = true
					break
				}
			}
			continue
		}

		duplicatedHashes[sku] = true
		uploadedDataClean = append(uploadedDataClean, uploadedData[i])
	}

	return uploadedDataClean
}

// ParseHeader maps recognized column names to their index in the header row.
func (p *Parser) ParseHeader(first []string) (map[string]int, error) {
	if len(first) < 1 {
		return nil, errors.New("too few fields")
	}

	indexMap := map[string]int{}

	// If there is a single element, try using a different mode
	if len(first) == 1 {
		indexMap["cardName"] = 0
		p.logf("No Header map, decklist mode (single element)")
		return indexMap, ErrDecklist
	}

	// Parse the header to understand where these fields are
	for i, field := range first {
		field = strings.ToLower(field)
		switch {
		// This should cover "uuid", "identifier", and so on
		// "key" is the uuid column of the mtgban inventory/cart CSV export
		case field == "uuid" || field == "id" || field == "key" || (strings.Contains(field, "id") && (strings.Contains(field, "scryfall") || strings.Contains(field, "tcgplayer product") || strings.Contains(field, "mtgjson"))):
			_, found := indexMap["id"]
			if !found {
				indexMap["id"] = i
			}
		case field == "tcgplayer id":
			_, found := indexMap["tcgSku"]
			if !found {
				indexMap["tcgSku"] = i
			}
		case (strings.Contains(field, "name") && !strings.Contains(field, "edition") && !strings.Contains(field, "set") && !strings.Contains(field, "expansion") && !strings.Contains(field, "folder")) || field == "card":
			_, found := indexMap["cardName"]
			if !found {
				indexMap["cardName"] = i
			}
		case strings.Contains(field, "edition") || strings.Contains(field, "set") || strings.Contains(field, "expansion"):
			_, found := indexMap["edition"]
			if !found {
				indexMap["edition"] = i
			}
		case strings.Contains(field, "comment") ||
			strings.Contains(field, "number") ||
			(strings.Contains(field, "col") && strings.Contains(field, "num")) ||
			strings.Contains(field, "variant") ||
			strings.Contains(field, "variation") ||
			strings.Contains(field, "version"):
			_, found := indexMap["variant"]
			if !found {
				indexMap["variant"] = i
			}
		case strings.Contains(field, "foil") || strings.Contains(field, "printing") || strings.Contains(field, "finish") || strings.Contains(field, "extra") || field == "f/nf" || field == "nf/f":
			_, found := indexMap["printing"]
			if !found {
				indexMap["printing"] = i
			}
		case strings.Contains(field, "sku"):
			_, found := indexMap["sku"]
			if !found {
				indexMap["sku"] = i
			}
		case strings.Contains(field, "condition"):
			_, found := indexMap["conditions"]
			if !found {
				indexMap["conditions"] = i
			}
		case strings.Contains(field, "price") || strings.Contains(field, "low"):
			_, found := indexMap["price"]
			if !found {
				indexMap["price"] = i
			}
		case (strings.Contains(field, "quantity") ||
			strings.Contains(field, "qty") ||
			strings.Contains(field, "stock") ||
			strings.Contains(field, "count") ||
			strings.Contains(field, "trade") ||
			strings.Contains(field, "have")) &&
			!strings.HasPrefix(field, "set") && !strings.Contains(field, "pending"):
			// Keep headers like "Add To Quantity" as backup if nothing is found later
			_, found := indexMap["quantity"]
			if !found && !strings.HasPrefix(field, "add") {
				indexMap["quantity"] = i
			} else {
				_, found := indexMap["quantity_backup"]
				if !found {
					indexMap["quantity_backup"] = i
				}
			}
		case strings.Contains(field, "title") && !strings.Contains(field, "variant"):
			_, found := indexMap["title"]
			if !found {
				indexMap["title"] = i
			}
		case strings.Contains(field, "notes") || strings.Contains(field, "data"):
			_, found := indexMap["notes"]
			if !found {
				indexMap["notes"] = i
			}
		}
	}

	// In case there was actually a single element, but the comma appears in the card name
	// Performing this after processing the map in case of a weird header with spaces
	// after the names
	if len(indexMap) < 2 && strings.Contains(strings.Join(first, ","), ", ") {
		indexMap["cardName"] = 0
		p.logf("No Header map, decklist mode (comma in card name)")
		return indexMap, ErrDecklist
	}

	// If a clean quantity header was not found see if there is a backup option
	_, foundQty := indexMap["quantity"]
	if !foundQty {
		i, found := indexMap["quantity_backup"]
		if found {
			indexMap["quantity"] = i
		}
	}

	// If this field is present we don't need safe defaults
	_, foundID := indexMap["id"]
	_, foundTcgID := indexMap["tcgSku"]

	// Set some default values for the mandatory fields
	_, foundName := indexMap["cardName"]
	if !foundName && !foundID && !foundTcgID {
		indexMap["cardName"] = 0
		// Used by some formats that do not set a card name
		i, found := indexMap["title"]
		if found {
			indexMap["cardName"] = i
			foundName = true
		}
	}
	_, foundEdition := indexMap["edition"]
	if !foundEdition && !foundID {
		indexMap["edition"] = 1
	}

	// If nothing at all was found, send an error to reprocess the first line
	if !foundName && !foundEdition && !foundID {
		p.logf("Fake Header map: %v", indexMap)
		return indexMap, ErrReloadFirstRow
	}

	p.logf("Header map: %v", indexMap)
	return indexMap, nil
}

// ParseRow matches one record against the card database using the column
// layout discovered by ParseHeader.
func (p *Parser) ParseRow(indexMap map[string]int, record []string) (Entry, error) {
	var res Entry

	// Skip empty lines
	hasContent := false
	for _, field := range record {
		if field != "" {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return res, errors.New("empty line")
	}

	// Ensure fields can be parsed correctly
	for i := range record {
		record[i] = strings.TrimSpace(record[i])
	}

	// Decklist mode
	if len(record) == 1 {
		line := record[0]

		// Try setting the card finish
		res.Card.Foil = strings.HasSuffix(line, "*F*")
		if strings.HasSuffix(line, "*E*") {
			res.Card.Variation = "etched"
		}
		line = strings.TrimRight(line, "FE*")
		line = strings.TrimSpace(line)

		if line != "" && unicode.IsDigit(rune(line[0])) {
			// Parse both "4 x <name>" and "4x <name>"
			fields := strings.Split(line, " ")
			field := strings.TrimSuffix(fields[0], "x")
			num, err := strconv.Atoi(field)
			if err == nil {
				// Cleanup and append
				line = strings.TrimPrefix(line, field)
				line = strings.TrimSpace(line)
				line = strings.TrimPrefix(line, "x")
				res.HasQuantity = true
				res.Quantity = num
			}
		}

		// Parse "Rift Bolt (TSP)"
		vars := mtgmatcher.SplitVariants(line)
		if len(vars) > 1 {
			maybeEdition := vars[1]
			// Only assign edition if it's a known set code
			set, err := mtgmatcher.GetSetByName(maybeEdition)
			if err == nil {
				// Remove the parsed part, leaving any other detail available downstream
				line = strings.Replace(line, "("+maybeEdition+")", "", 1)
				line = strings.Replace(line, "  ", "", -1)
				res.Card.Edition = set.Name
			}

			// Move anything that is not parsed to Variation
			// Parse the number from "Flagstones of Trokair (tsr) 278"
			// or long verbose lines like
			// Altar of the Brood [KTK] (Normal, Lightly Played, English) - $10.35 ($10.35 ea)
			variation := strings.TrimPrefix(line, vars[0])
			if res.Card.Variation != "" {
				res.Card.Variation += " "
			}
			res.Card.Variation += variation
			line = vars[0]
		}

		// Parse "10 Swamp <462> [CLB]"
		line = strings.Replace(line, "<", "(", 1)
		line = strings.Replace(line, ">", ")", 1)

		record[0] = line
		indexMap["cardName"] = 0
	}

	// Load quantity, and skip it if it's present and zero
	idx, found := indexMap["quantity"]
	if found && idx < len(record) {
		num, err := GetQuantity(record[idx])
		if err != nil || num == 0 {
			// Retry in the second quantity data if present
			idx, found = indexMap["quantity_backup"]
			if found && idx < len(record) {
				num, err = GetQuantity(record[idx])
			}
		}
		if err == nil {
			res.HasQuantity = true
			res.Quantity = num
		}
	}
	if res.HasQuantity && res.Quantity == 0 {
		return res, errors.New("no stock")
	}

	idx, found = indexMap["id"]
	if found && idx < len(record) {
		res.Card.ID = record[idx]
	}

	// Try looking up using the TCGSkuId if we found an id and it's not among
	// the supported ones - this needs to happen before the normal Match
	// or name matching might interfere with actual results
	var tcgSkuID string
	idx, found = indexMap["tcgSku"]
	if found && idx < len(record) && p.TCGSkuToUUID != nil {
		tcgSkuID = record[idx]
		res.Card.ID = p.TCGSkuToUUID(tcgSkuID)
	}

	res.Card.Name = record[indexMap["cardName"]]
	idx, found = indexMap["edition"]
	if found && idx < len(record) {
		res.Card.Edition = record[idx]
	}

	idx, found = indexMap["variant"]
	if found && idx < len(record) {
		res.Card.Variation = record[idx]
	}

	var sku string
	idx, found = indexMap["sku"]
	if found && idx < len(record) {
		sku = strings.ToLower(record[idx])
	}
	var conditions string
	idx, found = indexMap["conditions"]
	if found && idx < len(record) {
		conditions = strings.ToLower(record[idx])
	}
	var printing string
	idx, found = indexMap["printing"]
	if found && idx < len(record) {
		printing = strings.ToLower(record[idx])
	}
	switch printing {
	case "y", "yes", "true", "t", "1", "x":
		res.Card.Foil = true
	default:
		variation := strings.ToLower(res.Card.Variation)
		if (strings.Contains(printing, "foil") && !strings.Contains(printing, "non")) ||
			(strings.Contains(conditions, "foil") && !strings.Contains(conditions, "non")) ||
			(strings.Contains(variation, "foil") && !strings.Contains(variation, "non")) ||
			strings.HasSuffix(conditions, "f") || // MPF
			strings.Contains(sku, "-f-") || strings.Contains(sku, "-fo-") {
			res.Card.Foil = true
		}
	}

	idx, found = indexMap["price"]
	if found && idx < len(record) {
		res.OriginalPrice, _ = mtgmatcher.ParsePrice(record[idx])
	}

	switch {
	case strings.Contains(conditions, "mint"), strings.Contains(conditions, "nm"):
		res.OriginalCondition = "NM"
	case strings.Contains(conditions, "light"), strings.Contains(conditions, "lp"),
		strings.Contains(conditions, "sp"), strings.Contains(conditions, "ex"):
		res.OriginalCondition = "SP"
	case strings.Contains(conditions, "moderately"), strings.Contains(conditions, "mp"), strings.Contains(conditions, "vg"):
		res.OriginalCondition = "MP"
	case strings.Contains(conditions, "heav"), strings.Contains(conditions, "hp"), strings.Contains(conditions, "good"):
		res.OriginalCondition = "HP"
	case strings.Contains(conditions, "poor"), strings.Contains(conditions, "damage"),
		strings.Contains(conditions, "po"), strings.Contains(conditions, "dmg"):
		res.OriginalCondition = "PO"
	}

	// A TCGplayer SKU encodes its condition; when the source carried no
	// condition column, infer it from the SKU rather than leaving it blank.
	if res.OriginalCondition == "" && tcgSkuID != "" && p.TCGSkuToCondition != nil {
		res.OriginalCondition = p.TCGSkuToCondition(tcgSkuID)
	}

	idx, found = indexMap["notes"]
	if found && idx < len(record) {
		notes := record[idx]
		if len(notes) > 1024 {
			notes = notes[:1024]
		}
		res.Notes = notes
	}

	// Match might mutate the input card, keep a copy of the name for the
	// sealed fallback below
	ogName := res.Card.Name

	cardID, err := mtgmatcher.Match(&res.Card)

	// When the lookup fails, retry against the sealed pool for a 1:1 match
	if err != nil {
		hits, _ := mtgmatcher.SearchSealedEquals(ogName)
		if len(hits) > 0 {
			cardID = hits[0]
			err = nil
		}
	}

	var alias *mtgmatcher.AliasingError
	if errors.As(err, &alias) {
		// Keep the most recent printing available in case of aliasing
		aliases := alias.Probe()
		if p.PreferredPrinting != nil {
			sort.Slice(aliases, func(i, j int) bool {
				return p.PreferredPrinting(aliases[i], aliases[j])
			})
		}
		cardID = aliases[0]
		res.MismatchAlias = true
		res.PossibleAliases = aliases
	} else {
		res.MismatchError = err
	}
	res.CardID = cardID

	return res, nil
}
