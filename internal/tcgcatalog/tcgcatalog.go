// Package tcgcatalog parses the catalog dumps produced by tcgdumper
// (github.com/mtgban/go-tcgplayer).
package tcgcatalog

import (
	"encoding/json"
	"io"
	"strconv"
)

// Category identifies the dumped category: TCGplayer's own id and name (e.g.
// 1, "Magic"). The id scopes reads of the shared price archive to one game, so
// a game carries its own category in its dump rather than in a table here.
type Category struct {
	ID   int
	Name string
}

// Entry carries TCGplayer's own identifiers of a product.
type Entry struct {
	// The product name
	Name string
	// The name of the group (edition) the product belongs to
	Edition string
	// The collector number, kept as a string since 8k+ Magic numbers are
	// not numeric
	Number string
	// The rarity code (e.g. "M")
	Rarity string
}

// product is the minimal subset of a dump product needed to build an Entry;
// everything else (the skus array above all) is skipped during decoding and
// never retained.
type product struct {
	ProductID    int    `json:"productId"`
	Name         string `json:"name"`
	GroupID      int    `json:"groupId"`
	ExtendedData []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"extendedData"`
}

// Load parses a catalog dump into a map of entries keyed by product id, also
// returning the dumped category. The category is nil on error, and never nil
// otherwise (a dump without a category object yields a zero-valued one).
//
// Dumps easily exceed 1GB uncompressed, so the top-level object is walked
// one token at a time and products are decoded one by one; the whole
// document is never held in memory.
func Load(r io.Reader) (map[string]Entry, *Category, error) {
	dec := json.NewDecoder(r)
	groupNames := map[int]string{}
	products := map[string]Entry{}
	var category Category

	// Opening brace of the top-level object
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := keyToken.(string)
		switch key {
		case "category":
			var cat struct {
				CategoryID int    `json:"categoryId"`
				Name       string `json:"name"`
			}
			err := dec.Decode(&cat)
			if err != nil {
				return nil, nil, err
			}
			category = Category{ID: cat.CategoryID, Name: cat.Name}
		case "groups":
			var groups []struct {
				GroupID int    `json:"groupId"`
				Name    string `json:"name"`
			}
			err := dec.Decode(&groups)
			if err != nil {
				return nil, nil, err
			}
			for _, group := range groups {
				groupNames[group.GroupID] = group.Name
			}
		case "products":
			// Opening bracket of the array
			if _, err := dec.Token(); err != nil {
				return nil, nil, err
			}
			for dec.More() {
				var prod product
				err := dec.Decode(&prod)
				if err != nil {
					return nil, nil, err
				}
				entry := Entry{
					Name:    prod.Name,
					Edition: groupNames[prod.GroupID],
				}
				for _, data := range prod.ExtendedData {
					switch data.Name {
					case "Number":
						entry.Number = data.Value
					case "Rarity":
						entry.Rarity = data.Value
					}
				}
				products[strconv.Itoa(prod.ProductID)] = entry
			}
			// Closing bracket of the array
			if _, err := dec.Token(); err != nil {
				return nil, nil, err
			}
		default:
			// Any future field: decode and discard
			var skip json.RawMessage
			err := dec.Decode(&skip)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return products, &category, nil
}
