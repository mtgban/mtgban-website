package tcgcatalog

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// TestLoad feeds a synthetic tcgdumper dump through the streaming decoder
// and checks field mapping and sku skipping.
func TestLoad(t *testing.T) {
	const dump = `{
		"category": {"categoryId": 1, "name": "Magic"},
		"groups": [
			{"groupId": 10, "name": "10th Edition"},
			{"groupId": 20, "name": "Aether Revolt"}
		],
		"products": [
			{
				"productId": 100, "name": "Shivan Dragon", "groupId": 10,
				"skus": [{"skuId": 1, "productId": 100}],
				"extendedData": [
					{"name": "Rarity", "value": "R"},
					{"name": "Number", "value": "123a"}
				]
			},
			{
				"productId": 200, "name": "Heart of Kiran", "groupId": 20,
				"extendedData": [{"name": "Rarity", "value": "M"}]
			}
		]
	}`

	products, category, err := Load(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}

	// The id travels with the dump so a game can name its own category.
	if category == nil || *category != (Category{ID: 1, Name: "Magic"}) {
		t.Errorf("category = %+v, want {1 Magic}", category)
	}
	if len(products) != 2 {
		t.Errorf("got %d products, want 2: %v", len(products), products)
	}

	want := Entry{
		Name:    "Shivan Dragon",
		Edition: "10th Edition",
		Number:  "123a",
		Rarity:  "R",
	}
	if products["100"] != want {
		t.Errorf("products[100] = %+v, want %+v", products["100"], want)
	}

	want = Entry{
		Name:    "Heart of Kiran",
		Edition: "Aether Revolt",
		Rarity:  "M",
	}
	if products["200"] != want {
		t.Errorf("products[200] = %+v, want %+v", products["200"], want)
	}
}

// A dump cut off between two top-level fields, by a read error or an early
// EOF, is an error rather than a short catalog.
func TestLoadRejectsTruncated(t *testing.T) {
	const whole = `{"category":{"categoryId":3},"groups":[],"products":[{"productId":7,"name":"Pikachu"}]}`
	reset := iotest.ErrReader(errors.New("connection reset"))
	for name, r := range map[string]io.Reader{
		"reset after groups": io.MultiReader(strings.NewReader(`{"category":{"categoryId":3},"groups":[]`), reset),
		"EOF after products": strings.NewReader(whole[:len(whole)-1]),
	} {
		if products, _, err := Load(r); err == nil {
			t.Errorf("%s: loaded %d products, want an error", name, len(products))
		}
	}
}
