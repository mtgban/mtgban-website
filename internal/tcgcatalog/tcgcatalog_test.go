package tcgcatalog

import (
	"strings"
	"testing"
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

	products, categoryName, err := Load(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}

	if categoryName != "Magic" {
		t.Errorf("categoryName = %q, want Magic", categoryName)
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
