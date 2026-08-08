package collectr

import (
	"strings"
	"testing"
)

func TestParseShowcaseURL(t *testing.T) {
	for _, tc := range []struct {
		link   string
		handle string
		ok     bool
	}{
		{"https://app.getcollectr.com/showcase/profile/@handle", "@handle", true},
		{"https://app.getcollectr.com/showcase/profile/@handle?category=1&cardType=cards", "@handle", true},
		{"https://app.getcollectr.com/showcase/profile/handle", "", false},
		{"https://app.getcollectr.com/profile/@handle", "", false},
		{"https://evil.example.com/showcase/profile/@handle", "", false},
	} {
		handle, err := ParseShowcaseURL(tc.link)
		if tc.ok && (err != nil || handle != tc.handle) {
			t.Errorf("%s: handle=%q err=%v, want %q", tc.link, handle, err, tc.handle)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error", tc.link)
		}
	}
}

const productJSON = `{"product_id":"12345","product_name":"Lightning Bolt ","catalog_group":"Magic 2011","card_number":"146","rarity":"Common","quantity":"3","market_price":"1.50","card_condition":"Lightly Played","product_sub_type":"Foil","is_card":true,"catalog_category_name":"Magic: The Gathering"}`

// The same products array arrives in two encodings: plain JSON in the RSC
// stream, and JS-escaped inside the SSR HTML script chunks.
func TestParseProductsBothEncodings(t *testing.T) {
	plain := `garbage{"products":[` + productJSON + `]}garbage`
	escaped := `<script>self.__next_f.push("` +
		strings.ReplaceAll(strings.ReplaceAll(`{"products":[`+productJSON+`]}`, `\`, `\\`), `"`, `\"`) +
		`")</script>`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"rsc plain", plain},
		{"html escaped", escaped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, err := parseProducts(tc.body, "Magic: The Gathering", 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 {
				t.Fatalf("items = %d, want 1", len(items))
			}
			item := items[0]
			if item.Name != "Lightning Bolt" || item.SetName != "Magic 2011" ||
				item.Number != "146" || item.Quantity != 3 || !item.IsFoil ||
				item.IsSealed || item.Condition != "SP" || item.Price != 1.50 ||
				item.ProductID != "12345" {
				t.Errorf("item = %+v", item)
			}
		})
	}
}

func TestParseProductsFiltersCategory(t *testing.T) {
	body := `{"products":[` + productJSON + `]}`
	if _, err := parseProducts(body, "Lorcana", 0); err == nil {
		t.Error("wrong category should yield no products")
	}
}
