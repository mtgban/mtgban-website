package main

import (
	"bytes"
	"html/template"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// greenCells renders the results table for one card and answers which
// stores' prices came out green.
func greenCells(t *testing.T, buylist bool, loaded float64, prices map[string]float64) []string {
	t.Helper()
	tmpl, err := template.New("upload.html").Funcs(funcMap).ParseFiles("templates/upload.html")
	if err != nil {
		t.Fatalf("parsing upload.html: %v", err)
	}
	const id = "card-1"
	root := PageVars{
		UploadVars: UploadVars{
			IsBuylist:    buylist,
			ResultPrices: map[string]map[string]float64{id + "NM": prices},
		},
		Metadata: map[string]GenericCard{id: {Name: "Test Card"}},
	}
	var b bytes.Buffer
	err = tmpl.ExecuteTemplate(&b, "ures-results-table", map[string]any{
		"Entries":   []UploadEntry{{CardID: id, OriginalCondition: "NM", OriginalPrice: loaded, Quantity: 1}},
		"StoreKeys": []string{"LOW", "HIGH"},
		"Quantity":  1,
		"Noun":      "card",
		"Root":      root,
	})
	if err != nil {
		t.Fatalf("rendering the results table: %v", err)
	}
	var green []string
	for _, m := range regexp.MustCompile(`class="ures-price best" data-sort="[^"]*">\s*<a href="[^"]*/(\w+)/card-1"`).FindAllStringSubmatch(b.String(), -1) {
		green = append(green, m[1])
	}
	return green
}

// Green is what the legend says: a buylist offer above the price the list
// came with. A list with no prices, a ManaBox deck for one, has nothing to
// compare with and shows no green.
func TestUploadResultsGreenFollowsTheLegend(t *testing.T) {
	prices := map[string]float64{"LOW": 8, "HIGH": 12}
	for _, tc := range []struct {
		name    string
		buylist bool
		loaded  float64
		want    []string
	}{
		{"buylist above the loaded price", true, 10, []string{"HIGH"}},
		{"buylist, both stores above", true, 5, []string{"LOW", "HIGH"}},
		// Equal is not above.
		{"buylist at the loaded price", true, 12, nil},
		{"buylist with no loaded price", true, 0, nil},
		{"retail", false, 10, nil},
	} {
		got := greenCells(t, tc.buylist, tc.loaded, prices)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: green %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A row the list came with no price for sorts as missing, last whichever
// way the Your Price column is sorted, as the store columns' empty cells
// do; a priced row sorts by its price.
func TestUploadYourPriceSortsUnpricedLast(t *testing.T) {
	tmpl, err := template.New("upload.html").Funcs(funcMap).ParseFiles("templates/upload.html")
	if err != nil {
		t.Fatalf("parsing upload.html: %v", err)
	}
	for _, table := range []string{"ures-results-table", "ures-notfound-table"} {
		for _, tc := range []struct {
			loaded float64
			want   string
		}{
			{0, `<td class="ures-price" data-sort="">`},
			{7.5, `<td class="ures-price" data-sort="7.50">`},
		} {
			var b bytes.Buffer
			err = tmpl.ExecuteTemplate(&b, table, map[string]any{
				"Entries":   []UploadEntry{{CardID: "card-1", OriginalCondition: "NM", OriginalPrice: tc.loaded, Quantity: 1}},
				"StoreKeys": []string{},
				"Quantity":  1,
				"Noun":      "card",
				"Root":      PageVars{Metadata: map[string]GenericCard{"card-1": {Name: "Test Card"}}},
			})
			if err != nil {
				t.Fatalf("%s: %v", table, err)
			}
			if !strings.Contains(b.String(), tc.want) {
				t.Errorf("%s, loaded %v: no %s", table, tc.loaded, tc.want)
			}
		}
	}
}
