package main

import (
	"bytes"
	"html/template"
	"regexp"
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
		IsBuylist:    buylist,
		Metadata:     map[string]GenericCard{id: {Name: "Test Card"}},
		ResultPrices: map[string]map[string]float64{id + "NM": prices},
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
	for _, m := range regexp.MustCompile(`class="ures-price best">\s*<a href="[^"]*/(\w+)/card-1"`).FindAllStringSubmatch(b.String(), -1) {
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
		{"buylist with no loaded price", true, 0, nil},
		{"retail", false, 10, nil},
	} {
		got := greenCells(t, tc.buylist, tc.loaded, prices)
		if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
			t.Errorf("%s: green %v, want %v", tc.name, got, tc.want)
		}
	}
}
