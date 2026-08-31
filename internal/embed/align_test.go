package embed

import (
	"fmt"
	"strings"
	"testing"
)

// renderValue reproduces the line the bot prints for one value, from the
// format string in the website's prepareCard: name, tag, padding, all inside
// one code span, then the price.
func renderValue(v FieldValue) string {
	tag := ""
	if v.Tag != "" {
		tag = fmt.Sprintf(" (%s)", v.Tag)
	}
	return fmt.Sprintf("• **[`%s%s%s`](%s)** %s", v.ScraperName, tag, v.ExtraSpaces, v.Link, v.Price)
}

// priceColumn is where the price starts once rendered, which is what has to
// match across the rows of a field.
func priceColumn(v FieldValue) int {
	line := renderValue(v)
	return strings.Index(line, "](")
}

// The index rows are merged after their padding is measured - two scrapers
// become one row carrying a tag - so the padding no longer describes what is
// printed and the prices step in and out. Every row of a field has to put its
// price in the same column.
func TestIndexValuesAlign(t *testing.T) {
	svc := &Service{BaseURL: func() string { return "https://example.test" }}
	res := &SearchResult{
		CardID: "abcd",
		ResultsIndex: []Entry{
			{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 1.00},
			{ScraperName: "TCG Market", Shorthand: "TCGMarket", Price: 2.00},
			{ScraperName: "MKM Low", Shorthand: "MKMLow", Price: 3.00},
			{ScraperName: "MKM Trend", Shorthand: "MKMTrend", Price: 4.00},
		},
		ResultsSellers: []Entry{
			{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5.00},
			{ScraperName: "CSI", Shorthand: "CSI", Price: 6.00},
		},
	}

	for _, field := range svc.FormatSearchResult(res) {
		if len(field.Values) < 2 {
			continue
		}
		want := priceColumn(field.Values[0])
		for _, value := range field.Values {
			if got := priceColumn(value); got != want {
				t.Errorf("field %q: %q starts its price at column %d, want %d\n  %s",
					field.Name, value.ScraperName, got, want, renderValue(value))
			}
		}
		for _, value := range field.Values {
			t.Logf("%-8s %s", field.Name, renderValue(value))
		}
	}
}

// Field.Length decides when a value spills into a continuation field, so the
// re-padding has to leave it describing the values it actually holds.
func TestFieldLengthMatchesValues(t *testing.T) {
	svc := &Service{BaseURL: func() string { return "https://example.test" }}
	res := &SearchResult{
		CardID: "abcd",
		ResultsIndex: []Entry{
			{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 1.00},
			{ScraperName: "TCG Market", Shorthand: "TCGMarket", Price: 2.00},
			{ScraperName: "MKM Low", Shorthand: "MKMLow", Price: 3.00},
		},
	}

	for _, field := range svc.FormatSearchResult(res) {
		var sum int
		for _, value := range field.Values {
			sum += fieldValueLength(value)
		}
		if field.Length != sum {
			t.Errorf("field %q: Length is %d, values add up to %d", field.Name, field.Length, sum)
		}
	}
}
