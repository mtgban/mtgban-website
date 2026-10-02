package embed

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
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

// priceColumn is where the price starts once rendered, in characters, which
// is what has to match across the rows of a field.
func priceColumn(v FieldValue) int {
	line := renderValue(v)
	return utf8.RuneCountInString(line[:strings.Index(line, "](")])
}

// The index rows are merged after their padding is measured - two scrapers
// become one row carrying a tag - so the padding no longer describes what is
// printed and the prices step in and out. Every row of a field has to put its
// price in the same column.
func TestIndexValuesAlign(t *testing.T) {
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

	for _, field := range FormatSearchResult("https://example.test", res) {
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
	res := &SearchResult{
		CardID: "abcd",
		ResultsIndex: []Entry{
			{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: 1.00},
			{ScraperName: "TCG Market", Shorthand: "TCGMarket", Price: 2.00},
			{ScraperName: "MKM Low", Shorthand: "MKMLow", Price: 3.00},
		},
	}

	for _, field := range FormatSearchResult("https://example.test", res) {
		var sum int
		for _, value := range field.Values {
			sum += fieldValueLength(value)
		}
		if field.Length != sum {
			t.Errorf("field %q: Length is %d, values add up to %d", field.Name, field.Length, sum)
		}
	}
}

// Retail and Buylist sit side by side, and a row wider than its column wraps
// the price under the name - for every row, since they are all padded to the
// widest. Each row has to fit, and a grade has to survive the cut.
func TestInlineRowsFit(t *testing.T) {
	res := &SearchResult{
		CardID: "abcd",
		ResultsSellers: []Entry{
			{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 179.99},
			{ScraperName: "TCGplayer Direct", Shorthand: "TCGDirect", Price: 1133.82, Grade: "SP"},
		},
		ResultsVendors: []Entry{
			{ScraperName: "ABU Games", Shorthand: "ABU", Price: 47.88},
			{ScraperName: "A Store With A Very Long Name", Shorthand: "LONG", Price: 72.00, Ratio: 70},
		},
	}

	for _, field := range FormatSearchResult("https://example.test", res) {
		want := priceColumn(field.Values[0])
		for _, value := range field.Values {
			t.Logf("%-8s %s", field.Name, renderValue(value))
			if width := renderedNameWidth(value) + len(value.ExtraSpaces) + tailWidth(value); width > InlineRowWidth {
				t.Errorf("field %q: %q is %d wide, want at most %d", field.Name, value.ScraperName, width, InlineRowWidth)
			}
			if got := priceColumn(value); got != want {
				t.Errorf("field %q: %q starts its price at column %d, want %d", field.Name, value.ScraperName, got, want)
			}
		}
	}

	retail := FormatSearchResult("https://example.test", res)[0]
	if got := retail.Values[1]; got.Tag != "SP" || !strings.HasSuffix(got.ScraperName, "…") {
		t.Errorf("graded row is %q (%q), want a shortened name keeping its SP tag", got.ScraperName, got.Tag)
	}
}
