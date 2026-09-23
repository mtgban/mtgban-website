package main

import (
	"bytes"
	"html/template"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/docparse"
)

// loadedPrice renders the one cell, which is a named block and so can be
// executed without standing the whole results page up around it.
func loadedPrice(t *testing.T, entry docparse.Entry) string {
	t.Helper()
	tmpl, err := template.New("upload.html").Funcs(funcMap).ParseFiles("templates/upload.html")
	if err != nil {
		t.Fatalf("parsing upload.html: %v", err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "loaded-price", entry); err != nil {
		t.Fatalf("rendering loaded-price: %v", err)
	}
	return b.String()
}

// The offer link is the whole point of carrying the notes through: a row
// priced from a Cardmarket seller can be opened back where it was read.
func TestLoadedPriceLinksBackToTheOffer(t *testing.T) {
	const offer = "https://www.cardmarket.com/en/Lorcana/Users/Someone/Offers/Singles?name=Abu"

	linked := loadedPrice(t, docparse.Entry{OriginalPrice: 0.11, Notes: offer})
	if !strings.Contains(linked, offer) {
		t.Errorf("the price does not link back to the offer:\n%s", linked)
	}
	if !strings.Contains(linked, "$ 0.11") {
		t.Errorf("the price itself is missing:\n%s", linked)
	}

	// A row that carried no note is a price and nothing else. An empty
	// anchor would be a link to this page.
	plain := loadedPrice(t, docparse.Entry{OriginalPrice: 0.11})
	if strings.Contains(plain, "<a") {
		t.Errorf("a row with no notes was given a link:\n%s", plain)
	}

	// And notes that are not a link stay out of the href.
	noted := loadedPrice(t, docparse.Entry{OriginalPrice: 0.11, Notes: "bought at the shop"})
	if strings.Contains(noted, "<a") {
		t.Errorf("a note that is not a URL became a link:\n%s", noted)
	}
}

// A linked price must be visibly a link. It keeps the column's own colour
// on purpose - a row of blue numbers reads as a different kind of figure -
// and the site's anchors carry no underline of their own, so without a
// rule here the link is indistinguishable from plain text. It shipped that
// way: every price was a link and nothing on screen said so.
func TestALinkedPriceLooksLikeOne(t *testing.T) {
	sheet, err := os.ReadFile("css/upload.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}

	rule := regexp.MustCompile(`(?s)\.ures-price a[^{]*\{(.*?)\}`).FindStringSubmatch(string(sheet))
	if rule == nil {
		t.Fatal("nothing styles a linked price")
	}
	// The underline itself, and not merely a word: text-underline-offset
	// and text-decoration-color both say "underline" while drawing none
	// on their own, and the first draft of this check passed on a rule
	// that had lost the line and kept its colour.
	drawn := strings.Contains(rule[1], "text-decoration: underline") ||
		strings.Contains(rule[1], "text-decoration-line: underline")
	if !drawn {
		t.Error("a linked price is given no affordance, so it reads as plain text")
	}
}

// The optimizer shows the same number and had no link on it at all. It
// belongs only in the branch where that number is the uploaded price: with
// IgnorePrices the figure comes from an index, and pointing it at a seller
// would name the wrong source for it.
func TestTheOptimizerLinksTheLoadedPriceToo(t *testing.T) {
	page, err := os.ReadFile("templates/upload.html")
	if err != nil {
		t.Fatalf("reading upload.html: %v", err)
	}

	cell := regexp.MustCompile(`(?s)<td class="opt-loaded">.*?</td>`).FindString(string(page))
	if cell == "" {
		t.Fatal("the optimizer has no loaded-price cell")
	}
	if !strings.Contains(cell, "sourceLink .Notes") {
		t.Fatal("the optimizer's loaded price carries no link back to the offer")
	}

	// It has to sit inside the IgnorePrices else-branch, which is where
	// the number shown is the one the upload carried.
	split := strings.Index(cell, "{{else}}")
	source := strings.Index(cell, "sourceLink .Notes")
	if split < 0 {
		t.Fatal("the cell no longer branches on IgnorePrices")
	}
	if source < split {
		t.Error("the offer link is on the price the optimizer took from an index")
	}
}
