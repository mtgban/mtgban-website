package main

import (
	"bytes"
	"html/template"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A linked price must be visibly a link. It keeps the column's own colour
// on purpose - a row of blue numbers reads as a different kind of figure -
// and the site's anchors carry no underline of their own, so without a
// rule here the link is indistinguishable from plain text.
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

// The offer link sits after the loaded price, whose click edits it, or among
// the Optimizer's icons, and only an http or https note becomes one, without
// its userinfo.
func TestOfferLinkBesideTheLoadedPrice(t *testing.T) {
	tmpl, err := template.New("upload.html").Funcs(funcMap).ParseFiles("templates/upload.html")
	if err != nil {
		t.Fatalf("parsing upload.html: %v", err)
	}
	const offer = "https://www.cardmarket.com/en/Magic/Users/Someone/Offers/Singles?name=Abu"
	for _, tc := range []struct{ note, want string }{
		{offer, `href="https://www.cardmarket.com/en/Magic/Users/Someone/Offers/Singles?name=Abu"`},
		{"https://user:pass@example.com/offer", `href="https://example.com/offer"`},
		{"", ""},
		{"bought at the shop", ""},
		{"javascript:alert(1)", ""},
		{"ftp://example.com/offer", ""},
	} {
		var b bytes.Buffer
		err := tmpl.ExecuteTemplate(&b, "offer-link", map[string]any{"Notes": tc.note, "Opt": true})
		if err != nil {
			t.Fatalf("rendering offer-link: %v", err)
		}
		got := b.String()
		if tc.want == "" {
			if got != "" {
				t.Errorf("note %q became a link: %s", tc.note, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) || !strings.Contains(got, `data-track="ui.optimizer" data-track-value="offer_link"`) {
			t.Errorf("note %q: want %s in %s", tc.note, tc.want, got)
		}
		if strings.Contains(got, "pass@") {
			t.Errorf("note %q kept its userinfo: %s", tc.note, got)
		}
	}

	// Outside the Optimizer it counts as a Results action.
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "offer-link", map[string]any{"Notes": offer}); err != nil {
		t.Fatalf("rendering offer-link: %v", err)
	}
	if !strings.Contains(b.String(), `data-track="ui.upload.result"`) {
		t.Errorf("a Results offer link is not counted as one: %s", b.String())
	}

	// Results and the not-found rows draw it after the price, and each
	// Optimizer loaded cell among its icons, never in the Offer column.
	page, err := os.ReadFile("templates/upload.html")
	if err != nil {
		t.Fatalf("reading upload.html: %v", err)
	}
	if n := strings.Count(string(page), `{{template "offer-link"`); n != 4 {
		t.Errorf("offer-link is drawn in %d places, want 4", n)
	}
	for _, cell := range regexp.MustCompile(`<td class="opt-loaded".*?</td>`).FindAllString(string(page), -1) {
		icons := regexp.MustCompile(`<span class="opt-icons">.*`).FindString(cell)
		if !strings.Contains(icons, "offer-link") || !strings.Contains(icons, "opt-altlink") {
			t.Errorf("an Optimizer loaded cell keeps the offer link or its 🔗 out of its icons: %s", cell)
		}
	}
	for _, cell := range regexp.MustCompile(`<td class="opt-offer".*?</td>`).FindAllString(string(page), -1) {
		if strings.Contains(cell, "offer-link") {
			t.Errorf("an Optimizer offer cell draws the offer link: %s", cell)
		}
	}
}

// A leftover keeps its offer link when the list's prices are ignored, the
// only way back to an offer no store's Offer cell links.
func TestLeftoverOfferLinkWithPricesIgnored(t *testing.T) {
	const offer = "https://www.cardmarket.com/en/Magic/Users/Someone/Offers/Singles?name=Abu"
	for _, ignore := range []bool{false, true} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			IgnorePrices:  ignore,
			UploadEntries: []UploadEntry{{CardID: "a"}},
			NotBought:     []LeftoverEntry{{CardID: "a", Quantity: 1, Loaded: 2, Notes: offer}},
		}})
		section := leftoverRows(out, "opt-not-bought")
		if !strings.Contains(section, `class="ures-offer-link" href="`+offer) {
			t.Errorf("IgnorePrices %v: the leftover has no offer link: %s", ignore, section)
		}
	}
}

// Every results row holds a grade, empty for a row with no condition, so a
// condition picked for it reaches its Optimizer row, the key of its move.
func TestResultsRowGrade(t *testing.T) {
	for _, cond := range []mtgban.Condition{"", "SP"} {
		entries := []UploadEntry{{CardID: "a", OriginalCondition: cond}}
		out := renderUpload(t, PageVars{UploadVars: UploadVars{UploadEntries: entries, SinglesEntries: entries}})
		row := regexp.MustCompile(`<tr data-hash="a"[^>]*>`).FindString(out)
		want := ` data-grade="` + string(cond) + `"`
		if !strings.Contains(row, want) {
			t.Errorf("condition %q: row %q lacks%s", cond, row, want)
		}
	}
}

// A row loaded at its file's market price posts that price back with an "m"
// after it, which is how loadHashes knows it is not the owner's.
func TestResultsRowMarksAMarketPrice(t *testing.T) {
	for want, market := range map[string]bool{`data-price="9.99m"`: true, `data-price="9.99"`: false} {
		entries := []UploadEntry{{CardID: "a", OriginalPrice: 9.99, PriceIsMarket: market}}
		out := renderUpload(t, PageVars{UploadVars: UploadVars{UploadEntries: entries, SinglesEntries: entries}})
		row := regexp.MustCompile(`<tr data-hash="a"[^>]*>`).FindString(out)
		if !strings.Contains(row, want) {
			t.Errorf("PriceIsMarket %v: row %q lacks %s", market, row, want)
		}
	}
}
