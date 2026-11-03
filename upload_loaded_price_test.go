package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
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
