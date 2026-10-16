package main

import (
	"encoding/json"
	"html"
	"os"
	"strings"
	"testing"
)

func TestSearchResultHoverAndInitialArt(t *testing.T) {
	out := renderPage(t, "search.html", false, sealedPage(nil))

	if !strings.Contains(out, `data-hover="`) {
		t.Error("result header lacks data-hover")
	}
	if strings.Contains(out, "onmouseenter=") {
		t.Error("inline hover handler still rendered")
	}
	if !strings.Contains(loadedScript(t, out, "search-sidebar.js"), "__sidebarCardKey") {
		t.Error("search sidebar hover handler does not deduplicate the current result")
	}
}

// TestSearchResultHoverPayloadIsScalarsOnly checks that the HTML the hover
// panels need (printings, products) travels as a per-result <template>
// rather than as text in data-hover, which only carries the eight scalars.
func TestSearchResultHoverPayloadIsScalarsOnly(t *testing.T) {
	page := sealedPage(nil)
	page.AllKeys = []string{"first", "second"}
	page.Metadata = map[string]GenericCard{
		"first":  {Name: "First Product", SetCode: "ONE", Sealed: true},
		"second": {Name: "Second Product", SetCode: "TWO", Sealed: true},
	}
	out := renderPage(t, "search.html", false, page)

	args := firstHoverArgs(t, out)
	if len(args) != 8 {
		t.Errorf("data-hover has %d elements, want 8 (the HTML panels moved to a <template>): %v", len(args), args)
	}

	const marker = `data-hover="`
	for rest := out; ; {
		start := strings.Index(rest, marker)
		if start < 0 {
			break
		}
		rest = rest[start+len(marker):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			t.Fatal("data-hover attribute has no closing quote")
		}
		if strings.Contains(html.UnescapeString(rest[:end]), "<") {
			t.Errorf("data-hover carries HTML: %s", rest[:end])
		}
		rest = rest[end:]
	}

	if want, got := 2, strings.Count(out, `<template class="result-hover">`); got != want {
		t.Errorf("rendered %d <template class=\"result-hover\"> blocks, want %d (one per result)", got, want)
	}
	if want, got := 2, strings.Count(out, `class="hover-printings"`); got != want {
		t.Errorf("rendered %d .hover-printings divs, want %d", got, want)
	}
	if want, got := 2, strings.Count(out, `class="hover-products"`); got != want {
		t.Errorf("rendered %d .hover-products divs, want %d", got, want)
	}
}

// firstHoverArgs returns the parsed data-hover payload of the first result
// header in a rendered page: the eight scalars data-hover carries, in
// hover_args's call order (src, isFoil, isEtched, setCode, hasWarning,
// productsCount, releaseDate, cardName).
func firstHoverArgs(t *testing.T, out string) []any {
	t.Helper()
	const marker = `data-hover="`
	start := strings.Index(out, marker)
	if start < 0 {
		t.Fatal("rendered search page has no data-hover payload")
	}
	rest := out[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("data-hover attribute has no closing quote")
	}
	raw := html.UnescapeString(rest[:end])
	var args []any
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("data-hover is not valid JSON: %v (%s)", err, raw)
	}
	return args
}

// TestSearchResultHoverProductsRenderAsUnescapedHTML pins that
// GenericCard.Products reaches the template through trusted_html, not
// plain {{...}} escaping: swapping one for the other would turn the "<a"
// below into "&lt;a" and this test would catch it.
func TestSearchResultHoverProductsRenderAsUnescapedHTML(t *testing.T) {
	page := sealedPage(nil)
	page.Metadata = map[string]GenericCard{
		"prod": {Name: "A Sealed Thing", Sealed: true, SetCode: "TST", Products: `<a href="/sealed?q=x">Linked Product</a>`},
	}

	out := renderPage(t, "search.html", false, page)

	if !strings.Contains(out, `<div class="hover-products"><a href="/sealed?q=x">Linked Product</a></div>`) {
		t.Errorf("Products HTML was not rendered unescaped inside the template:\n%s", out)
	}
}

func TestSearchInitialArtKeepsFirstResultMetadata(t *testing.T) {
	page := sealedPage(nil)
	page.AllKeys = []string{"first", "second"}
	page.Metadata = map[string]GenericCard{
		"first":  {Name: "First Product", SetCode: "ONE", Date: "2020-01-02", Sealed: true},
		"second": {Name: "Second Product", SetCode: "TWO", Sealed: true, FullImageURL: "second.jpg", Foil: true},
	}

	out := renderPage(t, "search.html", false, page)
	args := firstHoverArgs(t, out)
	// [src, isFoil, isEtched, setCode, hasWarning, productsCount, releaseDate, cardName]
	if args[3] != "ONE" || args[6] != "2020-01-02" || args[7] != "First Product" {
		t.Errorf("first result's hover payload used the wrong metadata: %v", args)
	}
	if args[3] == "TWO" || args[1] == true || args[7] == "Second Product" {
		t.Errorf("first result's hover payload leaked the second result's metadata: %v", args)
	}
}

// TestSearchResultProductsKeepOddsMarkup checks the odds span survives the
// template: Products is trusted HTML in the result's hover template.
func TestSearchResultProductsKeepOddsMarkup(t *testing.T) {
	page := sealedPage(nil)
	page.AllKeys = []string{"first"}
	page.Metadata = map[string]GenericCard{
		"first": {
			Name:        "Some Card",
			SetCode:     "ONE",
			Products:    `<h4><a href=/sealed?q=abc>Some Box <span class="product-odds">1 in 12</span></a></h4>`,
			NumProducts: 1,
		},
	}
	out := renderPage(t, "search.html", false, page)

	want := `<div class="hover-products"><h4><a href=/sealed?q=abc>Some Box <span class="product-odds">1 in 12</span></a></h4></div>`
	if !strings.Contains(out, want) {
		t.Errorf("rendered page lacks the odds span unescaped; want %s", want)
	}
	css, err := os.ReadFile("css/search.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".sidebar-products-list .product-odds") {
		t.Error("search.css has no .sidebar-products-list .product-odds rule")
	}
}
