package main

import (
	"strings"
	"testing"
)

// TestMetaDescriptionActiveNav fills the meta tag from the active nav
// entry's subtitle, turned into a sentence.
func TestMetaDescriptionActiveNav(t *testing.T) {
	pv := PageVars{
		UserNav: &NavElem{Short: "b"},
		Nav: []NavElem{
			{Name: "Search", Description: "Find a card by name", Active: true},
		},
	}
	out := renderPage(t, "home.html", false, pv)
	want := `content="MTGBAN Search: Find a card by name."`
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in rendered page, got:\n%s", want, out)
	}
}

// TestMetaDescriptionSiteLine falls back to the site's own line when the
// active nav entry has no subtitle.
func TestMetaDescriptionSiteLine(t *testing.T) {
	pv := PageVars{
		UserNav: &NavElem{Short: "b"},
		Nav: []NavElem{
			{Name: "Home", Active: true},
		},
	}
	out := renderPage(t, "home.html", false, pv)
	want := `content="Card prices and buylist offers from every major store, compared in one search."`
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in rendered page, got:\n%s", want, out)
	}
}

// TestMetaDescriptionCardPage keeps the embed text search.go produced for
// a card page, instead of the active nav entry's subtitle.
func TestMetaDescriptionCardPage(t *testing.T) {
	var pv PageVars
	pv.UserNav = &NavElem{Short: "b"}
	pv.Embed.Title = "Lightning Bolt"
	pv.Embed.Description = "Printed in many sets."
	out := renderPage(t, "search.html", false, pv)
	want := `content="Lightning Bolt prices across stores and buylists. Printed in many sets."`
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in rendered page, got:\n%s", want, out)
	}
}

// TestMetaDescriptionCardPageMobile keeps the same embed text on a phone
// card page, which renders through its own template.
func TestMetaDescriptionCardPageMobile(t *testing.T) {
	var pv PageVars
	pv.UserNav = &NavElem{Short: "b"}
	pv.IsMobile = true
	pv.Embed.Title = "Lightning Bolt"
	pv.Embed.Description = "Printed in many sets."
	out := renderPage(t, "search.html", true, pv)
	want := `content="Lightning Bolt prices across stores and buylists. Printed in many sets."`
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in rendered page, got:\n%s", want, out)
	}
}
