package main

import (
	"strings"
	"testing"
)

// The setting that picks which reading a product's link opens is offered on
// the desktop settings panel; the mobile drawer has its own markup and its own
// cookie wiring, and had neither.
func TestMobileSettingsOfferSealedContents(t *testing.T) {
	// The drawer's markup sits in the results block, its cookie wiring in the
	// page around it, so each is read from where it lives.
	drawer := renderMobileSearch(t, sealedPageVars("expanded", "abc"))
	for _, want := range []string{
		`id="m-set-sealed-contents"`,
		`data-val="contents"`,
		`data-val="decklist"`,
		`data-val="variable"`,
	} {
		if !strings.Contains(drawer, want) {
			t.Errorf("mobile settings drawer lacks %s", want)
		}
	}

	page := renderPage(t, "search.html", true, PageVars{BetaNav: &NavElem{Short: "b"}, IsMobile: true})
	for _, want := range []string{
		`getCookie('SearchSealedContents')`,
		`setCookie('SearchSealedContents'`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("mobile settings script lacks %s", want)
		}
	}
}
