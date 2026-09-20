package main

import (
	"strings"
	"testing"
)

func TestSearchResultHoverAndInitialArt(t *testing.T) {
	out := renderPage(t, "search.html", false, sealedPage(nil))

	if !strings.Contains(out, `onmouseenter="hoverSidebar(`) {
		t.Error("search results do not use non-bubbling hover handlers")
	}
	if strings.Contains(out, `onmouseover="hoverSidebar(`) {
		t.Error("search results still use bubbling hover handlers")
	}
	cardBack := "/img/backs/" + Config.Game + ".webp"
	if !strings.Contains(out, cardBack) {
		t.Errorf("image-less first result does not seed the sidebar with %q", cardBack)
	}
}

func TestSearchInitialArtKeepsFirstResultMetadata(t *testing.T) {
	page := sealedPage(nil)
	page.AllKeys = []string{"first", "second"}
	page.Metadata = map[string]GenericCard{
		"first":  {Name: "First Product", SetCode: "ONE", Sealed: true},
		"second": {Name: "Second Product", SetCode: "TWO", Sealed: true, ImageURL: "second.jpg", Foil: true},
	}

	out := renderPage(t, "search.html", false, page)
	cardBack := "/img/backs/" + Config.Game + ".webp"
	start := strings.LastIndex(out, "updateSidebar(")
	end := strings.Index(out[start:], ");")
	if start < 0 || end < 0 {
		t.Fatal("rendered search page has no initial sidebar call")
	}
	call := out[start : start+end]
	if !strings.Contains(call, `"`+cardBack+`"`) || !strings.Contains(call, `"ONE"`) || strings.Contains(call, `"TWO"`) || strings.Contains(call, " true ") {
		t.Errorf("initial sidebar call used the wrong result metadata: %s", call)
	}
}
