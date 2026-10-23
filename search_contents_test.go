package main

import (
	"regexp"
	"strings"
	"testing"
)

func contentsPageVars(lines []ContentLine, more int) PageVars {
	return PageVars{
		SearchVars: SearchVars{
			SearchRan: true,
			AllKeys:   []string{"p1"},
		},
		Metadata: cardMetadata{"p1": GenericCard{
			UUID: "p1", Name: "Some Commander Deck", Edition: "Some Set", Title: "Some Set",
			Sealed: true, HasDeck: true, Contents: lines, ContentsMore: more,
		}},
	}
}

func TestSearchResultListsAProductsContents(t *testing.T) {
	lines := []ContentLine{
		{Name: "Sol Ring", Link: "/search?q=uuid-sol", Price: 1.2},
		{Count: 2, Name: "Collector Booster", Link: "/sealed?q=uuid-cb"},
	}
	for _, tc := range []struct {
		name, out, sep, price, more string
	}{
		{"desktop", renderDesktopSearch(t, contentsPageVars(lines, 3)), `class="result-contents-sep"`, `class="result-contents-price" title="TCG Market">$1.20<`, `+3 more`},
		{"mobile", renderMobileSearch(t, contentsPageVars(lines, 3)), `class="m-card-contents-sep"`, `class="m-card-contents-price" title="TCG Market">$1.20<`, `+3 more`},
	} {
		for _, want := range []string{tc.sep, tc.price, tc.more, `href="/search?q=uuid-sol"`, `2x Collector Booster`, `href="/sealed?q=uuid-cb"`, `decklist:"Some%20Commander%20Deck"`} {
			if !strings.Contains(tc.out, want) {
				t.Errorf("%s lacks %q", tc.name, want)
			}
		}
		if strings.Count(tc.out, tc.sep) != 1 {
			t.Errorf("%s: %d separators for two lines", tc.name, strings.Count(tc.out, tc.sep))
		}
	}
}

func TestSearchResultContentsWithoutRemainderOrPrice(t *testing.T) {
	lines := []ContentLine{{Count: 36, Name: "Play Booster"}}
	for _, out := range []string{renderDesktopSearch(t, contentsPageVars(lines, 0)), renderMobileSearch(t, contentsPageVars(lines, 0))} {
		if !strings.Contains(out, ">Contents</a>") || strings.Contains(out, "more<") {
			t.Error("a complete list does not say Contents")
		}
		if strings.Contains(out, "TCG Market") {
			t.Error("a pack line carries a price")
		}
		if !strings.Contains(out, "36x Play Booster") {
			t.Error("the pack line is missing")
		}
	}
}

func TestSearchResultWithoutContentsDrawsNoList(t *testing.T) {
	for _, out := range []string{renderDesktopSearch(t, contentsPageVars(nil, 0)), renderMobileSearch(t, contentsPageVars(nil, 0))} {
		if strings.Contains(out, "result-contents") || strings.Contains(out, "m-card-contents") || strings.Contains(out, ">Contents</a>") {
			t.Error("an empty list still drew the contents block")
		}
	}
}

// The more link sits after the clamped span, or the clamp hides it.
func TestMobileContentsMoreLinkIsOutsideTheClampedSpan(t *testing.T) {
	lines := []ContentLine{{Count: 1, Name: "Sol Ring", Link: "/search?q=uuid-sol"}, {Count: 36, Name: "Play Booster"}}
	out := renderMobileSearch(t, contentsPageVars(lines, 3))
	if !regexp.MustCompile(`</span>\s*<a class="m-card-contents-more"`).MatchString(out) {
		t.Error("the more link is not a sibling after the contents span")
	}
}
