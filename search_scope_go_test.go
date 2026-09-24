package main

import (
	"strings"
	"testing"
)

// orderInBar reports where each of the three controls sits in the rendered
// bar. A control that is missing comes back as -1, which fails the ordering
// below rather than passing it by accident.
func orderInBar(out string) (boxAt, goAt, clearAt int) {
	return strings.Index(out, `id="nav-scopebox"`),
		strings.Index(out, `id="nav-scope-go"`),
		strings.Index(out, `id="nav-scope-clear"`)
}

// GO belongs between the box and CLEAR: the one that acts on what was typed,
// then the one that throws it away. Drawn on every surface that draws the bar
// at all - the desktop navbar, and both of the mobile page's own copies.
func TestScopeGoSitsBetweenTheBoxAndClear(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mobile   bool
		pageVars PageVars
	}{
		{"desktop navbar", false, PageVars{}},
		{"mobile, before a search", true, PageVars{}},
		// SearchRan is what puts the mobile page on its results surface,
		// which draws a bar of its own - so this reaches the second copy
		// rather than rendering the first one twice.
		{"mobile, over results", true, PageVars{SearchQuery: "bolt", SearchRan: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.pageVars.BetaNav = &NavElem{Short: "b"}
			tc.pageVars.CanScope = true

			out := renderPage(t, "search.html", tc.mobile, tc.pageVars)
			boxAt, goAt, clearAt := orderInBar(out)

			if boxAt < 0 || goAt < 0 || clearAt < 0 {
				t.Fatalf("the bar is missing a control: box=%d go=%d clear=%d", boxAt, goAt, clearAt)
			}
			if !(boxAt < goAt && goAt < clearAt) {
				t.Errorf("the controls run box=%d go=%d clear=%d, want GO between the other two",
					boxAt, goAt, clearAt)
			}
		})
	}
}

// The bar is drawn only where a search can be run from it, so the button it
// gained is drawn on the same terms rather than on its own.
func TestScopeGoIsDrawnOnlyWithTheBar(t *testing.T) {
	out := renderPage(t, "search.html", false, PageVars{BetaNav: &NavElem{Short: "b"}})

	if strings.Contains(out, `id="nav-scope-go"`) {
		t.Error("the GO button is drawn on a page that has no pinned bar to run")
	}
}

// The shortcuts under the bar are finishes, which is what the label says now.
func TestScopeChipsAreLabelledForWhatTheyAre(t *testing.T) {
	out := renderPage(t, "search.html", false, PageVars{
		BetaNav:  &NavElem{Short: "b"},
		CanScope: true,
	})

	if !strings.Contains(out, `<span class="nav2-scope-label">Fill</span>`) {
		t.Error("the chip row is not labelled Fill")
	}
	if strings.Contains(out, `<span class="nav2-scope-label">Common</span>`) {
		t.Error("the chip row still carries the label that said how often they are used")
	}
}
