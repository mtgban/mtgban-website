package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// renderSearch runs a search page the way the server does, so what the page
// hands the recent-searches script is exercised rather than only parsed.
func renderSearch(t *testing.T, template string, pageVars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles(template, strings.HasPrefix(template, "mobile/"))
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing %s: %v", template, err)
	}
	pageVars.BetaNav = &NavElem{}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, baseName, pageVars); err != nil {
		t.Fatalf("rendering %s: %v", template, err)
	}
	return b.String()
}

// A search that found nothing says so, and the recent list drops it on that
// word alone - the page is the only thing that knows.
func TestTheSearchPageSaysWhetherItFoundAnything(t *testing.T) {
	for _, template := range []string{"search.html", "mobile/search.html"} {
		found := renderSearch(t, template, PageVars{
			SearchQuery: "Lightning Bolt",
			CardHashes:  []string{"some-uuid"},
		})
		if !strings.Contains(found, "found: true") {
			t.Errorf("%s: a page with results does not report found: true", template)
		}

		empty := renderSearch(t, template, PageVars{
			SearchQuery: "Lightning Bolt",
			InfoMessage: NoResultsMessage,
		})
		if !strings.Contains(empty, "found: false") {
			t.Errorf("%s: a page with no results does not report found: false", template)
		}
	}
}

// A uuid search is rebuilt into the card's own name, set and number, and that
// is the label the recent list gets. An ordinary search is already readable,
// so it carries itself.
func TestTheSearchPageHandsOverTheReadableQuery(t *testing.T) {
	for _, template := range []string{"search.html", "mobile/search.html"} {
		out := renderSearch(t, template, PageVars{
			SearchQuery: "Plaguecrafter s:SLD cn:1116jpn f:nonfoil",
			CardHashes:  []string{"some-uuid"},
		})
		if !strings.Contains(out, `label: "Plaguecrafter s:SLD cn:1116jpn f:nonfoil"`) {
			t.Errorf("%s: the rebuilt query is not handed to the recent list", template)
		}
	}
}

// The label rides through Go's JS escaping, so a name carrying a quote cannot
// end the string it sits in.
func TestTheReadableQueryCannotBreakOutOfItsString(t *testing.T) {
	out := renderSearch(t, "search.html", PageVars{
		SearchQuery: `Hero's Downfall" ; alert(1); "`,
		CardHashes:  []string{"some-uuid"},
	})
	if !strings.Contains(out, `label: "Hero's Downfall\" ; alert(1); \"",`) {
		t.Error("a quote in the query did not survive as an escaped quote")
	}
}
