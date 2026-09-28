package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// renderPage runs one page the way the server does.
func renderPage(t *testing.T, name string, mobile bool, pv PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles(name, mobile)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing %s (mobile=%v): %v", name, mobile, err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, baseName, pv); err != nil {
		t.Fatalf("rendering %s (mobile=%v): %v", name, mobile, err)
	}
	return b.String()
}

// gamePage is the page data genPageNav builds for a deployment of game. The
// config is back to what it was before anything renders, so a page naming
// the game can only have read it from its data.
func gamePage(game string, mobile bool) PageVars {
	prev := Config.Game
	defer func() { Config.Game = prev }()
	Config.Game = game
	pv := genPageNav(testSite, nil, "Search", "")
	pv.IsMobile = mobile
	return pv
}

// The card-corner rules key on the set a card belongs to, which cannot say
// "every card in this game". Yu-Gi-Oh needs that, so the body carries the game
// for CSS to select on - and it has to be on every base template, since a page
// rendered through one that lacks it would round its cards.
func TestBodyCarriesTheGame(t *testing.T) {
	for _, page := range []struct {
		name   string
		mobile bool
	}{
		{"search.html", false}, // base.html
		{"home.html", false},   // base-landing.html
		{"search.html", true},  // base-mobile.html
	} {
		for _, game := range []string{"yugioh", DefaultGame} {
			rendered := renderPage(t, page.name, page.mobile, gamePage(game, page.mobile))

			body := rendered[strings.Index(rendered, "<body"):]
			body = body[:strings.Index(body, ">")+1]
			if want := `data-game="` + game + `"`; !strings.Contains(body, want) {
				t.Errorf("%s (mobile=%v), game %q: body is %q, want it to carry %s",
					page.name, page.mobile, game, body, want)
			}
		}
	}
}
