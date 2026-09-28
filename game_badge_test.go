package main

import (
	"strings"
	"testing"
)

// The wordmark reads MTGBAN on every deployment, so a non-Magic site names
// the game it serves under it - on the landing page and on the navbar that
// carries the search bar. Magic keeps the bare wordmark.
func TestBrandNamesTheGame(t *testing.T) {
	for _, page := range []struct {
		name   string
		mobile bool
		// badge is the class the game rides on for this page's brand.
		badge string
	}{
		{"home.html", false, "landing-brand-game"},
		{"search.html", false, "nav2-brand-game"},
		{"home.html", true, "m-home-brand-game"},
		{"search.html", true, "m-nav-logo-game"},
	} {
		rendered := renderPage(t, page.name, page.mobile, gamePage("onepiece", page.mobile))

		want := `class="` + page.badge + `">One Piece<`
		if !strings.Contains(rendered, want) {
			t.Errorf("%s (mobile=%v): brand does not carry %s", page.name, page.mobile, want)
		}

		rendered = renderPage(t, page.name, page.mobile, gamePage(DefaultGame, page.mobile))
		if strings.Contains(rendered, page.badge) {
			t.Errorf("%s (mobile=%v): magic renders a %s badge, want the wordmark alone",
				page.name, page.mobile, page.badge)
		}
	}
}

// A game with no gameBadgeMap entry renders the wordmark with nothing under
// it, which reads as the Magic site to anyone who lands on it.
func TestEveryRegisteredGameHasABadge(t *testing.T) {
	for _, game := range registeredGames {
		got := gamePage(game, false).GameBadge
		if game == DefaultGame {
			if got != "" {
				t.Errorf("game %q is badged %q, want the bare wordmark", game, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("game %q has no gameBadgeMap entry", game)
		}
	}
}
