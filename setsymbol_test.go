package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// The set-symbol directory is named for the game, and that name is written by
// whoever edits the config. Only a game the matcher registers may name one.
//
// What the old code did with a climbing name is worth stating exactly, because
// it is narrower than the shape of the bug suggests: it read every .svg in
// whatever directory the name reached - img/logo holds two - but only files
// parsing as a badge were ever filed, and a logo is not one. So this closes an
// arbitrary .svg read rather than a demonstrated leak, and the one case below
// whose behaviour visibly changes is the empty name, which used to file
// img/setsymbol/default.svg a second time under "default".
func TestSetSymbolsOnlyReadUnderTheirOwnDirectory(t *testing.T) {
	for _, game := range []string{"../logo", "..", "../..", "/etc", "nosuchgame", ""} {
		t.Run(game, func(t *testing.T) {
			defer func(old string) { Config.Game = old }(Config.Game)
			defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
			Config.Game = game
			rarityBadges = map[string]rarityBadge{}

			loadRarityBadges()

			for key := range rarityBadges {
				// The "" fallback comes from a fixed path and is always fine.
				if key != "" {
					t.Errorf("game %q filed a badge %q read from outside its directory", game, key)
				}
			}
		})
	}
}

// A game that is registered still reads its own symbols.
func TestSetSymbolsLoadForARegisteredGame(t *testing.T) {
	for _, game := range mtgmatcher.RegisteredGames() {
		if game == DefaultGame {
			continue // the default returns before reading a directory
		}
		entries, err := os.ReadDir("img/setsymbol/" + game)
		if err != nil || len(entries) == 0 {
			continue
		}

		defer func(old string) { Config.Game = old }(Config.Game)
		defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
		Config.Game = game
		rarityBadges = map[string]rarityBadge{}

		loadRarityBadges()
		if len(rarityBadges) < 2 { // the fallback, plus at least one symbol
			t.Errorf("%s is registered and ships symbols, but loaded %d badges", game, len(rarityBadges))
		}
		return
	}
	t.Skip("no registered game ships set symbols in this checkout")
}

// A card and an edition carry the badge the partial draws, already fitted to
// their set code, so no page asks the rarity table for one as it renders: a
// card the drawing of its own rarity, an edition the default circle.
func TestCardDataCarriesTheBadge(t *testing.T) {
	oldGame, oldBadges := Config.Game, rarityBadges
	t.Cleanup(func() { Config.Game, rarityBadges = oldGame, oldBadges })

	for _, tc := range []struct {
		game, rarity, drawing string
	}{
		// One Piece draws its circle for every rarity
		{"onepiece", "SR", ""},
		// Lorcana draws a rare a shape of its own
		{"lorcana", "rare", "rare"},
	} {
		Config.Game = tc.game
		rarityBadges = map[string]rarityBadge{}
		loadRarityBadges()
		circle := fitCode(rarityBadges[""], "TST")
		want := fitCode(rarityBadges[tc.drawing], "TST")
		if want.Path == "" {
			t.Fatalf("%s loaded no %q drawing", tc.game, tc.drawing)
		}
		if tc.drawing != "" && want == circle {
			t.Fatalf("%s draws a %s as its default circle", tc.game, tc.rarity)
		}

		b := fixtureBackend("TST", "Test Set", "2024-01-01", [][2]string{{"Test Card", "1"}})
		b.UUIDs["TST-1"].Rarity = tc.rarity
		got := uuid2card(b, "TST-1", true, false, false).Badge
		if got != want {
			t.Errorf("%s card badge = %+v, want %+v", tc.game, got, want)
		}
		set, err := b.GetSet("TST")
		if err != nil {
			t.Fatal(err)
		}
		got = makeEditionEntry(set).Badge
		if got != circle {
			t.Errorf("%s edition badge = %+v, want the circle's %+v", tc.game, got, circle)
		}

		// A card the datastore does not know still carries a drawing, so its
		// symbol stays blank rather than falling back to an empty glyph.
		got = uuid2card(b, "TST-9", true, false, false).Badge
		if got != fitCode(rarityBadges[""], "") {
			t.Errorf("%s unknown card badge = %+v, want the uncoded circle", tc.game, got)
		}
	}
}

// Published symbols take precedence over glyphs and badges; sets without an
// image retain their existing rendering. Each case hands the partial its
// symbol and badge the way a page's data does.
func TestSetSymbolImages(t *testing.T) {
	oldGame, oldBadges := Config.Game, rarityBadges
	t.Cleanup(func() { Config.Game, rarityBadges = oldGame, oldBadges })
	Config.Game = "onepiece"
	rarityBadges = map[string]rarityBadge{}
	loadRarityBadges()
	tmpl, err := tmplparse.ParseFiles("set-symbol.html", []string{"templates/partials/set-symbol.html"}, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	const sviSymbol = "https://assets.tcgdex.net/univ/sv/sv01/symbol.webp"
	for _, tc := range []struct{ name, code, keyrune, symbol, want string }{
		{"symbol card", "SVI", "", sviSymbol, `src="https://assets.tcgdex.net/univ/sv/sv01/symbol.webp"`},
		{"symbol sized", "SVI", "", sviSymbol, `width="20" height="20"`},
		{"symbol keeps code", "SVI", "", sviSymbol, `alt="SVI"`},
		{"symbol precedes glyph", "SVI", "ss-svi", sviSymbol, `class="set-symbol-art`},
		{"no symbol still badges", "OP01", "", "", `>OP01</text>`},
		{"no symbol keeps glyph", "LEA", "ss-lea", "", `<i class="ss ss-lea`},
		// A published symbol's address is the vendor's to move, and it did:
		// every Pokemon symbol 404ed for nine days once. onerror falls the
		// image back to a hidden copy of the same glyph a set with none at
		// all would show, rather than an empty box.
		{"symbol has a fallback for a failed load", "SVI", "", sviSymbol, `onerror="this.style.display='none';this.nextElementSibling.hidden=false;"`},
		{"symbol's fallback is hidden", "SVI", "", sviSymbol, `<span hidden>`},
		{"symbol's fallback is the same glyph a bare set would draw", "SVI", "ss-svi", sviSymbol, `<span hidden> <i class="ss ss-svi`},
		{"symbol's fallback badges too, where a bare set would", "SVI", "", sviSymbol, `<span hidden> <svg`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arg := map[string]any{"Keyrune": tc.keyrune, "Code": tc.code, "Badge": rarityBadgeFor("", tc.code), "Color": "var(--normal)", "Foil": false, "Symbol": tc.symbol, "Size": 20, "Class": "x"}
			var b bytes.Buffer
			if err := tmpl.ExecuteTemplate(&b, "set-symbol", arg); err != nil {
				t.Fatal(err)
			}
			got := strings.Join(strings.Fields(b.String()), " ")
			if !strings.Contains(got, tc.want) {
				t.Errorf("%q missing %q", got, tc.want)
			}
		})
	}
}
