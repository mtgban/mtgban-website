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
	for _, game := range []mtgmatcher.Game{"../logo", "..", "../..", "/etc", "nosuchgame", ""} {
		t.Run(string(game), func(t *testing.T) {
			defer func(old mtgmatcher.Game) { Config().Game = old }(Config().Game)
			defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
			Config().Game = game
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
		entries, err := os.ReadDir("img/setsymbol/" + string(game))
		if err != nil || len(entries) == 0 {
			continue
		}

		defer func(old mtgmatcher.Game) { Config().Game = old }(Config().Game)
		defer func(old map[string]rarityBadge) { rarityBadges = old }(rarityBadges)
		Config().Game = game
		rarityBadges = map[string]rarityBadge{}

		loadRarityBadges()
		if len(rarityBadges) < 2 { // the fallback, plus at least one symbol
			t.Errorf("%s is registered and ships symbols, but loaded %d badges", game, len(rarityBadges))
		}
		return
	}
	t.Skip("no registered game ships set symbols in this checkout")
}

// Published symbols take precedence over glyphs and badges; sets without an
// image retain their existing rendering. Each case hands the partial its
// symbol the way a page's data does.
func TestSetSymbolImages(t *testing.T) {
	oldGame, oldBadges := Config().Game, rarityBadges
	t.Cleanup(func() { Config().Game, rarityBadges = oldGame, oldBadges })
	Config().Game = "onepiece"
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
			arg := map[string]any{"Keyrune": tc.keyrune, "Edition": "", "Code": tc.code, "Rarity": "", "Color": "var(--normal)", "Foil": false, "Symbol": tc.symbol, "Size": 20, "Class": "x"}
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

// The printings strip under a card draws each set through the same partial,
// inside a link titled with the set's name.
func TestCardPrintingsDrawTheSetSymbol(t *testing.T) {
	oldGame, oldBadges := Config().Game, rarityBadges
	t.Cleanup(func() { Config().Game, rarityBadges = oldGame, oldBadges })
	Config().Game = "onepiece"
	loadRarityBadges()

	for _, tc := range []struct {
		name   string
		set    mtgmatcher.Set
		want   []string
		absent []string
	}{
		{
			name: "keyrune set",
			set:  mtgmatcher.Set{Code: "PM10", Name: "Magic 2010 Promos", KeyruneCode: "M10"},
			want: []string{
				`href="/search?q=Bolt+s%3APM10"><i class="ss ss-m10 ss-2x ss-fw`,
				`data-mark="★"`,
			},
			absent: []string{`<img`, `<svg`},
		},
		{
			name: "symbol set",
			set:  mtgmatcher.Set{Code: "MA", Name: "EX Team Magma vs Team Aqua", Symbol: "https://example.com/ma.png"},
			want: []string{
				`<a class="printing-symbol" title="EX Team Magma vs Team Aqua"`,
				`<img class="set-symbol-art " src="https://example.com/ma.png" alt="MA" title="EX Team Magma vs Team Aqua"`,
				`<span hidden> <svg`,
				`>MA</text>`,
			},
			absent: []string{`title="MA"`, `class="ss `},
		},
		{
			name:   "bare set",
			set:    mtgmatcher.Set{Code: "PR-1840", Name: "Deck Exclusives"},
			want:   []string{`<svg`, `>PR-1840</text>`},
			absent: []string{`<img`, `class="ss `},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &mtgmatcher.Backend{Sets: map[string]*mtgmatcher.Set{tc.set.Code: &tc.set}}
			co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{Name: "Bolt", Printings: []string{tc.set.Code}}}

			got := strings.Join(strings.Fields(genCardPrintings(b, co)), " ")
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("%q missing %q", got, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("%q has %q", got, absent)
				}
			}
		})
	}
}

func TestSetSymbolMark(t *testing.T) {
	tmpl, err := tmplparse.ParseFiles("set-symbol.html", []string{"templates/partials/set-symbol.html"}, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ code, edition, want string }{
		{"PTHB", "Theros Beyond Death Promos", `data-mark="★"`},
		{"FBB", "Foreign Black Border", `data-mark="BB"`},
		{"THB", "Theros Beyond Death", ""},
	} {
		t.Run(tc.code, func(t *testing.T) {
			arg := map[string]any{"Keyrune": "ss-thb", "Edition": tc.edition, "Code": tc.code, "Rarity": "", "Color": "var(--normal)", "Foil": false, "Symbol": "", "Size": 20, "Class": ""}
			var b bytes.Buffer
			if err := tmpl.ExecuteTemplate(&b, "set-symbol", arg); err != nil {
				t.Fatal(err)
			}
			got := b.String()
			if tc.want == "" && strings.Contains(got, "data-mark") {
				t.Errorf("%q has a mark, want none", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("%q missing %q", got, tc.want)
			}
		})
	}
}
