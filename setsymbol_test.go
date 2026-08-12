package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// TestBadgeFilesParse reads every drawing under img/setsymbol the way the
// server does at startup. A malformed one degrades quietly there — the badge
// falls back to a circle — so it fails here instead.
func TestBadgeFilesParse(t *testing.T) {
	var files []string
	err := filepath.WalkDir("img/setsymbol", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".svg") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no set symbols found")
	}

	for _, path := range files {
		badge, err := readBadge(path)
		if err != nil {
			t.Errorf("%s: %s", path, err)
			continue
		}
		t.Logf("%-40s font %4.1f  y %4.1f", path, badge.Font, badge.TextY)
	}
}

// TestSetSymbolBlock runs the block every page draws its set symbol through,
// over the cases the pages used to branch on themselves.
func TestSetSymbolBlock(t *testing.T) {
	game := Config.Game
	defer func() { Config.Game = game }()
	Config.Game = "onepiece"
	loadRarityBadges()

	tmpl, err := tmplparse.ParseFiles("base.html", []string{"templates/base.html"}, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	paint := func(arg map[string]any) string {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, "set-symbol", arg); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}

	edition := func(keyrune, code string) map[string]any {
		return map[string]any{"Keyrune": keyrune, "Code": code, "Rarity": "",
			"Color": "var(--normal)", "Foil": false, "Size": 20, "Class": "x"}
	}
	card := func(keyrune, code, rarity, color string, foil bool) map[string]any {
		return map[string]any{"Keyrune": keyrune, "Code": code, "Rarity": rarity,
			"Color": color, "Foil": foil, "Size": 20, "Class": "x"}
	}

	for _, tc := range []struct {
		name, want string
		arg        map[string]any
	}{
		{"magic card", `<i class="ss ss-lea ss-rare ss-1x ss-fw x">`, card("ss-lea ss-rare", "LEA", "rare", "", false)},
		{"magic edition", `<i class="ss ss-lea ss-1x ss-fw x">`, edition("ss-lea", "LEA")},
		{"onepiece card", `font-size="5.5"`, card("", "ST-01", "C", "var(--normal)", false)},
		{"onepiece foil", `url(#gradient-foil)`, card("", "OP01", "R", "#B06435", true)},
		{"onepiece edition", `>OP01</text>`, edition("", "OP01")},
		{"unmapped rarity", "", card("", "XYZ", "nope", "", false)},
	} {
		got := paint(tc.arg)
		if tc.want == "" {
			if got != "" {
				t.Errorf("%s: want nothing, got %q", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q missing %q", tc.name, got, tc.want)
		}
		t.Logf("%-18s %s", tc.name, got)
	}

	// A deployment with no drawings is a keyrune one, and keeps the font's
	// fallback glyph for a set the font does not know.
	loaded := rarityBadges
	rarityBadges = map[string]rarityBadge{}
	defer func() { rarityBadges = loaded }()

	for _, arg := range []map[string]any{card("", "XYZ", "", "", false), edition("", "XYZ")} {
		got := paint(arg)
		if !strings.Contains(got, `<i class="ss`) {
			t.Errorf("no drawings loaded: got %q, want the keyrune fallback", got)
		}
		t.Logf("%-18s %s", "no drawings", got)
	}
}
