package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/uploadsort"
)

// matchKeys is the sort keys of the printing name and edition match.
func matchKeys(t *testing.T, b *matcher.Backend, name, edition string, foil bool) uploadsort.Keys {
	t.Helper()
	id, err := b.Match(&matcher.InputCard{Name: name, Edition: edition, Foil: foil})
	if err != nil {
		t.Fatalf("%s (%s): %v", name, edition, err)
	}
	return uploadsort.For(b, id)
}

func TestUploadSortKeysOrderMagicPrintings(t *testing.T) {
	skipWithoutDatastore(t)
	t.Parallel()
	b := backend()

	// One color in Magic's order, then two, then none
	colors := []string{
		matchKeys(t, b, "Swords to Plowshares", "Ice Age", false).Color,
		matchKeys(t, b, "Counterspell", "Ice Age", false).Color,
		matchKeys(t, b, "Lightning Bolt", "Magic 2010", false).Color,
		matchKeys(t, b, "Lightning Helix", "Ravnica: City of Guilds", false).Color,
		matchKeys(t, b, "Sol Ring", "Commander 2021", false).Color,
	}
	for i := 1; i < len(colors); i++ {
		if colors[i-1] >= colors[i] {
			t.Errorf("colors out of order: %q", colors)
		}
	}

	alpha := matchKeys(t, b, "Lightning Bolt", "Limited Edition Alpha", false)
	m10 := matchKeys(t, b, "Lightning Bolt", "Magic 2010", false)
	if !strings.HasPrefix(alpha.Set, "1993-") || alpha.Set >= m10.Set {
		t.Errorf("Alpha's set key %q not before M10's %q", alpha.Set, m10.Set)
	}

	foil := matchKeys(t, b, "Lightning Bolt", "Magic 2010", true)
	if !strings.HasPrefix(m10.Finish, "0 ") || !strings.HasPrefix(foil.Finish, "1 ") {
		t.Errorf("finishes %q and %q, want nonfoil before foil", m10.Finish, foil.Finish)
	}

	// Rarest first, compared as numbers as the page does
	mythic := matchKeys(t, b, "Jace, the Mind Sculptor", "Worldwake", false)
	common := matchKeys(t, b, "Lightning Bolt", "Magic 2010", false)
	mythicRank, errM := strconv.Atoi(mythic.Rarity)
	commonRank, errC := strconv.Atoi(common.Rarity)
	if errM != nil || errC != nil || mythicRank >= commonRank {
		t.Errorf("mythic rank %q, common rank %q, want the mythic first", mythic.Rarity, common.Rarity)
	}
	if m10.Name != "lightning bolt" || m10.Number == "" {
		t.Errorf("name %q, number %q", m10.Name, m10.Number)
	}
}

// Another game's colors and rarities come from its own backend, with no list
// in this repository.
func TestUploadSortKeysFollowAnotherGamesOrder(t *testing.T) {
	t.Parallel()
	b := gameDatastore(t, "lorcana").backend
	if len(b.Colors) < 2 {
		t.Fatalf("lorcana lists colors %q", b.Colors)
	}

	byColor := map[string]string{}
	ranked := 0
	for id, co := range b.UUIDs {
		keys := uploadsort.For(b, id)
		if keys.Rarity != "" {
			ranked++
		}
		if len(co.Colors) == 1 && byColor[co.Colors[0]] == "" {
			byColor[co.Colors[0]] = keys.Color
		}
	}
	if ranked == 0 {
		t.Error("no lorcana printing has a ranked rarity")
	}
	first, second := byColor[b.Colors[0]], byColor[b.Colors[1]]
	if first == "" || second == "" || first >= second {
		t.Errorf("%s files as %q, %s as %q: want the game's order", b.Colors[0], first, b.Colors[1], second)
	}
}
