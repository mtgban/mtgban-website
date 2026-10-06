package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestRaritiesBelowRare pins what "only Rare/Mythic" leaves out: whatever the
// game ranks below rare, and nothing for a game that ranks no rare.
func TestRaritiesBelowRare(t *testing.T) {
	for _, tt := range []struct {
		order []string
		want  []string
	}{
		{[]string{"oversize", "special", "mythic", "rare", "uncommon", "common", "token"}, []string{"uncommon", "common", "token"}},
		{[]string{"Promo", "Starfoil Rare", "Rare", "Mosaic Rare", "Common"}, []string{"mosaicrare", "common"}},
		{[]string{"Legend Rare", "C+", "Common"}, nil},
	} {
		b := rarityBackend(mtgmatcher.GameMagic, tt.order, nil)
		got := raritiesBelow(b, "rare")
		if !slices.Equal(got, tt.want) {
			t.Errorf("raritiesBelow(%v) = %v, want %v", tt.order, got, tt.want)
		}
	}
}
