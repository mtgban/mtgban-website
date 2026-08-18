package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestSplitIDPrefix(t *testing.T) {
	cases := []struct{ in, prefix, val string }{
		{"ban:123", "ban", "123"},
		{"tcg:454233", "tcg", "454233"},
		{"scryfall:abc-def-123", "scryfall", "abc-def-123"},
		{"mtgjson:7c3ea479-e463-58e7-b1b0-b217c77dae79", "mtgjson", "7c3ea479-e463-58e7-b1b0-b217c77dae79"},
		{"7c3ea479-e463-58e7-b1b0-b217c77dae79", "", "7c3ea479-e463-58e7-b1b0-b217c77dae79"},
		{"454233", "", "454233"},
		{"BAN:5", "ban", "5"}, // prefix is lowercased
	}
	for _, tc := range cases {
		p, v := splitIDPrefix(tc.in)
		if p != tc.prefix || v != tc.val {
			t.Errorf("splitIDPrefix(%q) = (%q, %q), want (%q, %q)", tc.in, p, v, tc.prefix, tc.val)
		}
	}
}

// The finish shapes below are the ones Lorcana actually ships, paired with the
// sub-types tcgcsv prices those products under: a plain foil sold as "Cold
// Foil", one sold as "Holofoil" (LorcanaJSON's FreeForm1 printings), a card
// with an extra foil sub-type on top of both, a foil-only card, and a card
// whose foil has no listing yet.
var tcgFinishCases = []struct {
	name     string
	subTypes []string          // what the product is priced under
	finishes map[string]string // mtgmatcher finish -> uuid
	want     map[string]string // uuid -> sub-type ("" = no data for that finish)
	unmapped []string          // sub-types the card has no finish for
}{
	{
		name:     "primary foil sold as cold foil",
		subTypes: []string{"Normal", "Cold Foil"},
		finishes: map[string]string{"nonfoil": "2790", "foil": "2790_f"},
		want:     map[string]string{"2790": "Normal", "2790_f": "Cold Foil"},
	},
	{
		name:     "primary foil sold as holofoil",
		subTypes: []string{"Normal", "Holofoil"},
		finishes: map[string]string{"nonfoil": "2206", "foil": "2206_f"},
		want:     map[string]string{"2206": "Normal", "2206_f": "Holofoil"},
	},
	{
		name:     "extra foil sub-type",
		subTypes: []string{"Normal", "Cold Foil", "Holofoil"},
		finishes: map[string]string{"nonfoil": "2800", "foil": "2800_f", "rainbowpillars": "2800_rainbowpillars"},
		want:     map[string]string{"2800": "Normal", "2800_f": "Cold Foil", "2800_rainbowpillars": "Holofoil"},
	},
	{
		// The product is priced under one more foil than the card has finishes,
		// so nothing maps to "Holofoil" in either direction. Mapping it onto the
		// plain foil would give a roster carrying both variants two rows for the
		// same printing.
		name:     "extra sub-type the card has no finish for",
		subTypes: []string{"Normal", "Cold Foil", "Holofoil"},
		finishes: map[string]string{"nonfoil": "2810", "foil": "2810_f"},
		want:     map[string]string{"2810": "Normal", "2810_f": "Cold Foil"},
		unmapped: []string{"Holofoil"},
	},
	{
		name:     "foil-only card",
		subTypes: []string{"Holofoil"},
		finishes: map[string]string{"foil": "2937"},
		want:     map[string]string{"2937": "Holofoil"},
	},
	{
		name:     "foil not priced yet",
		subTypes: []string{"Normal"},
		finishes: map[string]string{"nonfoil": "2900", "foil": "2900_f"},
		want:     map[string]string{"2900": "Normal", "2900_f": ""},
	},
	{
		name:     "single foil sub-type, as riftbound names it",
		subTypes: []string{"Normal", "Foil"},
		finishes: map[string]string{"nonfoil": "abc_nonfoil", "foil": "abc_foil"},
		want:     map[string]string{"abc_nonfoil": "Normal", "abc_foil": "Foil"},
	},
}

// foilSubTypes and extraFoilFinishes pair positionally over two sorted lists,
// so the mapping is only right while the primary foil's sub-type sorts before
// the extras' on the same product. That is a property of the names, not of the
// data, and a name breaking it would re-pair a product's finishes with nothing
// else failing. These are the names TCGplayer prices our games under; a new one
// belongs here, where the order is checked.
func TestFoilSubTypeOrdering(t *testing.T) {
	primaries := []string{"Cold Foil", "Foil"} // Lorcana, Riftbound
	extras := []string{"Holofoil"}             // what Lorcana's extra foils are sold as
	for _, primary := range primaries {
		for _, extra := range extras {
			if primary >= extra {
				t.Errorf("primary foil sub-type %q does not sort before extra sub-type %q; "+
					"the positional pairing in foilSubTypes would swap them", primary, extra)
			}
		}
	}
}

// A non-Magic product is priced per finish under a sub-type, so a card's finish
// has to pick its own variant — otherwise every finish charts the product's
// canonical ("Normal") prices (issue #295).
func TestTCGSubTypeForCard(t *testing.T) {
	for _, tc := range tcgFinishCases {
		subTypes := map[string]int64{}
		for i, subType := range tc.subTypes {
			subTypes[subType] = int64(i + 1)
		}
		for finish, uuid := range tc.finishes {
			co := &mtgmatcher.CardObject{
				Card: mtgmatcher.Card{UUID: uuid, FoilUUIDs: tc.finishes},
				Foil: finish != "nonfoil",
			}
			if got := tcgSubTypeForCard(co, subTypes); got != tc.want[uuid] {
				t.Errorf("%s: tcgSubTypeForCard(%s) = %q, want %q", tc.name, finish, got, tc.want[uuid])
			}
		}
	}
}

// And back: charting a variant has to land on the card row of the finish its
// sub-type names, not on the product's base printing.
func TestTCGFinishIDForSubType(t *testing.T) {
	for _, tc := range tcgFinishCases {
		subTypes := map[string]int64{}
		for i, subType := range tc.subTypes {
			subTypes[subType] = int64(i + 1)
		}
		// The card mtgmatcher resolves a bare product id to, as the callers get it.
		base := tc.finishes["nonfoil"]
		if base == "" {
			base = tc.finishes["foil"]
		}
		co := &mtgmatcher.CardObject{
			Card: mtgmatcher.Card{UUID: base, FoilUUIDs: tc.finishes},
		}
		for uuid, subType := range tc.want {
			if subType == "" {
				continue // no variant to chart
			}
			if got := tcgFinishIDForSubType(co, subTypes, subType); got != uuid {
				t.Errorf("%s: tcgFinishIDForSubType(%q) = %q, want %q", tc.name, subType, got, uuid)
			}
		}
		// And the other half of the symmetry: a sub-type the card has no finish
		// for maps to nothing, rather than landing on the primary foil.
		for _, subType := range tc.unmapped {
			if got := tcgFinishIDForSubType(co, subTypes, subType); got != "" {
				t.Errorf("%s: tcgFinishIDForSubType(%q) = %q, want no id", tc.name, subType, got)
			}
		}
	}
}

// A ban_id names one finish, but the variants table stores the finish next to
// the base uuid, so handing that uuid straight to the search used to render the
// nonfoil row for a foil chart (issue #295).
func TestMagicFinishSearchID(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}

	// Any printing that carries both finishes will do.
	var uuid, foilId string
	for _, id := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(id)
		if err != nil || co.Sealed || co.Foil || co.Etched {
			continue
		}
		alt, err := mtgmatcher.MatchId(id, true)
		if err != nil || alt == id {
			continue
		}
		if altCo, err := mtgmatcher.GetUUID(alt); err == nil && altCo.Foil {
			uuid, foilId = id, alt
			break
		}
	}
	if uuid == "" {
		t.Skip("no card with both a foil and a nonfoil printing")
	}

	if got := magicFinishSearchID(uuid, true, false); got != foilId {
		t.Errorf("magicFinishSearchID(%q, foil) = %q, want %q", uuid, got, foilId)
	}
	if got := magicFinishSearchID(uuid, false, false); got != uuid {
		t.Errorf("magicFinishSearchID(%q, nonfoil) = %q, want %q", uuid, got, uuid)
	}
}
