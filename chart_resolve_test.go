package main

import (
	"slices"
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

// printings orders a case's finishes the way FinishSiblings does - the shared
// ones first, then the game's own vocabulary sorted - so a fixture written as a
// finish map can drive the pairing, which walks printings rather than names.
func printings(finishes map[string]string) []printingFinish {
	var out []printingFinish
	for _, finish := range []string{mtgmatcher.FinishNonfoil, mtgmatcher.FinishFoil, mtgmatcher.FinishEtched} {
		uuid, ok := finishes[finish]
		if ok {
			out = append(out, printingFinish{Finish: finish, Treatment: finish, UUID: uuid})
		}
	}
	var extra []string
	for finish := range finishes {
		switch finish {
		case mtgmatcher.FinishNonfoil, mtgmatcher.FinishFoil, mtgmatcher.FinishEtched:
			continue
		}
		extra = append(extra, finish)
	}
	slices.Sort(extra)
	for _, finish := range extra {
		out = append(out, printingFinish{Finish: finish, Treatment: finish, UUID: finishes[finish]})
	}
	return out
}

// foilSubTypes and the foil printings pair positionally over two sorted lists,
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
			got := subTypeForPrinting(printings(tc.finishes), uuid, subTypes)
			if got != tc.want[uuid] {
				t.Errorf("%s: subTypeForPrinting(%s) = %q, want %q", tc.name, finish, got, tc.want[uuid])
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
		for uuid, subType := range tc.want {
			if subType == "" {
				continue // no variant to chart
			}
			got := printingForSubType(printings(tc.finishes), subTypes, subType, base)
			if got != uuid {
				t.Errorf("%s: printingForSubType(%q) = %q, want %q", tc.name, subType, got, uuid)
			}
		}
		// And the other half of the symmetry: a sub-type the card has no finish
		// for maps to nothing, rather than landing on the primary foil.
		for _, subType := range tc.unmapped {
			got := printingForSubType(printings(tc.finishes), subTypes, subType, base)
			if got != "" {
				t.Errorf("%s: printingForSubType(%q) = %q, want no id", tc.name, subType, got)
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
	var uuid, foilID string
	for _, id := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(id)
		if err != nil || co.Sealed || co.Foil || co.Etched {
			continue
		}
		alt, err := mtgmatcher.MatchID(id, true)
		if err != nil || alt == id {
			continue
		}
		if altCo, err := mtgmatcher.GetUUID(alt); err == nil && altCo.Foil {
			uuid, foilID = id, alt
			break
		}
	}
	if uuid == "" {
		t.Skip("no card with both a foil and a nonfoil printing")
	}

	if got := magicFinishSearchID(uuid, true, false); got != foilID {
		t.Errorf("magicFinishSearchID(%q, foil) = %q, want %q", uuid, got, foilID)
	}
	if got := magicFinishSearchID(uuid, false, false); got != uuid {
		t.Errorf("magicFinishSearchID(%q, nonfoil) = %q, want %q", uuid, got, uuid)
	}
}

// fabPrintings is the shape mtgmatcher/fleshandblood produces for a product
// sold in Normal + Rainbow Foil, as FinishSiblings lists it: one entry per
// printing, each naming its own treatment. FoilUUIDs holds the same two
// printings under four names - the generic pair as well as the treatments -
// and it was counting those names that put "normal" among the foil finishes
// and paired every Flesh and Blood foil one place along.
var fabPrintings = []printingFinish{
	{Finish: "normal", Treatment: "normal", UUID: "omn071_695162"},
	{Finish: "rainbowfoil", Treatment: "rainbowfoil", UUID: "omn071_695162_rainbow"},
}

// A finish whose own name is the sub-type's name resolves by name.
func TestSubTypeForPrintingByName(t *testing.T) {
	subTypes := map[string]int64{"Normal": 1001, "Rainbow Foil": 1002}

	tests := []struct{ name, uuid, want string }{
		{"rainbow foil", "omn071_695162_rainbow", "Rainbow Foil"},
		{"nonfoil", "omn071_695162", "Normal"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := subTypeForPrinting(fabPrintings, test.uuid, subTypes)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// Lorcana keeps the positional pairing: "Holofoil" does not name the finish
// ("rainbowpillars") the way Flesh and Blood's treatments name theirs, so the
// foil printings pair against the foil sub-types in order.
func TestSubTypeForPrintingPositionalFallback(t *testing.T) {
	subTypes := map[string]int64{"Normal": 1, "Cold Foil": 2, "Holofoil": 3}
	lorcana := []printingFinish{
		{Finish: mtgmatcher.FinishNonfoil, Treatment: mtgmatcher.FinishNonfoil, UUID: "1459"},
		{Finish: mtgmatcher.FinishFoil, Treatment: mtgmatcher.FinishFoil, UUID: "1459_f"},
		{Finish: "rainbowpillars", Treatment: "rainbowpillars", UUID: "1459_rainbowpillars"},
	}

	got := subTypeForPrinting(lorcana, "1459_rainbowpillars", subTypes)
	if got != "Holofoil" {
		t.Errorf("got %q, want \"Holofoil\"", got)
	}

	got = subTypeForPrinting(lorcana, "1459_f", subTypes)
	if got != "Cold Foil" {
		t.Errorf("primary foil: got %q, want \"Cold Foil\"", got)
	}
}

// Yu-Gi-Oh prices print runs rather than finishes, so its products carry no
// "Normal" sub-type and no foil one either. Resolution comes from the names.
func TestSubTypeForPrintingPrintRuns(t *testing.T) {
	subTypes := map[string]int64{"1st Edition": 1, "Unlimited": 2, "Limited": 3}
	yugioh := []printingFinish{
		{Finish: "1stedition", Treatment: "1stedition", UUID: "hac1-en105_265004_1e"},
		{Finish: "limited", Treatment: "limited", UUID: "hac1-en105_265004_ltd"},
		{Finish: "unlimited", Treatment: "unlimited", UUID: "hac1-en105_265004_unl"},
	}

	got := subTypeForPrinting(yugioh, "hac1-en105_265004_1e", subTypes)
	if got != "1st Edition" {
		t.Errorf("got %q, want \"1st Edition\"", got)
	}

	got = subTypeForPrinting(yugioh, "hac1-en105_265004_unl", subTypes)
	if got != "Unlimited" {
		t.Errorf("got %q, want \"Unlimited\"", got)
	}
}

// A game whose sub-types are the generic finish names keeps the positional
// pairing: nothing about "Normal" or "Foil" names a printing on its own.
func TestSubTypeForPrintingGenericNames(t *testing.T) {
	subTypes := map[string]int64{"Normal": 1, "Foil": 2}
	riftbound := []printingFinish{
		{Finish: mtgmatcher.FinishNonfoil, Treatment: mtgmatcher.FinishNonfoil, UUID: "rft001"},
		{Finish: mtgmatcher.FinishFoil, Treatment: mtgmatcher.FinishFoil, UUID: "rft001_foil"},
	}

	got := subTypeForPrinting(riftbound, "rft001", subTypes)
	if got != "Normal" {
		t.Errorf("nonfoil: got %q, want \"Normal\"", got)
	}

	got = subTypeForPrinting(riftbound, "rft001_foil", subTypes)
	if got != "Foil" {
		t.Errorf("foil: got %q, want \"Foil\"", got)
	}
}

// The canonical read path keys on a Postgres uuid column, so a target that
// resolved to no ban_id has to be judged before it is asked about: the id a
// non-Magic game hands back is a type error waiting to happen, not a miss.
func TestHasCanonicalIdentity(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want bool
	}{
		{"magic uuid", "00010d56-fe38-5e35-8aed-518019aa36a5", true},
		{"magic uuid tagged with a finish", "00010d56-fe38-5e35-8aed-518019aa36a5_f", true},
		{"flesh and blood id", "omn071_695162_rainbow", false},
		{"lorcana id", "1459_f", false},
		{"bare product id", "695162", false},
		{"empty", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hasCanonicalIdentity(&chartTarget{UUID: test.uuid})
			if got != test.want {
				t.Errorf("hasCanonicalIdentity(%q) = %t, want %t", test.uuid, got, test.want)
			}
		})
	}
}
