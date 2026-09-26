package main

import (
	"strconv"
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

// The finish shapes below are the ones the datastore games ship, paired with
// the sub-types tcgcsv prices those products under: a plain printing beside a
// Cold Foil, one beside a Holofoil, a Lorcana card sold in both, a foil-only
// card, a foil with no listing yet, and Riftbound's bare Foil. Each printing
// carries the finish TCGplayer prices it under, which is what FoilUUIDs keys.
var tcgFinishCases = []struct {
	name      string
	subTypes  []string          // what the product is priced under
	printings map[string]string // uuid -> the finish it carries
	want      map[string]string // uuid -> sub-type ("" = no data for that finish)
}{
	{
		name:      "cold foil",
		subTypes:  []string{"Normal", "Cold Foil"},
		printings: map[string]string{"2790": "nonfoil", "2790_coldfoil": "coldfoil"},
		want:      map[string]string{"2790": "Normal", "2790_coldfoil": "Cold Foil"},
	},
	{
		name:      "holofoil",
		subTypes:  []string{"Normal", "Holofoil"},
		printings: map[string]string{"2206": "nonfoil", "2206_holofoil": "holofoil"},
		want:      map[string]string{"2206": "Normal", "2206_holofoil": "Holofoil"},
	},
	{
		// The 12 Lorcana printings sold in both, which the old pairing by
		// sorted position would have crossed once the cold foil had a name.
		name:      "a treatment beside the cold foil",
		subTypes:  []string{"Normal", "Cold Foil", "Holofoil"},
		printings: map[string]string{"2800": "nonfoil", "2800_coldfoil": "coldfoil", "2800_holofoil": "holofoil"},
		want:      map[string]string{"2800": "Normal", "2800_coldfoil": "Cold Foil", "2800_holofoil": "Holofoil"},
	},
	{
		// The product is priced under one more foil than the card has finishes,
		// so nothing maps to "Holofoil" in either direction. Mapping it onto the
		// cold foil would give a roster carrying both variants two rows for the
		// same printing.
		name:      "extra sub-type the card has no finish for",
		subTypes:  []string{"Normal", "Cold Foil", "Holofoil"},
		printings: map[string]string{"2810": "nonfoil", "2810_coldfoil": "coldfoil"},
		want:      map[string]string{"2810": "Normal", "2810_coldfoil": "Cold Foil"},
	},
	{
		name:      "foil-only card",
		subTypes:  []string{"Holofoil"},
		printings: map[string]string{"2937_holofoil": "holofoil"},
		want:      map[string]string{"2937_holofoil": "Holofoil"},
	},
	{
		name:      "foil not priced yet",
		subTypes:  []string{"Normal"},
		printings: map[string]string{"2900": "nonfoil", "2900_coldfoil": "coldfoil"},
		want:      map[string]string{"2900": "Normal", "2900_coldfoil": ""},
	},
	{
		name:      "single foil sub-type, as riftbound names it",
		subTypes:  []string{"Normal", "Foil"},
		printings: map[string]string{"abc": "nonfoil", "abc_foil": "foil"},
		want:      map[string]string{"abc": "Normal", "abc_foil": "Foil"},
	},
}

// foilUUIDs keys a case's printings by the finish each carries.
func foilUUIDs(printings map[string]string) map[string]string {
	out := map[string]string{}
	for uuid, finish := range printings {
		out[finish] = uuid
	}
	return out
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
		for uuid, finish := range tc.printings {
			co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Finish: finish, FoilUUIDs: foilUUIDs(tc.printings)}}
			if got := tcgSubTypeForCard(co, subTypes); got != tc.want[uuid] {
				t.Errorf("%s: tcgSubTypeForCard(%s) = %q, want %q", tc.name, finish, got, tc.want[uuid])
			}
		}
	}
}

// productInBothFinishes is a product whose card is sold plain and foil, with
// the uuid of each, so the two sub-types have two printings to land on.
func productInBothFinishes(t *testing.T) (int, string, string) {
	t.Helper()
	for _, u := range backend().GetUUIDs() {
		co, err := backend().GetUUID(u)
		if err != nil || co.Foil || co.Etched || co.Sealed {
			continue
		}
		foil, hasFoil := co.FoilUUIDs[mtgmatcher.FinishFoil]
		if !hasFoil || foil == co.UUID {
			continue
		}
		pid, err := strconv.Atoi(co.Identifiers["tcgplayerProductId"])
		if err != nil {
			continue
		}
		return pid, co.UUID, foil
	}
	t.Skip("no card sold in both finishes with a tcgplayer product id")
	return 0, "", ""
}

// And back: charting a variant has to land on the card row of the finish its
// sub-type names, not on the product's base printing, and on no row at all
// for a sub-type the product is not sold in.
func TestTCGFinishID(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}
	pid, plain, foil := productInBothFinishes(t)
	base, err := backend().MatchID(strconv.Itoa(pid))
	if err != nil {
		t.Fatal(err)
	}
	for subType, want := range map[string]string{
		"":          base,
		"Normal":    plain,
		"Foil":      foil,
		"Cold Foil": "",
	} {
		if got := tcgFinishID(backend(), pid, subType); got != want {
			t.Errorf("tcgFinishID(%d, %q) = %q, want %q", pid, subType, got, want)
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
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err != nil || co.Sealed || co.Foil || co.Etched {
			continue
		}
		alt, err := backend().MatchID(id, true)
		if err != nil || alt == id {
			continue
		}
		if altCo, err := backend().GetUUID(alt); err == nil && altCo.Foil {
			uuid, foilID = id, alt
			break
		}
	}
	if uuid == "" {
		t.Skip("no card with both a foil and a nonfoil printing")
	}

	if got := magicFinishSearchID(backend(), uuid, true, false); got != foilID {
		t.Errorf("magicFinishSearchID(%q, foil) = %q, want %q", uuid, got, foilID)
	}
	if got := magicFinishSearchID(backend(), uuid, false, false); got != uuid {
		t.Errorf("magicFinishSearchID(%q, nonfoil) = %q, want %q", uuid, got, uuid)
	}
}

// fabCard builds the FoilUUIDs shape mtgmatcher/fleshandblood produces for a
// product sold in Normal + Rainbow Foil: one key per printing, named as
// TCGplayer prices it, and the foil flag's default beside them.
func fabCard(uuid string, foil bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{Foil: foil}
	co.UUID = uuid
	co.Finish = mtgmatcher.FinishNonfoil
	if foil {
		co.Finish = "rainbowfoil"
	}
	co.FoilUUIDs = map[string]string{
		mtgmatcher.FinishNonfoil: "omn071_695162",
		mtgmatcher.FinishFoil:    "omn071_695162_rainbowfoil",
		"rainbowfoil":            "omn071_695162_rainbowfoil",
	}
	return co
}

// A finish whose own name is the sub-type's name resolves by name.
func TestTCGSubTypeForCardByName(t *testing.T) {
	subTypes := map[string]int64{"Normal": 1001, "Rainbow Foil": 1002}

	tests := []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"rainbow foil", fabCard("omn071_695162_rainbowfoil", true), "Rainbow Foil"},
		{"nonfoil", fabCard("omn071_695162", false), "Normal"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := tcgSubTypeForCard(test.co, subTypes)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
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

// Yu-Gi-Oh prices print runs rather than finishes, so its products carry no
// "Normal" sub-type and no foil one either. Resolution comes from the names:
// the matcher keys each run by the same words TCGplayer sells it under.
func TestTCGSubTypeForCardPrintRuns(t *testing.T) {
	subTypes := map[string]int64{"1st Edition": 1, "Unlimited": 2, "Limited": 3}

	// The flag says nothing about a run, so resolution holds either way.
	for _, foil := range []bool{false, true} {
		co := &mtgmatcher.CardObject{Foil: foil}
		co.FoilUUIDs = map[string]string{
			"1stedition": "hac1-en105_265004_1stedition",
			"unlimited":  "hac1-en105_265004_unlimited",
			"limited":    "hac1-en105_265004_limited",
		}
		for finish, want := range map[string]string{"1stedition": "1st Edition", "unlimited": "Unlimited"} {
			co.UUID, co.Finish = co.FoilUUIDs[finish], finish
			if got := tcgSubTypeForCard(co, subTypes); got != want {
				t.Errorf("foil=%t: got %q, want %q", foil, got, want)
			}
		}
	}
}

// A game whose sub-types are the generic finish names reads them the same way.
func TestTCGSubTypeForCardGenericNames(t *testing.T) {
	subTypes := map[string]int64{"Normal": 1, "Foil": 2}

	co := &mtgmatcher.CardObject{}
	co.FoilUUIDs = map[string]string{
		mtgmatcher.FinishNonfoil: "rft001",
		mtgmatcher.FinishFoil:    "rft001_foil",
	}
	for finish, want := range map[string]string{mtgmatcher.FinishNonfoil: "Normal", mtgmatcher.FinishFoil: "Foil"} {
		co.UUID, co.Finish = co.FoilUUIDs[finish], finish
		if got := tcgSubTypeForCard(co, subTypes); got != want {
			t.Errorf("%s: got %q, want %q", finish, got, want)
		}
	}
}
