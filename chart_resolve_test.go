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
