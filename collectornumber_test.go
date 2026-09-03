package main

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// Both sides of the comparison are folded, so a number is asked for by any of
// its spellings and found whichever one the catalog holds.
func TestCollectorNumberFormsAllAgree(t *testing.T) {
	stored := []string{"034", "34", "034/182", "34/182"}
	queries := []string{"034", "34", "034/182", "34/182"}

	for _, strict := range []bool{false, true} {
		for _, number := range stored {
			for _, query := range queries {
				co := &mtgmatcher.CardObject{}
				co.Number = number
				co.OriginalNumber = number

				filters := fixupNumberNG(query, strict)
				skipped := cardFilterNumber(filters, co)
				if strict {
					skipped = cardFilterNumberStrict(filters, co)
				}
				if skipped {
					t.Errorf("strict=%t: cn:%s did not match a card stored as %q (folded to %q)",
						strict, query, number, filters)
				}
			}
		}
	}
}

// The fold takes the zeros that pad a run of digits and the set total, and
// nothing else: the dash in a PLST number and the star cns: exists to preserve
// both survive it.
func TestFoldCollectorNumber(t *testing.T) {
	tests := []struct{ in, want string }{
		{"034", "34"},
		{"34", "34"},
		{"034/182", "34"},
		{"082/167", "82"},
		{"sv049/sv122", "sv49"},
		{"mh1-123", "mh1-123"},
		{"2002-1", "2002-1"},
		{"123*", "123*"},
		{"MPA001", "mpa1"},
		{"0", "0"},
		{"00", "0"},
		{"000/182", "0"},
		{"", ""},
	}
	for _, test := range tests {
		if got := foldCollectorNumber(test.in); got != test.want {
			t.Errorf("foldCollectorNumber(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

// cns: still means strict: it keeps the suffix cn: trims, and folding must not
// have quietly made the two the same filter.
func TestStrictNumberKeepsItsSuffix(t *testing.T) {
	co := &mtgmatcher.CardObject{}
	co.Number = "123*"
	co.OriginalNumber = "123*"

	if cardFilterNumberStrict(fixupNumberNG("123*", true), co) {
		t.Error("cns:123* did not match a card numbered 123*")
	}
	if !cardFilterNumberStrict(fixupNumberNG("123", true), co) {
		t.Error("cns:123 matched a card numbered 123*, so strict stopped being strict")
	}
}

// Folding can only merge numbers that differed by padding or a total. Within a
// set that would be a collision - two printings answering one query - so check
// the datastore rather than assume.
func TestFoldingCollidesNoNumbersInASet(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("no datastore loaded")
	}

	type key struct{ set, folded string }
	raw := map[key]map[string]bool{}
	for _, uuid := range uuids {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		k := key{co.SetCode, foldCollectorNumber(co.Number)}
		if raw[k] == nil {
			raw[k] = map[string]bool{}
		}
		raw[k][co.Number] = true
	}

	// Folding is lossy in exactly one place, and it is worth knowing where:
	// a set numbering a card "0" and another "00" cannot tell them apart
	// afterwards. Anything else colliding would be a printing made
	// unreachable, so the test names what it allows rather than counting.
	for k, numbers := range raw {
		if len(numbers) == 1 {
			continue
		}
		for number := range numbers {
			if strings.Trim(number, "0") != "" {
				t.Errorf("%s: %v fold together into %q, and not merely by padding",
					k.set, slices.Sorted(maps.Keys(numbers)), k.folded)
				break
			}
		}
	}
}
