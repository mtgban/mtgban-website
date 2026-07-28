package main

import "testing"

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
