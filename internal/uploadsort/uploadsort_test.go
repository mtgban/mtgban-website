package uploadsort

import (
	"slices"
	"testing"
)

func TestColorKeyOrder(t *testing.T) {
	order := []string{"white", "blue", "black", "red", "green"}
	// Each case files after the one before it
	cases := []struct {
		name   string
		colors []string
		types  []string
	}{
		{"white", []string{"white"}, nil},
		{"blue artifact", []string{"blue"}, []string{"Artifact"}},
		{"green land", []string{"green"}, []string{"Land"}},
		{"two, the first colors first", []string{"blue", "white"}, nil},
		{"two, later colors", []string{"red", "black"}, nil},
		{"three", []string{"white", "blue", "black"}, nil},
		{"none", nil, []string{"Creature"}},
		{"artifact", nil, []string{"Artifact", "Creature"}},
		{"land", nil, []string{"Artifact", "Land"}},
	}
	var keys []string
	for _, c := range cases {
		keys = append(keys, colorKey(order, c.colors, c.types))
	}
	if !slices.IsSorted(keys) || len(slices.Compact(slices.Clone(keys))) != len(keys) {
		t.Errorf("keys out of order: %q", keys)
	}
}

func TestColorKeyCountsUnlistedAsNone(t *testing.T) {
	order := []string{"white", "blue", "colorless"}
	for _, colors := range [][]string{nil, {"colorless"}, {"purple"}} {
		got := colorKey(order, colors, nil)
		if got != "3" {
			t.Errorf("colorKey(%q) = %q, want none", colors, got)
		}
	}
	got := colorKey(order, []string{"blue", "colorless"}, nil)
	if got != colorKey(order, []string{"blue"}, nil) {
		t.Errorf("colorless beside blue filed as %q, not as blue", got)
	}
}
