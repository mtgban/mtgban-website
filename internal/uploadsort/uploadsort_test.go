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
	}{
		{"white", []string{"white"}},
		{"blue", []string{"blue"}},
		{"green", []string{"green"}},
		{"two, the first colors first", []string{"blue", "white"}},
		{"two, later colors", []string{"red", "black"}},
		{"three", []string{"white", "blue", "black"}},
		{"none", nil},
	}
	var keys []string
	for _, c := range cases {
		keys = append(keys, colorKey(order, c.colors))
	}
	if !slices.IsSorted(keys) || len(slices.Compact(slices.Clone(keys))) != len(keys) {
		t.Errorf("keys out of order: %q", keys)
	}
}

func TestColorKeyCountsUnlistedAsNone(t *testing.T) {
	order := []string{"white", "blue", "colorless"}
	for _, colors := range [][]string{nil, {"colorless"}, {"purple"}} {
		got := colorKey(order, colors)
		if got != "3" {
			t.Errorf("colorKey(%q) = %q, want none", colors, got)
		}
	}
	got := colorKey(order, []string{"blue", "colorless"})
	if got != colorKey(order, []string{"blue"}) {
		t.Errorf("colorless beside blue filed as %q, not as blue", got)
	}
}
