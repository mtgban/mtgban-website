package fuzzy

import (
	"slices"
	"testing"
)

func TestDistance(t *testing.T) {
	big := 999
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "ab", 1},
		{"ab", "abc", 1},
		{"lightnig bolt", "lightning bolt", 1},
		{"kitten", "sitting", 3},
		{"swapm", "swamp", 1}, // adjacent swap is one edit
		{"swapm", "snap", 2},  // so it beats a substitute-and-drop
		{"ca", "abc", 3},      // a swap only pairs adjacent letters
		{"", "abc", 3},
	}
	for _, tc := range cases {
		if got := Distance(tc.a, tc.b, big); got != tc.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	// Once the budget is exceeded the exact distance is not computed
	if got := Distance("abcdef", "uvwxyz", 2); got <= 2 {
		t.Errorf("expected distance over budget, got %d", got)
	}

	// A swap fits the tightest budget, and two of them exceed it
	if got := Distance("swapm", "swamp", 1); got != 1 {
		t.Errorf("Distance(swapm, swamp, 1) = %d, want 1", got)
	}
	if got := Distance("abcd", "badc", 1); got != 2 {
		t.Errorf("Distance(abcd, badc, 1) = %d, want limit+1 = 2", got)
	}
}

// One scan's rows give each pair the distance a fresh call does, however
// the lengths before it ran.
func TestDistanceReusesRows(t *testing.T) {
	pairs := [][2]string{
		{"lightnig bolt", "lightning bolt"},
		{"swapm", "swamp"},
		{"kitten", "sitting"},
		{"ca", "abc"},
		{"counterspel", "counterspell"},
		{"", "abc"},
		{"abcd", "badc"},
	}
	var r rows
	for _, limit := range []int{1, 2, 999} {
		for _, pair := range pairs {
			got := r.distance(pair[0], pair[1], limit)
			want := Distance(pair[0], pair[1], limit)
			if got != want {
				t.Errorf("distance(%q, %q, %d) = %d after other pairs, want %d", pair[0], pair[1], limit, got, want)
			}
		}
	}
}

func TestClosest(t *testing.T) {
	candidates := []string{"Lightning Bolt", "Lightning Helix", "Counterspell", "Island", "Snap", "Swab", "Swamp", "Swarm"}
	cases := []struct {
		query string
		want  []string
	}{
		{"lightnig bolt", []string{"Lightning Bolt"}},                     // single typo
		{"counterspel", []string{"Counterspell"}},                         // missing letter
		{"swapm", []string{"Swamp", "Swarm", "Snap"}},                     // the one-edit names in list order, then two edits, capped before Swab
		{"lightning bolt", nil},                                           // exact match, no suggestion
		{"lightning helx", []string{"Lightning Helix", "Lightning Bolt"}}, // one edit before three
		{"xyzzyqwerty", nil},                                              // far from everything
		{"ab", nil},                                                       // too short to disambiguate
	}
	for _, tc := range cases {
		if got := Closest(tc.query, candidates); !slices.Equal(got, tc.want) {
			t.Errorf("Closest(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}
