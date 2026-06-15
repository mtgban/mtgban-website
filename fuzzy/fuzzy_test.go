package fuzzy

import "testing"

func TestLevenshtein(t *testing.T) {
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
		{"", "abc", 3},
	}
	for _, tc := range cases {
		if got := Levenshtein(tc.a, tc.b, big); got != tc.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	// Once the budget is exceeded the exact distance is not computed
	if got := Levenshtein("abcdef", "uvwxyz", 2); got <= 2 {
		t.Errorf("expected distance over budget, got %d", got)
	}
}

func TestClosest(t *testing.T) {
	candidates := []string{"Lightning Bolt", "Lightning Helix", "Counterspell", "Island"}
	cases := []struct {
		query string
		want  string
	}{
		{"lightnig bolt", "Lightning Bolt"}, // single typo
		{"counterspel", "Counterspell"},     // missing letter
		{"lightning bolt", ""},              // exact match, no suggestion
		{"xyzzyqwerty", ""},                 // far from everything
		{"ab", ""},                          // too short to disambiguate
	}
	for _, tc := range cases {
		if got := Closest(tc.query, candidates); got != tc.want {
			t.Errorf("Closest(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}
