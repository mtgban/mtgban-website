package fuzzy

import "testing"

// benchNames is a name list the size of Magic's, two to four words each.
func benchNames() []string {
	words := []string{
		"lightning", "bolt", "swamp", "counterspell", "island", "helix",
		"ancestral", "recall", "dark", "ritual", "serra", "angel",
		"shivan", "dragon", "llanowar", "elves", "wrath", "of",
		"god", "black", "lotus", "time", "walk", "mox",
		"sapphire", "jet", "pearl", "ruby", "emerald", "sol",
		"ring", "force", "will",
	}
	var names []string
	for i, a := range words {
		for j, b := range words {
			for k, c := range words {
				name := a + " " + b
				if (i+j+k)%3 == 0 {
					name += " " + c
				}
				names = append(names, name)
			}
		}
	}
	return names
}

// BenchmarkClosest is one did-you-mean scan of the name list.
func BenchmarkClosest(b *testing.B) {
	names := benchNames()
	for b.Loop() {
		Closest("lightnig bolt", names)
	}
}
