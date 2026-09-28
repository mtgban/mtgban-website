package suggest

import (
	"fmt"
	"sort"
	"testing"
)

// The cases mirror tests/offline/autocomplete.test.js: the two matchers
// should fold a name the same way, or the search box and the browser's
// suggestion bar find different cards.
func TestFold(t *testing.T) {
	for _, tt := range []struct {
		name string
		want string
	}{
		{"Jace's Ire", "jaces ire"},
		{"Jötun Grunt", "jotun grunt"},
		{"Fire // Ice", "fire ice"},
		{"Ursula - Whisper of the Sea", "ursula whisper of the sea"},
		{"Lim-Dûl's Vault", "limduls vault"},
		{"Κλεοπάτρα", "κλεοπατρα"},
		{"_____", ""},
	} {
		got := Fold(tt.name)
		if got != tt.want {
			t.Errorf("fold(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMatchesFoldedNames(t *testing.T) {
	snap := NewNames([]string{
		"Ursula - Whisper of the Sea",
		"Jace's Ire",
		"Fire // Ice",
		"Lim-Dûl's Vault",
		"Lightning Bolt",
	}, nil)

	for _, tt := range []struct {
		typed string
		want  string
	}{
		{"ursula whisper", "Ursula - Whisper of the Sea"},
		{"ursula - whisper", "Ursula - Whisper of the Sea"},
		{"jaces", "Jace's Ire"},
		{"fire ice", "Fire // Ice"},
		{"limduls", "Lim-Dûl's Vault"},
	} {
		matches := snap.Matches(Fold(tt.typed), false)
		if len(matches) != 1 || matches[0] != tt.want {
			t.Errorf("%q matched %v, want just %q", tt.typed, matches, tt.want)
		}
	}

	matches := snap.Matches(Fold("counterspell"), false)
	if len(matches) != 0 {
		t.Errorf("counterspell matched %v, want nothing", matches)
	}
}

// A hyphen joining two words is the one place the fold and the reader
// disagree: the fold closes the gap, the reader types a space into it. The
// cases mirror tests/offline/autocomplete.test.js - both matchers have to find
// the same names, and 1,131 of Yu-Gi-Oh's 16,419 names carry such a hyphen.
func TestMatchesReachAJoiningHyphenFromEitherSpelling(t *testing.T) {
	snap := NewNames([]string{
		"Blue-Eyed Silver Zombie",
		"Roar of the Blue-Eyed Dragons",
		"3-Hump Lacooda",
		"Fire // Ice",
		"Lightning Bolt",
	}, nil)

	for _, tt := range []struct {
		typed string
		want  string
	}{
		{"blue eyed", "Blue-Eyed Silver Zombie"},
		{"blue-eyed", "Blue-Eyed Silver Zombie"},
		{"blueeyed", "Blue-Eyed Silver Zombie"},
		{"blue eyed silver", "Blue-Eyed Silver Zombie"},
		{"3 hump", "3-Hump Lacooda"},
		{"3-hump", "3-Hump Lacooda"},
		// The other direction: the name carries the space, the reader does not.
		{"fireice", "Fire // Ice"},
		{"fire ice", "Fire // Ice"},
	} {
		matches := snap.Matches(Fold(tt.typed), false)
		if len(matches) != 1 || matches[0] != tt.want {
			t.Errorf("%q matched %v, want just %q", tt.typed, matches, tt.want)
		}
	}

	// Closing the spaces must not make everything match everything.
	for _, typed := range []string{"counterspell", "eyed silver", "silver zombie"} {
		matches := snap.Matches(Fold(typed), false)
		if len(matches) != 0 {
			t.Errorf("%q matched %v, want nothing", typed, matches)
		}
	}
}

// A name found by both folds is offered once, in the place the folded search
// gave it, rather than twice.
func TestMatchesOfferANameFoundTwiceOnlyOnce(t *testing.T) {
	snap := NewNames([]string{"Blue-Eyed Silver Zombie", "Blue Eyed Rival"}, nil)

	got := snap.Matches(Fold("blueeyed"), false)
	want := []string{"Blue Eyed Rival", "Blue-Eyed Silver Zombie"}
	if len(got) != 2 {
		t.Fatalf("matched %v, want both names once each", got)
	}
	sort.Strings(got)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("matched %v, want %v", got, want)
			break
		}
	}
}

func TestMatchesCapTheAnswer(t *testing.T) {
	names := make([]string, maxSuggestions+5)
	for i := range names {
		names[i] = fmt.Sprintf("Same Prefix %02d", i)
	}
	snap := NewNames(names, nil)
	matches := snap.Matches(Fold("same prefix"), false)
	if len(matches) != maxSuggestions {
		t.Errorf("got %d matches, want the %d cap", len(matches), maxSuggestions)
	}
}
