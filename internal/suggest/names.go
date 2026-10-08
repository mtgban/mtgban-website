package suggest

import (
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// nameEntry pairs the folded form a typed prefix is matched against
// with the name to display for it.
type nameEntry struct {
	folded   string
	squashed string
	name     string
}

// Names is the card names, sorted by the forms a typed prefix is matched
// against, per game side. The pairing is rebuilt here because the
// datastore's canonical and lowercase name lists are each sorted on their
// own, so equal indexes in the two lists do not name the same card.
type Names struct {
	singles []nameEntry
	sealed  []nameEntry

	// The same entries again, sorted by the spaces-closed fold. A name that
	// spells a join with a hyphen loses it to the fold without leaving a
	// space - "Blue-Eyed Silver Zombie" folds to "blueeyed silver zombie" -
	// so a reader who types the space it looks like has no prefix to match.
	// Closing the spaces on both sides gives them one.
	singlesSquashed []nameEntry
	sealedSquashed  []nameEntry

	// Both canonical lists as one, built once per datastore for the box
	// that searches cards and products alike.
	merged []string
}

// Merged returns both canonical lists as one, cards first, or nil when no
// snapshot is built.
func (n *Names) Merged() []string {
	if n == nil {
		return nil
	}
	return n.merged
}

// squash closes up the spaces in an already-folded name, so that where one
// spelling puts a space the other can put nothing at all: it is what lets
// "blue eyed" reach "Blue-Eyed ...", and "fireice" reach "Fire // Ice".
func squash(folded string) string {
	return strings.ReplaceAll(folded, " ", "")
}

// Fold is the matching form of a name: case, diacritics and punctuation set
// aside, so "jaces ire" finds "Jace's Ire" and "jotun" finds "Jötun Grunt".
// It mirrors __acFold in js/autocomplete.js - the two matchers should find
// the same names - with the same space rule: the spaces around a dropped
// dash are one collapsed run, so "ursula whisper" finds "Ursula - Whisper of
// the Sea" and "fire ice" finds "Fire // Ice", while punctuation inside a
// word still folds clean away and "limduls" keeps finding "Lim-Dûl's Vault".
//
// Letters and digits are kept whatever the script: hundreds of the names
// carry no ASCII letter at all, and folding to a-z alone would leave them
// findable by no one.
func Fold(name string) string {
	var sb strings.Builder
	prevSpace := false
	for _, r := range norm.NFD.String(name) {
		switch {
		case unicode.Is(unicode.Mn, r):
			// The combining marks NFD split off the base letters.
		case r == ' ':
			if !prevSpace {
				sb.WriteRune(' ')
			}
			prevSpace = true
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			sb.WriteRune(unicode.ToLower(r))
			prevSpace = false
		default:
			// Punctuation folds away and leaves the run state alone.
		}
	}
	return sb.String()
}

// NewNames builds the two sorted views each side is looked up in, from one
// datastore's canonical single and sealed names.
func NewNames(singles, sealed []string) *Names {
	byFold, bySquashed := buildNameEntries(singles)
	sealedByFold, sealedBySquashed := buildNameEntries(sealed)
	return &Names{
		singles:         byFold,
		singlesSquashed: bySquashed,
		sealed:          sealedByFold,
		sealedSquashed:  sealedBySquashed,
		merged:          MergeNames(singles, sealed),
	}
}

// buildNameEntries returns the same entries twice, sorted by each of the
// two forms a typed prefix is looked up in. They share their strings; what
// differs is the order, because each lookup is a binary search over its own.
func buildNameEntries(names []string) (byFold, bySquashed []nameEntry) {
	byFold = make([]nameEntry, len(names))
	for i, name := range names {
		folded := Fold(name)
		byFold[i] = nameEntry{folded: folded, squashed: squash(folded), name: name}
	}
	sort.Slice(byFold, func(i, j int) bool {
		if byFold[i].folded != byFold[j].folded {
			return byFold[i].folded < byFold[j].folded
		}
		return byFold[i].name < byFold[j].name
	})

	bySquashed = make([]nameEntry, len(byFold))
	copy(bySquashed, byFold)
	sort.Slice(bySquashed, func(i, j int) bool {
		if bySquashed[i].squashed != bySquashed[j].squashed {
			return bySquashed[i].squashed < bySquashed[j].squashed
		}
		return bySquashed[i].name < bySquashed[j].name
	})
	return byFold, bySquashed
}

// maxSuggestions caps a response: the search box renders at most 30
// candidates, and every match costs a printings-line render.
const maxSuggestions = 30

// Matches returns the names a prefix already folded by Fold reaches, by
// folded form first and then by the spaces-closed form, each a binary search
// over the view sorted for it. Both run every time rather than the second
// standing in for a failed first: the two disagree in both directions, since
// a typed space has to reach a hyphen in the name and a typed hyphen has to
// reach a space. Names already found keep the place the folded search gave
// them.
func (n *Names) Matches(folded string, sealed bool) []string {
	byFold, bySquashed := n.singles, n.singlesSquashed
	if sealed {
		byFold, bySquashed = n.sealed, n.sealedSquashed
	}

	seen := make(map[string]bool, maxSuggestions)
	out := appendPrefixMatches(nil, byFold, folded, seen, func(e nameEntry) string { return e.folded })
	return appendPrefixMatches(out, bySquashed, squash(folded), seen, func(e nameEntry) string { return e.squashed })
}

// MatchesBoth is Matches over both lists, cards first: a prefix typed into
// a box that searches cards and products alike. A name both lists carry
// is offered once, in its card place.
func (n *Names) MatchesBoth(folded string) []string {
	out := n.Matches(folded, false)
	seen := make(map[string]bool, len(out))
	for _, name := range out {
		seen[name] = true
	}
	for _, name := range n.Matches(folded, true) {
		if len(out) >= maxSuggestions {
			break
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// MergeNames is both canonical lists as one, cards first and then the
// products whose name no card carries. The result is a new slice; the
// inputs are left as they are.
func MergeNames(singles, sealed []string) []string {
	out := make([]string, 0, len(singles)+len(sealed))
	out = append(out, singles...)
	seen := make(map[string]bool, len(singles))
	for _, name := range singles {
		seen[name] = true
	}
	for _, name := range sealed {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

// appendPrefixMatches collects the names whose key starts with prefix, from
// entries sorted by that key, up to the response cap. A name already
// collected is skipped rather than ending the walk: the two views hold the
// same names in different orders, so a repeat says nothing about what
// follows it.
func appendPrefixMatches(out []string, entries []nameEntry, prefix string, seen map[string]bool, key func(nameEntry) string) []string {
	if prefix == "" {
		return out
	}
	start := sort.Search(len(entries), func(i int) bool {
		return key(entries[i]) >= prefix
	})
	for i := start; i < len(entries) && len(out) < maxSuggestions; i++ {
		if !strings.HasPrefix(key(entries[i]), prefix) {
			break
		}
		if seen[entries[i].name] {
			continue
		}
		seen[entries[i].name] = true
		out = append(out, entries[i].name)
	}
	return out
}
