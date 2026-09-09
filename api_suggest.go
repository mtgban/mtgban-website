package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/embed"
	"golang.org/x/text/unicode/norm"
)

// suggestEntry pairs the folded form a typed prefix is matched against
// with the name to display for it.
type suggestEntry struct {
	folded   string
	squashed string
	name     string
}

// suggestIndex is the autocomplete index: name entries sorted by their
// folded form, per game side. The pairing is rebuilt here because the
// datastore's canonical and lowercase name lists are each sorted on their
// own, so equal indexes in the two lists do not name the same card.
type suggestIndex struct {
	singles []suggestEntry
	sealed  []suggestEntry

	// The same entries again, sorted by the spaces-closed fold. A name that
	// spells a join with a hyphen loses it to the fold without leaving a
	// space - "Blue-Eyed Silver Zombie" folds to "blueeyed silver zombie" -
	// so a reader who types the space it looks like has no prefix to match.
	// Closing the spaces on both sides gives them one.
	singlesSquashed []suggestEntry
	sealedSquashed  []suggestEntry
}

// squashSuggestName closes up the spaces in an already-folded name, so that
// where one spelling puts a space the other can put nothing at all: it is what
// lets "blue eyed" reach "Blue-Eyed ...", and "fireice" reach "Fire // Ice".
func squashSuggestName(folded string) string {
	return strings.ReplaceAll(folded, " ", "")
}

// foldSuggestName is the matching form of a name: case, diacritics and
// punctuation set aside, so "jaces ire" finds "Jace's Ire" and "jotun"
// finds "Jötun Grunt". It mirrors __acFold in js/autocomplete.js - the two
// matchers should find the same names - with the same space rule: the
// spaces around a dropped dash are one collapsed run, so "ursula whisper"
// finds "Ursula - Whisper of the Sea" and "fire ice" finds "Fire // Ice",
// while punctuation inside a word still folds clean away and "limduls"
// keeps finding "Lim-Dûl's Vault".
//
// Letters and digits are kept whatever the script: hundreds of the names
// carry no ASCII letter at all, and folding to a-z alone would leave them
// findable by no one.
func foldSuggestName(name string) string {
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

var suggestIndexPtr atomic.Pointer[suggestIndex]

// rebuildSuggestIndex derives the autocomplete index from the loaded card
// data. Called from loadDatastore, the one place the card data swaps.
func rebuildSuggestIndex() {
	suggestIndexPtr.Store(newSuggestIndex(
		mtgmatcher.AllNames("canonical", false),
		mtgmatcher.AllNames("canonical", true),
	))
}

// newSuggestIndex builds the two sorted views each side is looked up in.
func newSuggestIndex(singles, sealed []string) *suggestIndex {
	byFold, bySquashed := buildSuggestEntries(singles)
	sealedByFold, sealedBySquashed := buildSuggestEntries(sealed)
	return &suggestIndex{
		singles:         byFold,
		singlesSquashed: bySquashed,
		sealed:          sealedByFold,
		sealedSquashed:  sealedBySquashed,
	}
}

// buildSuggestEntries returns the same entries twice, sorted by each of the
// two forms a typed prefix is looked up in. They share their strings; what
// differs is the order, because each lookup is a binary search over its own.
func buildSuggestEntries(names []string) (byFold, bySquashed []suggestEntry) {
	byFold = make([]suggestEntry, len(names))
	for i, name := range names {
		folded := foldSuggestName(name)
		byFold[i] = suggestEntry{folded: folded, squashed: squashSuggestName(folded), name: name}
	}
	sort.Slice(byFold, func(i, j int) bool {
		if byFold[i].folded != byFold[j].folded {
			return byFold[i].folded < byFold[j].folded
		}
		return byFold[i].name < byFold[j].name
	})

	bySquashed = make([]suggestEntry, len(byFold))
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

// prefixMatches returns the entries a typed prefix reaches, by folded form
// first and then by the spaces-closed form, each a binary search over the view
// sorted for it. Both run every time rather than the second standing in for a
// failed first: the two disagree in both directions, since a typed space has
// to reach a hyphen in the name and a typed hyphen has to reach a space.
// Names already found keep the place the folded search gave them.
func (idx *suggestIndex) matchesFor(typed string, sealed bool) []suggestEntry {
	folded := foldSuggestName(typed)
	return idx.prefixMatches(folded, squashSuggestName(folded), sealed)
}

func (idx *suggestIndex) prefixMatches(folded, squashed string, sealed bool) []suggestEntry {
	byFold, bySquashed := idx.singles, idx.singlesSquashed
	if sealed {
		byFold, bySquashed = idx.sealed, idx.sealedSquashed
	}

	seen := make(map[string]bool, maxSuggestions)
	out := appendPrefixMatches(nil, byFold, folded, seen, func(e suggestEntry) string { return e.folded })
	return appendPrefixMatches(out, bySquashed, squashed, seen, func(e suggestEntry) string { return e.squashed })
}

// appendPrefixMatches collects entries whose key starts with prefix, from a
// slice sorted by that key, up to the response cap. A name already collected
// is skipped rather than ending the walk: the two views hold the same names in
// different orders, so a repeat says nothing about what follows it.
func appendPrefixMatches(out, entries []suggestEntry, prefix string, seen map[string]bool, key func(suggestEntry) string) []suggestEntry {
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
		out = append(out, entries[i])
	}
	return out
}

func SuggestAPI(w http.ResponseWriter, r *http.Request) {
	sealed, _ := strconv.ParseBool(r.FormValue("sealed"))

	if r.FormValue("all") == "true" {
		AllNames := mtgmatcher.AllNames("canonical", sealed)
		// An empty pool means the datastore isn't (fully) loaded; make sure
		// no cache holds on to the degraded answer
		if len(AllNames) == 0 {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			// The full name list is the heaviest thing the front end
			// asks for, and it only changes when the datastore reloads,
			// so let the browser keep it instead of pulling it down on
			// every page view
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&AllNames)
		return
	}

	// The length gate reads the typed text, but the match runs on its folded
	// form - and a query that folds to nothing (all punctuation) matches
	// every entry as an empty prefix, so it answers nothing instead.
	if len(r.FormValue("q")) < 3 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	prefix := foldSuggestName(r.FormValue("q"))
	if prefix == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	idx := suggestIndexPtr.Load()
	if idx == nil {
		// Datastore not loaded yet; don't let a cache hold the empty answer
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var suggestions []string
	var results []string
	var links []string
	for _, entry := range idx.prefixMatches(prefix, squashSuggestName(prefix), sealed) {
		suggestions = append(suggestions, entry.name)
		printings, _ := mtgmatcher.Printings4Card(entry.name)
		results = append(results, embed.PrintingsLine(printings))
		links = append(links, ServerURL+"/search?q="+url.QueryEscape(entry.name))
	}
	// This argument is mandatory
	if suggestions == nil {
		suggestions = append(suggestions, "")
	}

	// The first element echoes the query, per the opensearch suggestions
	// shape - the text as typed, not the folded form it was matched by.
	out := []any{}
	out = append(out, r.FormValue("q"))
	for _, tags := range [][]string{suggestions, results, links} {
		if tags == nil {
			break
		}
		out = append(out, tags)
	}

	// Cache response for 5 minutes, unless it was served while the
	// datastore was still loading
	if dataReady() {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}

	json.NewEncoder(w).Encode(&out)
}
