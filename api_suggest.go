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
	folded string
	name   string
}

// suggestIndex is the autocomplete index: name entries sorted by their
// folded form, per game side. The pairing is rebuilt here because the
// datastore's canonical and lowercase name lists are each sorted on their
// own, so equal indexes in the two lists do not name the same card.
type suggestIndex struct {
	singles []suggestEntry
	sealed  []suggestEntry
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
	suggestIndexPtr.Store(&suggestIndex{
		singles: buildSuggestEntries(mtgmatcher.AllNames("canonical", false)),
		sealed:  buildSuggestEntries(mtgmatcher.AllNames("canonical", true)),
	})
}

func buildSuggestEntries(names []string) []suggestEntry {
	entries := make([]suggestEntry, len(names))
	for i, name := range names {
		entries[i] = suggestEntry{folded: foldSuggestName(name), name: name}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].folded != entries[j].folded {
			return entries[i].folded < entries[j].folded
		}
		return entries[i].name < entries[j].name
	})
	return entries
}

// maxSuggestions caps a response: the search box renders at most 30
// candidates, and every match costs a printings-line render.
const maxSuggestions = 30

// prefixMatches returns the first entries whose folded form starts with
// prefix (itself already folded), located by binary search over the sorted
// index.
func (idx *suggestIndex) prefixMatches(prefix string, sealed bool) []suggestEntry {
	entries := idx.singles
	if sealed {
		entries = idx.sealed
	}
	start := sort.Search(len(entries), func(i int) bool {
		return entries[i].folded >= prefix
	})
	end := start
	for end < len(entries) && end-start < maxSuggestions && strings.HasPrefix(entries[end].folded, prefix) {
		end++
	}
	return entries[start:end]
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
	for _, entry := range idx.prefixMatches(prefix, sealed) {
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
