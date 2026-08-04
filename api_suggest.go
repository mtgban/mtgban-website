package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// suggestEntry pairs the lowercase form a typed prefix is matched against
// with the name to display for it.
type suggestEntry struct {
	lower string
	name  string
}

// suggestIndex is the autocomplete index: name entries sorted by their
// lowercase form, per game side. The pairing is rebuilt here because the
// datastore's canonical and lowercase name lists are each sorted on their
// own, so equal indexes in the two lists do not name the same card.
type suggestIndex struct {
	singles []suggestEntry
	sealed  []suggestEntry
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
		entries[i] = suggestEntry{lower: strings.ToLower(name), name: name}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lower < entries[j].lower
	})
	return entries
}

// prefixMatches returns the entries whose lowercase form starts with prefix,
// located by binary search over the sorted index.
func (idx *suggestIndex) prefixMatches(prefix string, sealed bool) []suggestEntry {
	entries := idx.singles
	if sealed {
		entries = idx.sealed
	}
	start := sort.Search(len(entries), func(i int) bool {
		return entries[i].lower >= prefix
	})
	end := start
	for end < len(entries) && strings.HasPrefix(entries[end].lower, prefix) {
		end++
	}
	return entries[start:end]
}

func SuggestAPI(w http.ResponseWriter, r *http.Request) {
	sealed, _ := strconv.ParseBool(r.FormValue("sealed"))

	if r.FormValue("all") == "true" {
		AllNames := mtgmatcher.AllNames("canonical", sealed)
		json.NewEncoder(w).Encode(&AllNames)
		return
	}

	prefix := strings.ToLower(r.FormValue("q"))
	if len(prefix) < 3 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	idx := suggestIndexPtr.Load()
	if idx == nil {
		// Datastore not loaded yet
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var suggestions []string
	var results []string
	var links []string
	for _, entry := range idx.prefixMatches(prefix, sealed) {
		suggestions = append(suggestions, entry.name)
		printings, _ := mtgmatcher.Printings4Card(entry.lower)
		results = append(results, embed.PrintingsLine(printings))
		links = append(links, ServerURL+"/search?q="+url.QueryEscape(entry.name))
	}
	// This argument is mandatory
	if suggestions == nil {
		suggestions = append(suggestions, "")
	}

	out := []any{}
	out = append(out, prefix)
	for _, tags := range [][]string{suggestions, results, links} {
		if tags == nil {
			break
		}
		out = append(out, tags)
	}

	// Cache response for 5 minutes
	w.Header().Set("Cache-Control", "public, max-age=300")

	json.NewEncoder(w).Encode(&out)
}
