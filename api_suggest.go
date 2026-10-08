package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/embed"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

func (s *site) SuggestAPI(w http.ResponseWriter, r *http.Request) {
	// sealed picks the name list: cards (the default), products, or with
	// "all" both, cards first, for a box that searches the two together.
	both := r.FormValue("sealed") == "all"
	sealed, _ := strconv.ParseBool(r.FormValue("sealed"))
	ds := s.datastore()

	if r.FormValue("all") == "true" {
		AllNames := ds.backend.Names(mtgmatcher.NameFormCanonical, sealed)
		if both {
			// Merged once with the names snapshot; nil until it is built,
			// which the empty-pool check below answers with no-store.
			AllNames = ds.names.Merged()
		}
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
	prefix := suggest.Fold(r.FormValue("q"))
	if prefix == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if ds.names == nil {
		// Names snapshot not built yet; don't let a cache hold the empty answer
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var suggestions []string
	var results []string
	var links []string
	matches := ds.names.Matches(prefix, sealed)
	if both {
		matches = ds.names.MatchesBoth(prefix)
	}
	for _, name := range matches {
		suggestions = append(suggestions, name)
		printings, _ := ds.backend.Printings4Card(name)
		results = append(results, embed.PrintingsLine(printings))
		links = append(links, absoluteURL(r, "/search?q="+url.QueryEscape(name)))
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
	if dataReady(ds.backend) {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}

	json.NewEncoder(w).Encode(&out)
}
