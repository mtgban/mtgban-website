package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func SuggestAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sealed, _ := strconv.ParseBool(r.FormValue("sealed"))

	AllNames := mtgmatcher.AllNames("canonical", sealed)
	if r.FormValue("all") == "true" {
		json.NewEncoder(w).Encode(&AllNames)
		return
	}

	prefix := strings.ToLower(r.FormValue("q"))
	if len(prefix) < 3 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	AllLowerCaseNames := mtgmatcher.AllNames("lowercase", false)

	var suggestions []string
	var results []string
	var links []string
	for i, name := range AllLowerCaseNames {
		if strings.HasPrefix(name, prefix) {
			suggestions = append(suggestions, AllNames[i])
			printings, _ := mtgmatcher.Printings4Card(name)
			results = append(results, printings2line(printings))
			links = append(links, ServerURL+"/search?q="+url.QueryEscape(AllNames[i]))
		}
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

	json.NewEncoder(w).Encode(&out)
}
