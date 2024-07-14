package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

var AllNames []string
var AllLowerCaseNames []string

func loadNames() {
	var allNames []string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, _ := mtgmatcher.GetUUID(uuid)
		if !slices.Contains(allNames, co.Name) {
			allNames = append(allNames, co.Name)
		}
		// Look for alternate names too
		for _, name := range []string{co.FaceName, co.FlavorName, co.FaceFlavorName} {
			// Skip empty entries and all those faces that would duplicate the card
			if name == "" || strings.HasPrefix(co.Name, name) {
				continue
			}
			if !slices.Contains(allNames, name) {
				allNames = append(allNames, name)
			}
		}
	}
	sort.Strings(allNames)

	allLowerCaseNames := make([]string, len(allNames))
	for i := range allNames {
		allLowerCaseNames[i] = strings.ToLower(allNames[i])
	}
	AllNames = allNames
	AllLowerCaseNames = allLowerCaseNames

	log.Println("AllNames Loaded!")
}

func SuggestAPI(w http.ResponseWriter, r *http.Request) {
	if AllNames == nil {
		loadNames()
	}

	if r.FormValue("all") == "true" {
		json.NewEncoder(w).Encode(&AllNames)
		return
	}

	prefix := strings.ToLower(r.FormValue("q"))
	if len(prefix) < 3 {
		return
	}
	baseURL := getBaseURL(r)

	var suggestions []string
	var results []string
	var links []string
	for i, name := range AllLowerCaseNames {
		if strings.HasPrefix(name, prefix) {
			suggestions = append(suggestions, AllNames[i])
			printings, _ := mtgmatcher.Printings4Card(name)
			results = append(results, printings2line(printings))
			links = append(links, baseURL+"/search?q="+url.QueryEscape(AllNames[i]))
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
