package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/suggest"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func filterNames(filters []FilterElem) []string {
	var names []string
	for _, filter := range filters {
		names = append(names, filter.Name)
	}
	return names
}

func parseForTest(t *testing.T, query string) SearchConfig {
	t.Helper()
	return parseSearchOptionsNG(query, nil, nil, nil)
}

// TestSearchScopeAddsFilters is the case the bar exists for: a set pinned
// once, then a finish typed and retyped in the main bar.
func TestSearchScopeAddsFilters(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, typed := range []string{"is:foil", "is:nonfoil"} {
		config := parseForTest(t, typed)
		applySearchScope(&config, scopeFilters("s:sos"))

		names := filterNames(config.CardFilters)
		if !slices.Contains(names, "edition") {
			t.Errorf("%q: the pinned set did not reach the search, filters are %v", typed, names)
		}
	}
}

// TestSearchScopePrimaryWins keeps the bar nobody is looking at from
// emptying a search the main bar just asked for: filters are ANDed, so a
// pinned set under a typed set would answer nothing at all.
func TestSearchScopePrimaryWins(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	config := parseForTest(t, "s:mh3")
	before := len(config.CardFilters)
	applySearchScope(&config, scopeFilters("s:sos"))

	if len(config.CardFilters) != before {
		t.Errorf("the pinned set was added on top of the typed one: %v", filterNames(config.CardFilters))
	}
}

// TestSearchScopeIgnoresNames is the other half of the contract: the
// sticky bar carries filters, and pinning a card name is what the main
// bar is for.
func TestSearchScopeIgnoresNames(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	config := parseForTest(t, "is:foil")
	before := len(config.CardFilters)
	applySearchScope(&config, scopeFilters("abrade"))

	if len(config.CardFilters) != before {
		t.Errorf("a name in the pinned bar changed the search: %v", filterNames(config.CardFilters))
	}
	if config.CleanQuery == "abrade" {
		t.Error("a name in the pinned bar replaced what the main bar searched for")
	}
}

// TestSearchScopeSkipsPassthroughModes leaves alone the queries that name
// their own cards or that another syntax reads whole.
func TestSearchScopeSkipsPassthroughModes(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, mode := range []string{"hashing", "scryfall"} {
		config := parseForTest(t, "is:foil")
		config.SearchMode = mode
		before := len(config.CardFilters)
		applySearchScope(&config, scopeFilters("s:sos"))

		if len(config.CardFilters) != before {
			t.Errorf("%s mode was narrowed by the pinned bar: %v", mode, filterNames(config.CardFilters))
		}
	}
}

// TestSearchScopeURLWins covers the rule that lets clearing tell itself
// apart from arriving with no field at all.
func TestSearchScopeURLWins(t *testing.T) {
	tests := []struct {
		name   string
		target string
		cookie string
		want   string
	}{
		{"url names it", "/search?q=x&scope=s%3Asos", "is:foil", "s:sos"},
		{"url clears it", "/search?q=x&scope=", "is:foil", ""},
		{"url is silent", "/search?q=x", "is:foil", "is:foil"},
		{"nothing anywhere", "/search?q=x", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.target, nil)
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "SearchScope", Value: tt.cookie})
			}
			got := searchScope(httptest.NewRecorder(), r)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSearchScopeRendersInSuggestions renders the page that sits at the far
// end of a pinned filter: nothing found, the bar still narrowing, and the
// "without s:xxx" suggestions listed under it.
//
// Nothing already here could see this. The parse tests read the templates
// without running them, and a field looked up on the wrong dot - .SearchScope
// inside {{range .AltSearches}}, where the dot is the suggestion and not the
// page - is legal to parse and fails on execution, halfway through the
// attribute it was writing. The page comes back truncated mid-href, which
// reads as a styling problem rather than a 500.
func TestSearchScopeRendersInSuggestions(t *testing.T) {
	saved := DevMode
	DevMode = false
	defer func() { DevMode = saved }()

	cache, err := buildTemplateCache()
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}

	pageVars := PageVars{
		Title:       "BAN Search",
		InfoMessage: NoCardsMessage,
		SearchQuery: "s:M19 cns:235 Fountain sdfsdfsdf Renewal",
		SearchScope: "f:foil",
		CanScope:    true,
		DidYouMean:  "Fountain of Renewal",
		AltSearches: []suggest.AltSearch{
			{Query: "Fountain sdfsdfsdf Renewal", Label: "without s:M19"},
			{Query: "s:M19 Fountain sdfsdfsdf Renewal", Label: "without cns:235"},
		},
		Metadata: map[string]GenericCard{},
		// The navbar names the reader; a zero PageVars would fault on it
		// long before reaching the suggestions this is about.
		BetaNav: &NavElem{Short: "TEST"},
	}

	// The claim the page makes about the bar has to match what the bar is
	// doing: a bar the search ignores did not empty the page, and offering
	// to undo it sends the reader after the one thing that is blameless.
	for _, key := range []string{"search.html", "mobile/search.html"} {
		t.Run(key+" ignored", func(t *testing.T) {
			tmpl, found := cache[key]
			if !found {
				t.Fatalf("%s is not in the template cache", key)
			}

			vars := pageVars
			vars.IsMobile = strings.HasPrefix(key, "mobile/")
			vars.ScopeIgnored = true

			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, tmpl.Name(), vars); err != nil {
				t.Fatalf("rendering failed: %v", err)
			}
			if strings.Contains(buf.String(), "narrowing this search") {
				t.Error("the page says the bar is narrowing a search it is being left out of")
			}
		})
	}

	for _, key := range []string{"search.html", "mobile/search.html"} {
		t.Run(key, func(t *testing.T) {
			tmpl, found := cache[key]
			if !found {
				t.Fatalf("%s is not in the template cache", key)
			}

			var buf bytes.Buffer
			pageVars.IsMobile = strings.HasPrefix(key, "mobile/")
			if err := tmpl.ExecuteTemplate(&buf, tmpl.Name(), pageVars); err != nil {
				t.Fatalf("rendering failed: %v", err)
			}

			page := buf.String()
			// A halted execution leaves the page short and the document
			// unclosed, which is the shape the truncation took.
			if !strings.Contains(page, "</html>") {
				t.Errorf("the page stops early, so execution halted partway: %d bytes ending %q",
					len(page), page[max(0, len(page)-60):])
			}
			if !strings.Contains(page, "narrowing this search") {
				t.Error("a bar that is narrowing the search went unmentioned on the page it emptied")
			}
			// The suggestions have to carry the pinned bar forward, or
			// following one silently drops it.
			for _, alt := range pageVars.AltSearches {
				if !strings.Contains(page, alt.Label) {
					t.Errorf("the %q suggestion never rendered", alt.Label)
				}
			}
			if strings.Count(page, "scope=f%3afoil")+strings.Count(page, "scope=f%3Afoil") < len(pageVars.AltSearches) {
				t.Error("the suggestions dropped the pinned bar from their links")
			}
		})
	}
}

// TestScopeRowOpen pins what the chip has to do: close, and stay closed.
// A pinned filter opens the row the first time, but once it has been put
// away by hand the next search must not draw it again - that is what made
// the chip look like it had stopped answering.
func TestScopeRowOpen(t *testing.T) {
	tests := []struct {
		name   string
		scope  string
		cookie string
		want   bool
	}{
		{"a pinned filter opens the row", "f:foil", "", true},
		{"nothing pinned, nothing drawn", "", "", false},
		{"closed by hand stays closed", "f:foil", "0", false},
		{"opened by hand stays open", "", "1", true},
		{"reopened over a filter", "f:foil", "1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/search?q=x", nil)
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "SearchScopeOpen", Value: tt.cookie})
			}
			got := scopeRowOpen(r, tt.scope)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSearchScopeSurvivesReaderOptions is the shape that made the bar lie.
// hidePromos and hidePrelPack put is: filters of their own into the main
// query, and a merge that deduped on the filter name alone read those as
// something the reader had typed - so a pinned finish was dropped, on the
// settings of readers who never asked for any of this.
func TestSearchScopeSurvivesReaderOptions(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, opts := range [][]string{nil, {"hidePromos"}, {"hidePrelPack"}} {
		config := parseSearchOptionsNG("s:soa", nil, nil, opts)
		applySearchScope(&config, scopeFilters("is:foil"))

		var applied bool
		for _, filter := range config.CardFilters {
			if filter.Name != "is" || filter.Negate {
				continue
			}
			applied = applied || slices.Contains(filter.Values, "foil")
		}
		if !applied {
			t.Errorf("opts %v: the pinned is:foil never reached the search: %v",
				opts, filterNames(config.CardFilters))
		}
	}
}

// TestScopeIgnoredIsWhatTheBarSays keeps the red state honest: it means
// the search passes over the bar whole, not merely that the bar is odd.
func TestScopeIgnoredIsWhatTheBarSays(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	tests := []struct {
		scope   string
		ignored bool
	}{
		{"", false},
		{"f:foil", false},
		{"s:soa r:mythic", false},
		{"abrade", true},
		{"sdfsdfsdf", true},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			got := len(scopeFilters(tt.scope)) == 0 && tt.scope != ""
			if got != tt.ignored {
				t.Errorf("%q: ignored=%v, want %v", tt.scope, got, tt.ignored)
			}
		})
	}
}
