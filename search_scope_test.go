package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/suggest"
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
	return parseSearchOptionsNG(backend(), query, nil, nil, nil)
}

// TestSearchScopeAddsFilters is the case the bar exists for: a set pinned
// once, then a finish typed and retyped in the main bar.
func TestSearchScopeAddsFilters(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, typed := range []string{"is:foil", "is:nonfoil"} {
		config := parseForTest(t, typed)
		applySearchScope(&config, scopeFilters(backend(), "s:sos"))

		names := filterNames(config.CardFilters)
		if !slices.Contains(names, "edition") {
			t.Errorf("%q: the pinned set did not reach the search, filters are %v", typed, names)
		}
	}
}

// TestSearchScopeKeepsBothSides is the contract in place of a merge that
// picks a winner: both bars apply, always. Two editions do answer nothing,
// and that is the point - the empty page names the pinned bar and offers to
// drop it, where a bar quietly overruled reads as applied while it is not.
func TestSearchScopeKeepsBothSides(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	tests := []struct {
		typed  string
		pinned string
	}{
		{"s:mh3", "s:sos"},      // same axis: answers nothing, by the reader's own hand
		{"is:promo", "is:foil"}, // different axes under one filter name
		{"s:sos", "r:mythic"},   // the ordinary case
	}

	for _, tt := range tests {
		t.Run(tt.typed+" + "+tt.pinned, func(t *testing.T) {
			config := parseForTest(t, tt.typed)
			before := len(config.CardFilters)
			pinned := scopeFilters(backend(), tt.pinned)
			applySearchScope(&config, pinned)

			if len(config.CardFilters) != before+len(pinned) {
				t.Errorf("a pinned filter went missing: typed %v, pinned %v, merged %v",
					tt.typed, filterNames(pinned), filterNames(config.CardFilters))
			}
		})
	}
}

// TestSearchScopeIgnoresNames is the other half of the contract: the
// sticky bar carries filters, and pinning a card name is what the main
// bar is for.
func TestSearchScopeIgnoresNames(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	config := parseForTest(t, "is:foil")
	before := len(config.CardFilters)
	applySearchScope(&config, scopeFilters(backend(), "abrade"))

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
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, mode := range []string{"hashing", "scryfall"} {
		config := parseForTest(t, "is:foil")
		config.SearchMode = mode
		before := len(config.CardFilters)
		applySearchScope(&config, scopeFilters(backend(), "s:sos"))

		if len(config.CardFilters) != before {
			t.Errorf("%s mode was narrowed by the pinned bar: %v", mode, filterNames(config.CardFilters))
		}
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
		SearchRan:   true,
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
			if !strings.Contains(page, "scope-clear") || !strings.Contains(page, "CLEAR") {
				t.Error("the pinned bar has no explicit clear button")
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

// TestSearchScopeSurvivesReaderOptions is the shape that made the bar lie
// while the merge still picked winners. hidePromos and hidePrelPack put
// is: filters of their own into the main query, those were read as
// something the reader had typed, and a pinned finish was dropped on the
// settings of readers who never asked for any of this. Nothing is dropped
// now, and this stands to say so.
func TestSearchScopeSurvivesReaderOptions(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	for _, opts := range [][]string{nil, {"hidePromos"}, {"hidePrelPack"}} {
		config := parseSearchOptionsNG(backend(), "s:soa", nil, nil, opts)
		applySearchScope(&config, scopeFilters(backend(), "is:foil"))

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
	if len(backend().GetUUIDs()) == 0 {
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
			got := len(scopeFilters(backend(), tt.scope)) == 0 && tt.scope != ""
			if got != tt.ignored {
				t.Errorf("%q: ignored=%v, want %v", tt.scope, got, tt.ignored)
			}
		})
	}
}
