package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The markup each of the answers is recognised by: the landing panes, the
// results (found or empty-handed), the editions tree /sets draws instead of
// either, and the product browser that is /sealed's landing.
const (
	landingMarker = `class="search-landing"`
	setsMarker    = `class="page-standard sets-page"`
	sealedMarker  = `class="sealed-layout"`
)

// searchWithStock runs the search page over a request, with one card stocked
// so a search that reaches the stores has something to show - without a
// seller every result is filtered away for carrying no listing, and a page
// that found cards reads exactly like one that found none.
func searchWithStock(t *testing.T, stocked string, target string, cookies ...*http.Cookie) string {
	t.Helper()

	// render() only reparses templates from disk while DevMode is set, which
	// is the only template cache a test binary has; SigCheck off keeps every
	// page open to an unsigned request.
	prevDev, prevSig := DevMode, SigCheck
	DevMode, SigCheck = true, false
	t.Cleanup(func() { DevMode, SigCheck = prevDev, prevSig })

	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}

	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	stock := mtgban.InventoryRecord{}
	stock.Add(stocked, &mtgban.InventoryEntry{Conditions: "NM", Price: 1.5, Quantity: 1})
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(stock,
		mtgban.ScraperInfo{Name: "CK", Shorthand: "CK"})}
	sellersPtr.Store(&sellers)

	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	Search(rec, req)
	return rec.Body.String()
}

// scopedCard picks a card and the set filter that names it, which is the
// pinned bar this all turns on.
func scopedCard(t *testing.T) (uuid, name, scope string) {
	t.Helper()

	uuids := backend().GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}
	for _, id := range uuids {
		co, err := backend().GetUUID(id)
		if err != nil || co.Sealed {
			continue
		}
		return id, co.Name, "s:" + co.SetCode
	}
	t.Skip("no single card to scope by")
	return "", "", ""
}

// The point of the change: the pinned bar searches on its own, with the box
// above it empty. Before this the page went to the landing panes and the
// filter sat there doing nothing.
func TestScopeAloneRunsTheSearch(t *testing.T) {
	uuid, name, scope := scopedCard(t)

	out := searchWithStock(t, uuid, "/search?q=&scope="+url.QueryEscape(scope))

	if strings.Contains(out, landingMarker) {
		t.Fatalf("a pinned %q with no query fell back to the landing page", scope)
	}
	if !strings.Contains(out, name) {
		t.Errorf("the scoped search did not turn up %q, which its own set holds", name)
	}
}

// The sealed tab is a search too, and its empty state is a product browser
// rather than a placeholder - so the pinned bar has to get past that one as
// well.
func TestScopeAloneRunsTheSealedSearch(t *testing.T) {
	if len(backend().GetSealedUUIDs()) == 0 {
		t.Skip("this datastore carries no sealed product")
	}
	sealed := backend().GetSealedUUIDs()[0]
	co, err := backend().GetUUID(sealed)
	if err != nil {
		t.Skip("the sealed product does not resolve")
	}

	out := searchWithStock(t, sealed, "/sealed?scope="+url.QueryEscape("s:"+co.SetCode))

	if strings.Contains(out, sealedMarker) {
		t.Fatal("a pinned set with no query fell back to the product browser on /sealed")
	}
	if !strings.Contains(out, co.Name) {
		t.Errorf("the scoped sealed search did not turn up %q", co.Name)
	}
}

// The bar lives in the url alone, but browsers still carry the SearchScope
// and SearchScopeOpen cookies older builds wrote, good for ten years. A page
// opened with nothing in its url comes up with nothing pinned regardless:
// an empty bar, and the row put away.
func TestScopeIgnoresLeftoverCookies(t *testing.T) {
	uuid, _, scope := scopedCard(t)
	leftovers := []*http.Cookie{
		{Name: "SearchScope", Value: scope},
		{Name: "SearchScopeOpen", Value: "1"},
	}

	for _, page := range []string{"/search", "/sealed"} {
		out := searchWithStock(t, uuid, page, leftovers...)
		// Looked for rather than ruled out, so a page that failed to render
		// cannot pass for one with nothing pinned.
		if !strings.Contains(out, `name="scope" value=""`) {
			t.Errorf("%s did not come up with an empty pinned bar", page)
		}
		if strings.Contains(out, " has-scope") {
			t.Errorf("%s opened the pinned row from a cookie", page)
		}
	}
}

// A bar holding something the parser makes no filter of is not a search: it
// would seed nothing and answer nothing, and the landing page says that
// better than an empty result does. Same for a bar holding nothing at all.
func TestScopeThatFiltersNothingKeepsTheLanding(t *testing.T) {
	uuid, _, _ := scopedCard(t)

	for _, scope := range []string{"just some words", ""} {
		out := searchWithStock(t, uuid, "/search?q=&scope="+url.QueryEscape(scope))
		if !strings.Contains(out, landingMarker) {
			t.Errorf("scope=%q searched on nothing instead of showing the landing page", scope)
		}
	}
}

// The editions tree is the page /sets is for, not a placeholder waiting on a
// query, so a pinned filter does not replace it with a card list.
func TestScopeAloneLeavesTheEditionsTree(t *testing.T) {
	uuid, _, scope := scopedCard(t)

	out := searchWithStock(t, uuid, "/sets?scope="+url.QueryEscape(scope))

	if !strings.Contains(out, setsMarker) {
		t.Error("a pinned filter took /sets off its own editions tree")
	}
}

// A search that ran and found nothing is still a search: it owes the reader
// the reason and the way out, which live on the results page, not the
// landing page the request no longer qualifies for.
func TestScopeAloneThatFindsNothingSaysSo(t *testing.T) {
	uuid, _, scope := scopedCard(t)

	// Scoped to a set, but stocked with a card from wherever: every result
	// the scope names is dropped for carrying no listing.
	out := searchWithStock(t, uuid, "/search?q=&scope="+url.QueryEscape(scope+" is:etched cn:99999"))

	if strings.Contains(out, landingMarker) {
		t.Fatal("an empty-handed scope search showed the landing page instead of saying so")
	}
	if !strings.Contains(out, NoResultsMessage) && !strings.Contains(out, NoCardsMessage) {
		t.Error("the page came back without telling the reader nothing was found")
	}
}

// The parser is handed an empty query by both bars now - the search page when
// the pinned bar is doing the searching, and the export links the results page
// builds, which carry the query in the path and so name /api/search/retail/.csv
// when there is none. It indexed the last byte before checking there was one.
func TestParseEmptyQueryIsNotACrash(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      string
		blocklists bool
	}{
		{"nothing at all", "", false},
		{"nothing, with blocklists to carry", "", true},
		{"a trailing special the cleaner trims", "&", false},
		{"one that trims away to nothing", "&*~`", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var retail, buylist []string
			if tc.blocklists {
				retail, buylist = []string{"CK"}, []string{"CK"}
			}

			config := parseSearchOptionsNG(tc.query, retail, buylist, nil)

			// The blocklists are the one thing an empty query still carries:
			// they are what keeps a search off the stores a reader blocked.
			if tc.blocklists && len(config.StoreFilters) == 0 {
				t.Error("the blocklists did not survive an empty query")
			}
		})
	}
}

// The page that says nothing was found has a query to quote on one route and
// not on the other, and quoting the one it does not have reads as a bug.
func TestEmptyHandedScopeSearchQuotesNoQuery(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, PageVars{
			BetaNav:     &NavElem{Short: "b"},
			SearchRan:   true,
			SearchScope: "s:LEA",
			InfoMessage: NoResultsMessage,
		})

		// The empty query, quoted: "No results for &ldquo;&rdquo;." Matching
		// the quotes themselves rather than a bare pair of "" characters,
		// which every empty html attribute on the page also carries.
		if strings.Contains(out, "&ldquo;&rdquo;") || strings.Contains(out, "\u201c\u201d") {
			t.Errorf("mobile=%v: the page quotes the query it does not have", mobile)
		}
		if !strings.Contains(out, NoResultsMessage) {
			t.Errorf("mobile=%v: the page does not say what happened", mobile)
		}
		if !strings.Contains(out, "s:LEA") {
			t.Errorf("mobile=%v: the page does not name the bar it searched on", mobile)
		}
	}
}
