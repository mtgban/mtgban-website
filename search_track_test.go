package main

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/suggest"
	"github.com/mtgban/mtgban-website/observability"
)

// track is the attribute run a tracked control ends its opening tag with.
func track(name, value, scope string) string {
	s := `data-track="` + name + `"`
	if value != "" {
		s += ` data-track-value="` + value + `"`
	}
	if scope != "" {
		s += ` data-track-scope="` + scope + `"`
	}
	return s
}

// wantTracks fails for each attribute run that does not occur exactly n times.
func wantTracks(t *testing.T, page, out string, want map[string]int) {
	t.Helper()
	for attr, n := range want {
		if got := strings.Count(out, attr); got != n {
			t.Errorf("%s: %s occurs %d times, want %d", page, attr, got, n)
		}
	}
}

var (
	markedTag = regexp.MustCompile(`<[a-zA-Z][^>]*\bdata-track(?:-value|-scope)?="[^>]*>`)
	trackAttr = regexp.MustCompile(`\bdata-track(-value|-scope)?="([^"]*)"`)
)

// closedTrackSet fails for each value or scope in out outside its name's
// registered set; stores are the shorthands a store-typed value may take.
func closedTrackSet(t *testing.T, page, out string, stores ...string) {
	t.Helper()
	for _, p := range trackSetProblems(out, stores) {
		t.Errorf("%s: %s", page, p)
	}
}

// trackSetProblems lists each marked tag in out whose name, value or scope the registry refuses.
func trackSetProblems(out string, stores []string) []string {
	var problems []string
	for _, tag := range markedTag.FindAllString(out, -1) {
		attrs := map[string]string{}
		for _, m := range trackAttr.FindAllStringSubmatch(tag, -1) {
			attrs[m[1]] = m[2]
		}
		name, ok := attrs[""]
		n, found := observability.Lookup(name)
		if !ok || !found {
			problems = append(problems, tag+" carries no registered name")
			continue
		}
		if v, ok := attrs["-value"]; ok && !trackValueAllowed(n, v, stores) {
			problems = append(problems, fmt.Sprintf("%s value %q is outside its registered set", name, v))
		}
		if s, ok := attrs["-scope"]; ok && !trackScopeAllowed(n, s, stores) {
			problems = append(problems, fmt.Sprintf("%s scope %q is outside its registered set", name, s))
		}
	}
	return problems
}

// The closed set refuses what the registry does not list, and passes what it does.
func TestTrackSetProblems(t *testing.T) {
	good := `<a data-track="ui.row.store" data-track-value="CK" data-track-scope="seller"><b data-track="ui.home" data-track-value="random">`
	if p := trackSetProblems(good, []string{"CK"}); len(p) != 0 {
		t.Errorf("listed values flagged: %q", p)
	}
	for _, bad := range []string{
		`<a data-track="ui.home" data-track-value="zzquery">`,
		`<a data-track="ui.row.store" data-track-value="ZZ" data-track-scope="seller">`,
		`<a data-track="ui.row.store" data-track-value="CK" data-track-scope="zz">`,
		`<a data-track="ui.sealed.toc" data-track-value="ZZA">`,
		`<a data-track-value="open">`,
	} {
		if p := trackSetProblems(bad, []string{"CK"}); len(p) != 1 {
			t.Errorf("%s: want one problem, got %q", bad, p)
		}
	}
}

func trackValueAllowed(n observability.Name, v string, stores []string) bool {
	switch n.Values {
	case observability.ValueNone:
		return v == ""
	case observability.ValueEnum, observability.ValueBucket:
		return slices.Contains(n.Enum, v)
	case observability.ValueFlag:
		return v == "on" || v == "off"
	case observability.ValueStore:
		return v == "other" || slices.Contains(stores, v)
	}
	return false
}

func trackScopeAllowed(n observability.Name, s string, stores []string) bool {
	switch n.Scope {
	case observability.ScopeEnum:
		return slices.Contains(n.Scopes, s)
	case observability.ScopeStore:
		return slices.Contains(stores, s)
	}
	return false
}

// noTrackText fails when a marker is not on the page, or appears in any data-track attribute of out.
func noTrackText(t *testing.T, page, out string, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(marker)) {
			t.Errorf("%s: %q is not on the page, so its absence proves nothing", page, marker)
		}
	}
	for _, m := range trackAttr.FindAllStringSubmatch(out, -1) {
		for _, marker := range markers {
			if strings.Contains(strings.ToLower(m[2]), strings.ToLower(marker)) {
				t.Errorf("%s: %q reached a count attribute: %s", page, marker, m[0])
			}
		}
	}
}

// trackPage is one card, not sealed, with everything a result header can show.
func trackPage() PageVars {
	const id = "card"
	return PageVars{
		UserNav:     &NavElem{Short: "b"},
		PatreonIDs:  map[string]string{"ban": "client"},
		HasVelocity: true,
		ShowUpsell:  true,
		Metadata: cardMetadata{id: {
			UUID: id, ChartID: id, Name: "A Card", SetCode: "TST", Edition: "Test Set", Date: "2020-01-02",
			Treatments: []string{"galaxyfoil"}, PromoTypes: []string{"showcase"},
			PromoLabels:  map[string]string{"galaxyfoil": "Galaxy Foil", "showcase": "Showcase"},
			SourceSealed: []string{"box"}, TCGId: "1",
			DeckboxURL: "https://example.test/d", CKRestockURL: "https://example.test/r", ScryfallURL: "https://example.test/s",
			Velocity: "1.2",
		}},
		SearchVars: SearchVars{
			SearchRan: true, SearchQuery: "a card", AllKeys: []string{id},
			CondKeys:     []mtgban.Condition{"INDEX", "NM", "SP"},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{},
			CanFixSearch: true, HasAvailable: true, CanAlerts: true,
		},
	}
}

func TestResultHeaderTracks(t *testing.T) {
	desktop := renderPage(t, "search.html", false, trackPage())
	want := map[string]int{
		track("ui.result.link", "set_icon", ""):          1,
		track("ui.result.link", "name", ""):              1,
		track("ui.result.link", "treatment", ""):         1,
		track("ui.result.link", "set_title", ""):         1,
		track("ui.result.link", "found_in_products", ""): 1,
		track("ui.result.link", "promo_type", ""):        1,
		track("ui.result.icon_menu", "open", ""):         1,
		track("ui.result.image", "focus_search", ""):     1,
	}
	for _, v := range []string{"admin_raw", "admin_fix", "find_in_sealed", "copy_name", "deckbox", "ck_restock",
		"scryfall", "tcg_inventory", "chart_view", "view_image", "star_add", "pack_add", "pack_take", "bell"} {
		want[track("ui.result.icon", v, "header")] = 1
	}
	want[`data-track-scope="menu"`] = 0 // the kebab moves icons there at click time
	wantTracks(t, "desktop", desktop, want)

	mv := trackPage()
	mv.IsMobile = true
	mobile := renderPage(t, "search.html", true, mv)
	want = map[string]int{
		track("ui.result.image", "drawer_open", ""):    1,
		track("ui.result.link", "treatment", ""):       1,
		track("ui.result.link", "promo_type", ""):      1,
		track("ui.result.link", "name", ""):            0,
		track("ui.result.icon_menu", "open", ""):       1,
		track("ui.result.image", "reveal_warning", ""): 0, // no warning on this card
	}
	for _, v := range []string{"star_add", "pack_add", "pack_take", "chart_view"} {
		want[track("ui.result.icon", v, "header")] = 1
	}
	for _, v := range []string{"star_add", "pack_add", "pack_take", "bell", "chart_view", "find_in_sealed",
		"copy_name", "deckbox", "ck_restock", "scryfall", "tcg_inventory"} {
		want[track("ui.result.icon", v, "menu")] = 1
	}
	wantTracks(t, "mobile", mobile, want)

	// The landscape image counts only where tapping it reveals a warning.
	mv.Metadata["card"] = withWarning(mv.Metadata["card"])
	wantTracks(t, "mobile warning", renderPage(t, "search.html", true, mv), map[string]int{
		track("ui.result.image", "reveal_warning", ""): 1,
	})
}

func withWarning(c GenericCard) GenericCard {
	c.HasContentWarning = true
	return c
}

// The sealed-only icons and the two chart roster links.
func TestSealedAndRosterIconsTrack(t *testing.T) {
	sealed := func(mobile bool) PageVars {
		v := trackPage()
		v.IsMobile = mobile
		c := v.Metadata["card"]
		c.Sealed, c.Booster, c.HasDeck = true, true, true
		v.Metadata["card"] = c
		return v
	}
	for _, c := range []struct {
		mobile bool
		scope  string
	}{{false, "header"}, {true, "menu"}} {
		out := renderPage(t, "search.html", c.mobile, sealed(c.mobile))
		want := map[string]int{track("ui.result.icon", "find_in_sealed", c.scope): 0}
		for _, v := range []string{"unpack", "decklist_tcg", "decklist_mkm", "contents"} {
			want[track("ui.result.icon", v, c.scope)] = 1
		}
		wantTracks(t, "sealed "+c.scope, out, want)
	}

	v := trackPage()
	v.ChartIDsCSV, v.ChartIDs = "other", []string{"other"}
	wantTracks(t, "roster without the card", renderPage(t, "search.html", false, v), map[string]int{
		track("ui.result.icon", "chart_add", "header"):  1,
		track("ui.result.icon", "chart_view", "header"): 0,
	})
	v.ChartIDsCSV, v.ChartIDs = "card,other", []string{"card", "other"}
	wantTracks(t, "roster with the card", renderPage(t, "search.html", false, v), map[string]int{
		track("ui.result.icon", "chart_remove", "header"): 1,
	})

	// The sole card on a chart shows a static glyph, which is not a control.
	v.ChartIDsCSV, v.ChartIDs = "card", []string{"card"}
	out := renderPage(t, "search.html", false, v)
	if i := strings.Index(out, `title="The only card on this chart"`); i < 0 {
		t.Error("the sole-card glyph is not rendered")
	} else if tag := out[strings.LastIndex(out[:i], "<"):i]; strings.Contains(tag, "data-track") {
		t.Errorf("the sole-card glyph is tracked: %s", tag)
	}
}

func TestSortBarTracks(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		v := trackPage()
		v.IsMobile = mobile
		v.SearchSort = "retail"
		v.AlphaSort = "hybrid"
		v.TotalUnique = 1
		v.CanVelocity = false
		v.Contents = &ContentsViews{Product: "A Box", Mode: "variable", All: "a", Fixed: "b", Variable: "c"}
		out := renderPage(t, "search.html", mobile, v)
		want := map[string]int{
			track("ui.search.sort", "chrono", "sort"):          1,
			track("ui.search.sort", "alpha", "sort"):           1,
			track("ui.search.sort", "number", "sort"):          1,
			track("ui.search.sort", "retail", "reverse"):       1,
			track("ui.search.sort", "buylist", "sort"):         1,
			track("ui.search.sort", "odds", "sort"):            1,
			track("ui.search.sort", "velocity", "sort"):        0,
			track("ui.search.sort_locked", "velocity", ""):     1,
			track("ui.search.contents_mode", "everything", ""): 1,
			track("ui.search.contents_mode", "fixed", ""):      1,
			track("ui.search.contents_mode", "variable", ""):   1,
			`data-track-value="hybrid"`:                        0,
		}
		if mobile {
			want[`data-track="ui.search.random"`] = 0
			want[`data-track="ui.search.chart_top"`] = 0
		} else {
			want[track("ui.search.random", "card", "")] = 1
		}
		wantTracks(t, fmt.Sprintf("mobile=%v", mobile), out, want)
	}
}

// With no sort chosen the chronological pill is the active one.
func TestDefaultSortIsReversedByItsOwnPill(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		v := trackPage()
		v.IsMobile = mobile
		v.TotalUnique = 1
		v.CanVelocity = true
		wantTracks(t, fmt.Sprintf("mobile=%v", mobile), renderPage(t, "search.html", mobile, v), map[string]int{
			track("ui.search.sort", "chrono", "reverse"): 1,
			track("ui.search.sort", "chrono", "sort"):    0,
			track("ui.search.sort", "velocity", "sort"):  1,
			`data-track="ui.search.sort_locked"`:         0,
			`data-track="ui.search.contents_mode"`:       0, // no product, no contents row
			track("ui.search.sort", "retail", "reverse"): 0,
		})
	}
}

func TestSidebarTracks(t *testing.T) {
	v := trackPage()
	v.CanShowAll = true
	v.Alternative, v.AltEtchedID = "x", "y"
	v.StocksURL = "https://example.test/m"
	v.CanDownloadCSV = true
	v.CardHashes = []string{"card"}
	v.AllKeys = []string{"card", "card2"}
	v.Metadata["card2"] = GenericCard{UUID: "card2", ChartID: "card2", Name: "B Card", SetCode: "TST"}
	want := map[string]int{
		track("ui.search.chart_top", "", ""):  1,
		track("ui.search.random", "card", ""): 1,
	}
	for _, l := range []string{"show_all_versions", "switch_foil", "switch_etched", "mtgstocks"} {
		want[track("ui.sidebar.link", l, "")] = 1
	}
	for _, e := range []string{"retail", "buylist", "list"} {
		want[track("ui.sidebar.export", e, "")] = 1
	}
	for _, u := range []string{"retail", "buylist"} {
		want[track("ui.sidebar.upload", u, "")] = 1
	}
	out := renderPage(t, "search.html", false, v)
	wantTracks(t, "desktop", out, want)
	// The Available In toggle counts by script, not by a mark.
	if i := strings.Index(out, `id="productsToggle"`); i < 0 {
		t.Error("the products toggle is not rendered")
	} else if tag := out[strings.LastIndex(out[:i], "<") : i+strings.Index(out[i:], ">")]; strings.Contains(tag, "data-track") {
		t.Errorf("the products toggle is marked: %s", tag)
	}

	v.IsSealed = true
	wantTracks(t, "sealed", renderPage(t, "search.html", false, v), map[string]int{
		track("ui.search.random", "sealed", ""): 1,
		track("ui.search.random", "card", ""):   0,
	})
}

// rowsPage is trackPage with offers: a store with a link, a fallback row with a link and no
// shorthand, a row with no link, and a locked row, on both sides.
func rowsPage() PageVars {
	v := trackPage()
	rows := func() []SearchEntry {
		return []SearchEntry{
			{ScraperName: "Card Kingdom", Shorthand: "CK", Price: 5, Credit: 4, URL: "https://example.test/ck"},
			{ScraperName: "TCGplayer", URL: "https://example.test/tcg", NoQuantity: true},
			{ScraperName: "No Link Games", Shorthand: "NL", Price: 4},
			{ScraperName: "Gated", Shorthand: "GT", Locked: true},
		}
	}
	v.FoundSellers["card"] = map[mtgban.Condition][]SearchEntry{"NM": rows()}
	v.FoundVendors["card"] = map[mtgban.Condition][]SearchEntry{"NM": rows()}
	v.MobileSearchLayout = "compact"
	return v
}

func TestRowStoreTracks(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		v := rowsPage()
		v.IsMobile = mobile
		out := renderPage(t, "search.html", mobile, v)
		wantTracks(t, fmt.Sprintf("mobile=%v", mobile), out, map[string]int{
			track("ui.row.store", "CK", "seller"):    1,
			track("ui.row.store", "CK", "buyer"):     1,
			track("ui.row.store", "other", "seller"): 1,
			track("ui.row.store", "other", "buyer"):  1,
			`data-track="ui.row.store"`:              4, // the row with no link and the locked row have none
			`data-track-value="NL"`:                  0,
			`data-track-value="GT"`:                  0,
			`data-track-value="TCGplayer"`:           0, // a display name is never a value
			`data-track-value="Card Kingdom"`:        0,
			track("ui.row.locked", "join", ""):       2,
			track("ui.row.locked", "login", ""):      2,
		})
	}

	// The sealed index rows sit in a grid of their own on desktop, and on mobile in the INDEX group.
	for _, mobile := range []bool{false, true} {
		v := rowsPage()
		v.IsMobile = mobile
		c := v.Metadata["card"]
		c.Sealed = true
		v.Metadata["card"] = c
		v.FoundSellers["card"]["INDEX"] = []SearchEntry{{ScraperName: "TCG (Low / Market)", Shorthand: "TCGLow", Price: 9, URL: "https://example.test/i"}}
		wantTracks(t, fmt.Sprintf("sealed mobile=%v", mobile), renderPage(t, "search.html", mobile, v), map[string]int{
			track("ui.row.store", "TCGLow", "seller"): 1,
		})
	}
}

func TestRowControlsTrack(t *testing.T) {
	v := rowsPage()
	v.CanVelocity = false
	wantTracks(t, "desktop", renderPage(t, "search.html", false, v), map[string]int{
		track("ui.row.locked", "velocity_upsell", ""): 1,
		track("ui.row.admin_fix", "retail", ""):       3, // every unlocked row, linked or not
		track("ui.row.admin_fix", "buylist", ""):      3,
	})
	v.CanFixSearch = false
	wantTracks(t, "desktop, no fix mode", renderPage(t, "search.html", false, v), map[string]int{
		`data-track="ui.row.admin_fix"`: 0,
	})

	pages := []struct {
		at   Pagination
		want map[string]int
	}{
		{Pagination{CurrentIndex: 2, TotalIndex: 3, PrevIndex: 1, NextIndex: 3}, map[string]int{
			track("ui.search.pager", "first", ""): 1, track("ui.search.pager", "prev", ""): 1,
			track("ui.search.pager", "next", ""): 1, track("ui.search.pager", "last", ""): 1,
		}},
		{Pagination{CurrentIndex: 1, TotalIndex: 3, NextIndex: 2}, map[string]int{
			track("ui.search.pager", "first", ""): 0, track("ui.search.pager", "prev", ""): 0,
			track("ui.search.pager", "next", ""): 1, track("ui.search.pager", "last", ""): 1,
		}},
	}
	for _, mobile := range []bool{false, true} {
		for _, p := range pages {
			v := rowsPage()
			v.IsMobile = mobile
			v.Pagination = p.at
			wantTracks(t, fmt.Sprintf("pager %d mobile=%v", p.at.CurrentIndex, mobile), renderPage(t, "search.html", mobile, v), p.want)
		}
	}

	v = rowsPage()
	v.IsMobile = true
	v.CanVelocity = false
	wantTracks(t, "mobile compact", renderPage(t, "search.html", true, v), map[string]int{
		track("ui.row.tab", "sellers", ""):            1,
		track("ui.row.tab", "buyers", ""):             1,
		track("ui.row.condition", "NM", ""):           1,
		track("ui.row.condition", "INDEX", ""):        0,
		track("ui.row.locked", "velocity_upsell", ""): 1,
		`data-track="ui.row.admin_fix"`:               0,
	})
	v.FoundSellers["card"]["INDEX"] = []SearchEntry{{ScraperName: "TCG Market", Shorthand: "TCGMarket", Price: 9}}
	wantTracks(t, "mobile compact with an index", renderPage(t, "search.html", true, v), map[string]int{
		track("ui.row.condition", "INDEX", ""): 1,
		track("ui.row.condition", "NM", ""):    1,
	})
	v.MobileSearchLayout = "expanded"
	wantTracks(t, "mobile expanded", renderPage(t, "search.html", true, v), map[string]int{
		`data-track="ui.row.tab"`:       0,
		`data-track="ui.row.condition"`: 0,
	})
}

func TestEmptyResultSuggestionsTrack(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		v := trackPage()
		v.IsMobile = mobile
		v.AllKeys = nil
		v.SearchScope = "f:foil"
		v.DidYouMean = []string{"bolt"}
		v.AltSearches = []suggest.AltSearch{{Label: "x", Query: "y"}}
		v.PopularSearches = []PopularSearch{{Label: "p", URL: "/search?q=p"}}
		want := map[string]int{
			track("ui.search.suggestion", "unpin_scope", ""):  1,
			track("ui.search.suggestion", "did_you_mean", ""): 1,
			track("ui.search.suggestion", "try_one_of", ""):   1,
			track("ui.search.suggestion", "popular", ""):      1,
		}
		if mobile {
			want[track("ui.search.suggestion", "popular", "")] = 0
		}
		wantTracks(t, fmt.Sprintf("mobile=%v", mobile), renderPage(t, "search.html", mobile, v), want)
	}
}

// A tap the header's own handler never sees must not be counted as the header's.
func TestStopPropagationControlsAreTracked(t *testing.T) {
	v := rowsPage()
	v.IsMobile = true
	out := renderPage(t, "search.html", true, v)
	tags := regexp.MustCompile(`<[a-z]+ [^>]*event\.stopPropagation\(\)[^>]*>`).FindAllString(out, -1)
	if len(tags) == 0 {
		t.Fatal("no control stops propagation: the pattern no longer reads the page")
	}
	for _, tag := range tags {
		if !strings.Contains(tag, `data-track="`) {
			t.Errorf("stops propagation with no data-track of its own: %s", tag)
		}
	}
}

// mobileOf is v on the mobile templates.
func mobileOf(v PageVars) PageVars {
	v.IsMobile = true
	return v
}

// modalOf is v inside the chart's "Add card" iframe.
func modalOf(v PageVars) PageVars {
	v.ModalMode = true
	return v
}

func TestSearchBarsTrack(t *testing.T) {
	scoped := func(v PageVars) PageVars { v.CanScope = true; return v }
	for _, c := range []struct {
		page, tmpl string
		mobile     bool
		vars       PageVars
		want       map[string]int
	}{
		{"desktop results", "search.html", false, scoped(trackPage()), map[string]int{
			track("ui.searchbar.submit", "nav", ""): 1,
			`data-track="ui.scope.clear"`:           1,
			track("ui.scope.chip", "nonfoil", ""):   1,
			track("ui.scope.chip", "foil", ""):      1,
			track("ui.scope.chip", "altfoil", ""):   1,
		}},
		{"desktop home", "home.html", false, PageVars{UserNav: &NavElem{Short: "b"}}, map[string]int{
			track("ui.searchbar.submit", "home", ""): 1,
		}},
		{"mobile home", "home.html", true, PageVars{UserNav: &NavElem{Short: "b"}, IsMobile: true}, map[string]int{
			track("ui.searchbar.submit", "home", ""): 1,
			track("ui.searchbar.submit", "nav", ""):  1,
		}},
		{"mobile results", "search.html", true, scoped(mobileOf(trackPage())), map[string]int{
			track("ui.searchbar.submit", "results", ""): 1,
			track("ui.searchbar.submit", "nav", ""):     1,
			`data-track="ui.scope.clear"`:               1,
			`data-track="ui.mfilter.open"`:              2,
			`data-track="ui.scope.chip"`:                0,
		}},
		{"mobile landing", "search.html", true, PageVars{UserNav: &NavElem{Short: "b"}, IsMobile: true}, map[string]int{
			track("ui.searchbar.submit", "landing", ""): 1,
			`data-track="ui.mfilter.open"`:              1, // the navbar's; the page has no sheet to open
		}},
		{"mobile sealed landing", "search.html", true, PageVars{UserNav: &NavElem{Short: "b"}, IsMobile: true, SearchVars: SearchVars{EditionSort: []string{"Boxes"}}}, map[string]int{
			track("ui.searchbar.submit", "landing", ""): 1,
			`data-track="ui.mfilter.open"`:              1, // its own button opens the category sheet
		}},
		{"the chart modal's home", "home.html", false, modalOf(PageVars{UserNav: &NavElem{Short: "b"}}), map[string]int{
			track("ui.searchbar.submit", "modal", ""): 1,
			track("ui.searchbar.submit", "home", ""):  0,
			track("ui.searchbar.submit", "nav", ""):   0, // the iframe has no navbar
		}},
	} {
		wantTracks(t, c.page, renderPage(t, c.tmpl, c.mobile, c.vars), c.want)
	}
}

// applyFilters is an inline function no render test runs.
func TestMobileFilterApplyIsCounted(t *testing.T) {
	src, err := os.ReadFile("templates/mobile/search.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `BAN.track('ui.mfilter.apply', setVal && finish ? 'both' : setVal ? 'set' : finish ? 'finish' : 'none')`) {
		t.Error("applyFilters does not count what it applied")
	}
}

func TestChartControlsTrack(t *testing.T) {
	v := trackPage()
	v.ChartID = "card"
	v.ChartIDs = []string{"card"}
	v.ChartIDsCSV = "card"
	v.MaxChartCards = 10
	v.MaxLookbackDays = 3650
	v.AxisLabels = []string{"2026-01-01"}
	v.Datasets = []Dataset{{}}
	out := renderPage(t, "search.html", false, v)
	wantTracks(t, "desktop chart", out, map[string]int{
		`data-track="ui.chart.download"`:              1,
		track("ui.chart.add_modal", "open", ""):       1,
		track("ui.chart.add_modal", "new_search", ""): 1,
		track("ui.chart.add_modal", "commit", ""):     1,
		track("ui.chart.add_modal", "close", ""):      0, // closeChartAddModal counts every way it closes
	})
	if !strings.Contains(out, `src="/js/search-track.js?`) {
		t.Error("the chart page does not load search-track.js, which counts roster links")
	}

	// A full chart draws its Add card as a span, which opens nothing.
	v.MaxChartCards = 1
	wantTracks(t, "full chart", renderPage(t, "search.html", false, v), map[string]int{
		`data-track="ui.chart.add_modal"`: 2,
	})

	m := trackPage()
	m.IsMobile = true
	wantTracks(t, "mobile drawer", renderPage(t, "search.html", true, m), map[string]int{
		`data-track="ui.mchart.reset_zoom"`: 1,
	})
}

func TestSealedIndexTracks(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		v := PageVars{UserNav: &NavElem{Short: "b"}, IsMobile: mobile, SearchVars: SearchVars{
			IsSealed:    true,
			EditionSort: []string{"Zzcategory"},
			EditionList: map[string][]EditionEntry{"Zzcategory": {{Name: "Zzname A", Code: "ZZA"}, {Name: "Zzname B", Code: "ZZB"}}},
		}}
		page := fmt.Sprintf("mobile=%v", mobile)
		out := renderPage(t, "search.html", mobile, v)
		wantTracks(t, page, out, map[string]int{
			`data-track="ui.sealed.toc"`:     1,
			`data-track="ui.sealed.edition"`: 2,
		})
		closedTrackSet(t, page, out)
		noTrackText(t, page, out, "Zzcategory", "Zzname A", "ZZA")
	}
}

func TestEditionsPageTracks(t *testing.T) {
	edition := FlatEditionEntry{
		EditionEntry: EditionEntry{Name: "Zzname", Code: "ZZC", Rarities: []string{"rare"}},
		Finishes:     []FinishOption{{Query: "zzfinish", Label: "Zzlabel"}},
		ColorHex:     []ColorEntry{{Name: "zzcolor", Hex: "#ffffff"}},
	}
	for _, c := range []struct {
		mobile bool
		file   string
	}{{false, "templates/sets.html"}, {true, "templates/mobile/sets.html"}} {
		v := PageVars{UserNav: &NavElem{Short: "b"}, IsMobile: c.mobile, SearchVars: SearchVars{FlatEditions: []FlatEditionEntry{edition}}}
		out := renderPage(t, "sets.html", c.mobile, v)
		wantTracks(t, c.file, out, map[string]int{
			track("ui.sets", "set", ""):        1,
			track("ui.sets", "finish_tag", ""): 1,
			track("ui.sets", "color_tag", ""):  1,
			track("ui.sets", "rarity_tag", ""): 1,
		})
		closedTrackSet(t, c.file, out)
		noTrackText(t, c.file, out, "Zzname", "ZZC", "zzfinish", "Zzlabel", "zzcolor", "rare")
		src, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		wantTracks(t, c.file+" source", string(src), map[string]int{
			`BAN.track('ui.sets', 'expand')`:      1,
			`BAN.track('ui.sets', 'filter_used')`: 1,
			`{once: true}`:                        1,
		})
	}
}

func TestHomeTracks(t *testing.T) {
	home := PageVars{
		UserNav: &NavElem{Short: "b"},
		Nav:     []NavElem{{Name: "Home", Link: "/"}, {Name: "Zztool", Short: "Zs", Link: "/zzlink"}, {Name: "Account", Link: "/user"}},
		PopularSearches: []PopularSearch{
			{Label: "zzlabel one", URL: "/search?q=zzone", ImageURL: "/img/zza.jpg"},
			{Label: "zzlabel two", URL: "/search?q=zztwo", ImageURL: "/img/zzb.jpg"},
		},
		MetricsVars: MetricsVars{MetricsPage: "home"},
	}
	desktop := renderPage(t, "home.html", false, home)
	wantTracks(t, "desktop", desktop, map[string]int{
		track("ui.home", "tool_tile", ""):                                         1,
		track("ui.home", "popular_card", ""):                                      4, // the strip is drawn twice for its loop
		track("ui.home", "random", ""):                                            1,
		`data-track="ui.home"`:                                                    6,
		`BAN.track('ui.home', collapsed ? 'popular_collapse' : 'popular_expand')`: 1,
	})
	closedTrackSet(t, "desktop", desktop)
	noTrackText(t, "desktop", desktop, "zzlabel", "zzone", "zza.jpg", "Zztool", "Zs", "zzlink")
	wantTracks(t, "modal", renderPage(t, "home.html", false, modalOf(home)), map[string]int{
		track("ui.home", "tool_tile", ""):    0,
		track("ui.home", "popular_card", ""): 0,
		track("ui.home", "random", ""):       0,
		`data-track="ui.home"`:               0,
	})
	mobile := renderPage(t, "home.html", true, mobileOf(home))
	wantTracks(t, "mobile", mobile, map[string]int{
		track("ui.home", "tool_tile", ""):    1,
		track("ui.home", "popular_card", ""): 0,
		`data-track-value="random"`:          0,
	})
	closedTrackSet(t, "mobile", mobile)
	// A refusal borrows the template with no page label; a home error sends no load either.
	refused, withError := home, home
	refused.MetricsPage = ""
	refused.ErrorMessage = "Unauthorized"
	withError.ErrorMessage = "Your session has expired"
	for _, c := range []struct {
		name string
		pv   PageVars
	}{{"refusal", refused}, {"refusal, mobile", mobileOf(refused)}, {"home error", withError}, {"home error, mobile", mobileOf(withError)}} {
		wantTracks(t, c.name, renderPage(t, "home.html", c.pv.IsMobile, c.pv), map[string]int{
			`data-track="ui.home"`: 0,
			`BAN.track('ui.home'`:  0,
		})
	}
}
