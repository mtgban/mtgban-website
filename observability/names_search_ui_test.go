package observability

import (
	"slices"
	"strings"
	"testing"
)

// Each case is one (name, scope, value) a search page control sends, and what is stored.
func TestSearchUINames(t *testing.T) {
	v := Validators{Store: func(s string) bool { return s == "CK" }}
	for _, c := range []struct {
		name, scope, value string
		wantS, wantV       string
		ok                 bool
	}{
		{"ui.result.link", "", "set_icon", "", "set_icon", true},
		{"ui.result.link", "", "A Card Name", "", "", false},
		{"ui.result.icon", "header", "star_add", "header", "star_add", true},
		{"ui.result.icon", "menu", "bell", "menu", "bell", true},
		{"ui.result.icon", "sidebar", "bell", "", "", false},
		{"ui.result.icon", "", "bell", "", "", false}, // a scoped name always carries a scope
		{"ui.result.icon_menu", "", "open", "", "open", true},
		{"ui.result.image", "", "drawer_open", "", "drawer_open", true},
		{"ui.search.sort", "sort", "retail", "sort", "retail", true},
		{"ui.search.sort", "reverse", "odds", "reverse", "odds", true},
		{"ui.search.sort", "sort", "hybrid", "", "", false},
		{"ui.search.sort", "", "retail", "", "", false},
		{"ui.search.sort_locked", "", "velocity", "", "velocity", true},
		{"ui.search.chart_top", "", "", "", "", true},
		{"ui.search.random", "", "sealed", "", "sealed", true},
		{"ui.search.contents_mode", "", "fixed", "", "fixed", true},
		{"ui.sidebar.printing", "", "overflow", "", "overflow", true},
		{"ui.sidebar.printings_more", "", "filter_used", "", "filter_used", true},
		{"ui.sidebar.link", "", "mtgstocks", "", "mtgstocks", true},
		{"ui.sidebar.products", "", "click", "", "click", true},
		{"ui.sidebar.export", "", "list", "", "list", true},
		{"ui.sidebar.upload", "", "buylist", "", "buylist", true},
		{"ui.row.store", "seller", "CK", "seller", "CK", true},
		{"ui.row.store", "buyer", "CK", "buyer", "CK", true},
		{"ui.row.store", "seller", "Bob's Cards & Games", "seller", "other", true},
		{"ui.row.store", "seller", "other", "seller", "other", true},
		{"ui.row.store", "seller", "", "seller", "other", true},
		{"ui.row.store", "sidebar", "CK", "", "", false},
		{"ui.row.locked", "", "velocity_upsell", "", "velocity_upsell", true},
		{"ui.row.velocity", "", "open", "", "open", true},
		{"ui.row.detail", "", "open", "", "open", true},
		{"ui.row.tab", "", "buyers", "", "buyers", true},
		{"ui.row.condition", "", "INDEX", "", "INDEX", true},
		{"ui.row.condition", "", "DMG", "", "", false},
		{"ui.row.admin_fix", "", "retail", "", "retail", true},
		{"ui.search.pager", "", "last", "", "last", true},
		{"ui.search.suggestion", "", "unpin_scope", "", "unpin_scope", true},
		{"ui.chart.roster", "page", "add", "page", "add", true},
		{"ui.chart.roster", "", "add", "", "", false},
		{"ui.searchbar.submit", "", "results", "", "results", true},
		{"ui.searchbar.submit", "", "modal", "", "modal", true},
		{"ui.searchbar.submit", "", "bolt", "", "", false},
		{"ui.autocomplete.pick", "", "name", "", "", false},
		{"ui.autocomplete.pick", "name", "name", "name", "name", true},
		{"ui.autocomplete.pick", "s:", "token", "s:", "token", true},
		{"ui.autocomplete.pick", "name", "complete", "name", "complete", true},
		{"ui.autocomplete.pick", "-s:", "token", "", "", false},
		{"ui.autocomplete.pick", "name", "Lightning Bolt", "", "", false},
		{"ui.scope.toggle", "", "close", "", "close", true},
		{"ui.scope.apply", "", "enter", "", "enter", true},
		{"ui.scope.clear", "", "", "", "", true},
		{"ui.scope.chip", "", "altfoil", "", "altfoil", true},
		{"ui.scope.chip", "", "f:foil", "", "", false},
		{"ui.mfilter.open", "", "", "", "", true},
		{"ui.mfilter.apply", "", "none", "", "none", true},
		{"ui.chart.range", "", "1825", "", "1825", true},
		{"ui.chart.range", "", "all", "", "all", true},
		{"ui.chart.range", "", "45", "", "", false},
		{"ui.chart.gaps", "", "on", "", "on", true},
		{"ui.chart.gaps", "", "off", "", "off", true},
		{"ui.chart.download", "", "", "", "", true},
		{"ui.chart.checkpoint", "off", "ban", "off", "ban", true},
		{"ui.chart.checkpoint", "", "ban", "", "", false},
		{"ui.chart.reference", "", "TCG Low", "", "", false}, // a reference name is never stored
		{"ui.chart.reference", "", "", "", "", true},
		{"ui.chart.legend", "", "hide", "", "hide", true},
		{"ui.chart.legend", "", "TCGplayer Low", "", "", false},
		{"ui.chart.add_modal", "", "commit", "", "commit", true},
		{"ui.chart.roster", "modal", "add", "modal", "add", true},
		{"ui.chart.roster", "page", "remove", "page", "remove", true},
		{"ui.mchart.open", "", "", "", "", true},
		{"ui.mchart.reset_zoom", "", "", "", "", true},
		{"ui.mchart.gesture", "", "pan", "", "pan", true},
		{"ui.recents", "", "unpin", "", "unpin", true},
		{"ui.recents", "", "zzqueryzz", "", "", false}, // a stored query is never a value
		{"ui.fav", "", "shared_open", "", "", false},   // the shared page has its own name
		{"ui.fav.shared_open", "", "", "", "", true},
		{"ui.fav.sort", "", "sell", "", "", false},
		{"ui.fav", "", "manual", "", "", false},
		{"ui.fav.sort", "asc", "sell", "asc", "sell", true},
		{"ui.fav.sort", "desc", "manual", "", "", false},
		{"ui.fav.csv", "", "import", "", "import", true},
		{"ui.fav.chart", "", "", "", "", true},
		{"ui.fav.upload", "", "retail", "", "retail", true},
		{"ui.fav.share", "", "create", "", "create", true},
		{"ui.fav.merge", "", "", "", "", true},
		{"ui.sealed.toc", "", "", "", "", true},
		{"ui.sealed.edition", "", "", "", "", true},
		{"ui.sealed.edition", "", "MH3", "", "", false}, // a set code is never stored
		{"ui.sets", "", "rarity_tag", "", "rarity_tag", true},
		{"ui.sets", "", "MH3", "", "", false},
		{"ui.home", "", "popular_expand", "", "popular_expand", true},
		{"ui.home", "", "Newspaper", "", "", false},
		{"ui.home", "", "black lotus", "", "", false}, // a popular search's text is never stored
	} {
		n, found := Lookup(c.name)
		if !found {
			t.Errorf("%s is not registered", c.name)
			continue
		}
		if n.Family != FamilyUI || n.Area == "" {
			t.Errorf("%s: family and area must be set: %+v", c.name, n)
		}
		s, val, ok := n.Check(c.scope, c.value, v)
		if ok != c.ok || s != c.wantS || val != c.wantV {
			t.Errorf("%s (%q, %q): got (%q, %q, %v), want (%q, %q, %v)",
				c.name, c.scope, c.value, s, val, ok, c.wantS, c.wantV, c.ok)
		}
	}
}

// What each name's rate is measured against, by the labels pageLabel gives
// /search, /sealed, /search/shared, /sets and /.
func TestSearchUIPages(t *testing.T) {
	// Every name not listed is on the search template; the landing panes never render on /sealed.
	other := map[string]string{
		"ui.searchbar.submit": "*", "ui.autocomplete.pick": "*",
		"ui.scope.toggle": "*", "ui.scope.apply": "*", "ui.scope.clear": "*", "ui.scope.chip": "*",
		"ui.sealed.toc": "sealed", "ui.sealed.edition": "sealed",
		"ui.sets": "sets", "ui.home": "home",
		"ui.fav.merge": "search/shared", "ui.fav.shared_open": "search/shared",
		"ui.recents": "search", "ui.fav.sort": "search", "ui.fav.csv": "search",
		"ui.fav.chart": "search", "ui.fav.upload": "search", "ui.fav.share": "search",
	}
	denoms := map[string]string{
		"ui.mfilter.apply": "ui.mfilter.open", "ui.mchart.reset_zoom": "ui.mchart.open", "ui.mchart.gesture": "ui.mchart.open",
	}
	prefixes := []string{"ui.result.", "ui.search.", "ui.sidebar.", "ui.row.", "ui.searchbar.", "ui.autocomplete.",
		"ui.scope.", "ui.mfilter.", "ui.chart.", "ui.mchart.", "ui.recents", "ui.fav", "ui.sealed.", "ui.sets", "ui.home"}
	seen := 0
	for _, n := range All() {
		if !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(n.Name, p) }) {
			continue
		}
		seen++
		want, listed := other[n.Name]
		if !listed {
			want = "search,sealed"
		}
		if n.Page != want {
			t.Errorf("%s: page %q, want %q", n.Name, n.Page, want)
		}
		if n.Denom != denoms[n.Name] {
			t.Errorf("%s: denom %q, want %q", n.Name, n.Denom, denoms[n.Name])
		}
	}
	if seen != 56 {
		t.Errorf("%d names under this phase's prefixes, want 56", seen)
	}
}
