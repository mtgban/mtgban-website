package main

import (
	"go/ast"
	"go/token"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
)

func TestChartDataFacts(t *testing.T) {
	for _, c := range []struct {
		ids, days          int
		scope, value, size string
	}{
		{1, 0, "single", "all", "1"},
		{1, -5, "single", "all", "1"},
		{1, 30, "single", "30", "1"},
		{2, 3650, "multi", "3650", "2"},
		{4, 1825, "multi", "1825", "3-5"},
		{10, 1800, "multi", "other", "6+"},
	} {
		got := chartDataFacts(c.ids, c.days)
		want := []fact{newFact(c.scope, "data.chart", c.value), newFact("", "data.chart_ids", c.size)}
		if !slices.Equal(got, want) {
			t.Errorf("chartDataFacts(%d, %d) = %v, want %v", c.ids, c.days, got, want)
		}
	}

	// Every range bucket, both scopes and every size pass the registry.
	for _, days := range []int{30, 90, 180, 365, 730, 1825, 3650, 0, 1800} {
		for _, ids := range []int{1, 2, 4, 10} {
			for _, f := range chartDataFacts(ids, days) {
				n, ok := observability.Lookup(f.name)
				if !ok {
					t.Errorf("%s is not registered", f.name)
					continue
				}
				if _, _, ok := n.Check(f.scope, f.value, observability.Validators{}); !ok {
					t.Errorf("the registry refuses %s scope %q value %q", f.name, f.scope, f.value)
				}
			}
		}
	}
}

func TestPaletteWrappersCount(t *testing.T) {
	served := 0
	next := func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("body"))
	}
	rows := withFeatureCounter(t)
	rec := httptest.NewRecorder()
	paletteList("promos", next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/palette/promos.json", nil))
	paletteChip("sealed", next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/palette/sealed/x", nil))
	paletteList("<free text>", next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	got := rows.rows()
	if list := find(got, "palette.list"); len(list) != 1 || list[0].Value != "promos" {
		t.Errorf("palette.list rows = %+v, want one for promos", list)
	}
	if chip := find(got, "palette.chip_fetch"); len(chip) != 1 || chip[0].Value != "sealed" {
		t.Errorf("palette.chip_fetch rows = %+v, want one for sealed", chip)
	}
	if served != 3 {
		t.Errorf("served %d requests, want 3: counting never stands in the way", served)
	}
	if rec.Code != http.StatusTeapot || rec.Body.String() != "body" || rec.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("the wrapper changed the answer: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
}

// Every palette route is counted: the registrations are read off the source.
func TestEveryPaletteRouteIsCounted(t *testing.T) {
	fset := token.NewFileSet()
	var routes int
	for _, path := range rootGoFiles(t, ".") {
		ast.Inspect(parseGoFile(t, fset, path), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
				return true
			}
			pattern, _ := literalString(call.Args[0])
			if !strings.HasPrefix(pattern, "/api/palette/") {
				return true
			}
			routes++
			if wrapper := innerOfNoSigning(call.Args[1]); wrapper != "paletteList" && wrapper != "paletteChip" {
				t.Errorf("%s is served through %q, not a counting wrapper", pattern, wrapper)
			}
			return true
		})
	}
	if routes != 8 {
		t.Fatalf("found %d palette routes, want 8", routes)
	}
}

// innerOfNoSigning names the function noSigning's argument calls, or "".
func innerOfNoSigning(e ast.Expr) string {
	outer, ok := e.(*ast.CallExpr)
	if !ok || len(outer.Args) != 1 {
		return ""
	}
	if fn, ok := outer.Fun.(*ast.Ident); !ok || fn.Name != "noSigning" {
		return ""
	}
	inner, ok := outer.Args[0].(*ast.CallExpr)
	if !ok {
		return ""
	}
	fn, ok := inner.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	return fn.Name
}

func TestSuggestFetchIsCounted(t *testing.T) {
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	s := fixtureSite(t, b, nil, nil)
	for _, c := range []struct{ target, scope, value string }{
		{"/api/suggest?all=true", "cards", "all"},
		{"/api/suggest?all=true&sealed=true", "sealed", "all"},
		{"/api/suggest?q=fixture", "cards", "prefix"},
		{"/api/suggest?q=fixture&sealed=true", "sealed", "prefix"},
		{"/api/suggest?q=fi", "", ""},   // too short to match
		{"/api/suggest?q=----", "", ""}, // folds to nothing
	} {
		rows := withFeatureCounter(t)
		s.SuggestAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, c.target, nil))
		got := find(rows.rows(), "suggest.fetch")
		if c.value == "" {
			if len(got) != 0 {
				t.Errorf("%s counted %+v", c.target, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Scope != c.scope || got[0].Value != c.value {
			t.Errorf("%s: suggest.fetch rows = %+v, want %s under %s", c.target, got, c.value, c.scope)
		}
	}
}

func TestSettingsAndOpenSearchFetchesAreCounted(t *testing.T) {
	mux := http.NewServeMux()
	s := newSite()
	for _, nav := range ExtraNavs {
		s.mountNav(mux, nav)
	}
	rows := withFeatureCounter(t)
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/arbit/settings-values?name=ArbitVendorsList", nil))
	OpenSearchDesc(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/opensearch.xml", nil))
	got := rows.rows()
	if values := find(got, "settings.values_fetch"); len(values) != 1 || values[0].Scope != "arbit" {
		t.Errorf("settings.values_fetch rows = %+v, want one under arbit", values)
	}
	if len(find(got, "opensearch.fetch")) != 1 {
		t.Error("the descriptor fetch was not counted")
	}
}

func TestBatchPricesAreCounted(t *testing.T) {
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	uuid := "FIXTUREA-1"
	inventory := mtgban.InventoryRecord{}
	if err := inventory.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1, URL: "https://example.test"}); err != nil {
		t.Fatal(err)
	}
	buylist := mtgban.BuylistRecord{}
	if err := buylist.Add(uuid, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 5, Quantity: 1, URL: "https://example.test"}); err != nil {
		t.Fatal(err)
	}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Name: "Alpha Seller", Shorthand: "ZZA"})}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Name: "Alpha Vendor", Shorthand: "ZZB"})}

	for _, c := range []struct {
		name string
		s    *site
		want []string
	}{
		{"stores loaded", fixtureSite(t, b, sellers, vendors), []string{"1-9"}},
		{"no stores", fixtureSite(t, b, nil, nil), nil},
	} {
		rows := withFeatureCounter(t)
		rec := httptest.NewRecorder()
		c.s.BatchPricesAPI(rec, httptest.NewRequest(http.MethodGet, "/data/prices/FIXTUREA-1,FIXTUREA-2", nil))
		var got []string
		for _, row := range find(rows.rows(), "data.prices") {
			got = append(got, row.Value)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s (status %d): data.prices values = %v, want %v", c.name, rec.Code, got, c.want)
		}
	}
}
