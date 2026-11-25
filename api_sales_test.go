package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

func TestBuyersMode(t *testing.T) {
	cases := []struct {
		chosen, gameDefault, want string
	}{
		{"", "", "buylist"},
		{"", "sales", "sales"},
		{"buylist", "sales", "buylist"},
		{"sales", "", "sales"},
		{"bogus", "", "buylist"},
	}
	for _, c := range cases {
		got := buyersMode(c.chosen, c.gameDefault)
		if got != c.want {
			t.Errorf("buyersMode(%q, %q) = %q, want %q", c.chosen, c.gameDefault, got, c.want)
		}
	}
}

// recentFixture is one card with two NM orders and one card with none.
func recentFixture() *salesvelocity.RecentSnapshot {
	at := uint32(time.Date(2026, 11, 19, 14, 32, 0, 0, time.UTC).Unix())
	r := &salesvelocity.Recent{}
	r.Grades[0] = []salesvelocity.Order{{At: at, Cents: 14759, Qty: 4}, {At: at - 86400, Cents: 13606, Qty: 1}}
	return &salesvelocity.RecentSnapshot{Cards: map[string]*salesvelocity.Recent{"sold": r}}
}

func TestFillRecentSales(t *testing.T) {
	withSigMode(t, false, true)
	keys := []string{"sold", "unsold"}

	var v SearchVars
	granted := testSig(map[string]string{"SearchSales": "true"})
	fillRecentSales(&v, recentFixture(), httptest.NewRequest(http.MethodGet, "/search", nil), granted, keys)
	if v.BuyersMode != "buylist" || !v.CanSales {
		t.Errorf("mode %q, can %v; want the buylist, granted", v.BuyersMode, v.CanSales)
	}
	if !v.HasSales["sold"] || v.HasSales["unsold"] {
		t.Errorf("HasSales = %v, want only the card with orders", v.HasSales)
	}

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	r.AddCookie(&http.Cookie{Name: "SearchBuyersMode", Value: "sales"})
	v = SearchVars{}
	fillRecentSales(&v, recentFixture(), r, granted, keys)
	if v.BuyersMode != "sales" {
		t.Errorf("chose Sales: mode %q", v.BuyersMode)
	}
	for name, sig := range map[string]string{
		"logged out":       "",
		"without the flag": testSig(map[string]string{"UserTier": "Vintage"}),
		"flag off":         testSig(map[string]string{"SearchSales": "false"}),
	} {
		v = SearchVars{}
		fillRecentSales(&v, recentFixture(), r, sig, keys)
		if v.BuyersMode != "buylist" || v.CanSales || len(v.HasSales) != 0 {
			t.Errorf("%s, chose Sales: mode %q, can %v, has %v", name, v.BuyersMode, v.CanSales, v.HasSales)
		}
	}
}

// SearchSales must be signed, and the Search entry must carry it to
// the values.
func TestSearchSalesIsAnACLProperty(t *testing.T) {
	if !slices.Contains(OptionalFields, "SearchSales") {
		t.Fatal("OptionalFields lacks SearchSales")
	}
	table := access.Table{"Admin": {"Search": {"SearchSales": "true"}}, "Legacy": {"Search": {}}}
	for tier, want := range map[string]string{"Admin": "true", "Legacy": ""} {
		if got := aclValuesIn(table, tier, nil).Get("SearchSales"); got != want {
			t.Errorf("%s: SearchSales %q, want %q", tier, got, want)
		}
	}
}

// A page shows no trace of the sales to a reader without SearchSales, whatever
// the mode cookie says, on desktop or phone, nor where no card has any.
func TestSearchHidesSales(t *testing.T) {
	skipWithoutDatastore(t)
	readyToRender(t)
	signingEnabled(t, true)
	const bolt = "78380203-7623-50bc-ab48-577cd655ee9a"
	saved := recentSalesStore.Snapshot()
	recentSalesStore.Publish(&salesvelocity.RecentSnapshot{Cards: map[string]*salesvelocity.Recent{bolt: {}}})
	t.Cleanup(func() { recentSalesStore.Publish(saved) })

	for _, agent := range []string{"", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148"} {
		for _, granted := range []bool{false, true} {
			fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
			if granted {
				fields.Set("SearchSales", "true")
			}
			r := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape("id:"+bolt), nil)
			r.AddCookie(&http.Cookie{Name: "SearchBuyersMode", Value: "sales"})
			r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
			if agent != "" {
				r.Header.Set("User-Agent", agent)
			}
			rec := httptest.NewRecorder()
			testSite.Search(rec, r)
			body := rec.Body.String()
			if !strings.Contains(body, bolt) {
				t.Fatal("the page does not list the card")
			}
			for _, mark := range []string{"sales-pane", "search-buyers.js"} {
				if strings.Contains(body, mark) != granted {
					t.Errorf("agent %q, granted %v: page has %q: %v", agent, granted, mark, !granted)
				}
			}
			if !granted && strings.Contains(body, "data-buyers-") {
				t.Errorf("agent %q: the switch shows without the flag", agent)
			}
		}
	}

	// No card on the page has an order: no column and no switch.
	recentSalesStore.Publish(&salesvelocity.RecentSnapshot{})
	r := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape("id:"+bolt), nil)
	fields := url.Values{"UserEmail": {"reader@example.com"}, "SearchSales": {"true"}}
	r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
	rec := httptest.NewRecorder()
	testSite.Search(rec, r)
	for _, mark := range []string{"with-sales", "sales-pane", "data-buyers-", "search-buyers.js"} {
		if strings.Contains(rec.Body.String(), mark) {
			t.Errorf("a page with no sales has %q", mark)
		}
	}
}

func TestSalesPaneAPI(t *testing.T) {
	signingEnabled(t, true)
	saved := recentSalesStore.Snapshot()
	recentSalesStore.Publish(recentFixture())
	t.Cleanup(func() { recentSalesStore.Publish(saved) })

	rec := httptest.NewRecorder()
	testSite.SalesPaneAPI(rec, httptest.NewRequest(http.MethodGet, "/data/sales/sold", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("no signature: status %d, want 403", rec.Code)
	}
	plain := url.QueryEscape(signedAs(t, url.Values{"UserEmail": {"reader@example.com"}}, time.Now().Add(time.Hour)))
	rec = httptest.NewRecorder()
	testSite.SalesPaneAPI(rec, httptest.NewRequest(http.MethodGet, "/data/sales/sold?sig="+plain, nil))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "147.59") {
		t.Errorf("without SearchSales: status %d, want 403: %s", rec.Code, rec.Body.String())
	}

	sig := url.QueryEscape(signedAs(t, url.Values{"UserEmail": {"reader@example.com"}, "SearchSales": {"true"}}, time.Now().Add(time.Hour)))
	get := func(path, agent string) map[string]string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path+"?sig="+sig, nil)
		if agent != "" {
			r.Header.Set("User-Agent", agent)
		}
		rec := httptest.NewRecorder()
		testSite.SalesPaneAPI(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body.String())
		}
		var panes map[string]string
		err := json.Unmarshal(rec.Body.Bytes(), &panes)
		if err != nil {
			t.Fatal(err)
		}
		return panes
	}

	panes := get("/data/sales/sold,unsold,sold", "")
	if len(panes) != 2 {
		t.Fatalf("panes for %v, want sold and unsold once each", panes)
	}
	for _, want := range []string{"Condition: NM", "avg <b>$ 145.28</b>", "2026-11-19", `title="2026-11-19 14:32 UTC"`, "147.59", "×4", "/img/logo/tcgplayer.png"} {
		if !strings.Contains(panes["sold"], want) {
			t.Errorf("sold pane lacks %q:\n%s", want, panes["sold"])
		}
	}
	// The fixture's card is in no datastore, so its name links nowhere.
	if strings.Contains(panes["sold"], "href") {
		t.Errorf("a card with no product has a link:\n%s", panes["sold"])
	}
	if !strings.Contains(panes["unsold"], "No sales on record") {
		t.Errorf("unsold pane = %q", panes["unsold"])
	}

	phone := get("/data/sales/sold", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148")
	if phone["sold"] != panes["sold"] {
		t.Errorf("phone pane differs from the desktop's:\n%s", phone["sold"])
	}

	many := make([]string, salesPaneMaxIDs+5)
	for i := range many {
		many[i] = "card" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if got := len(get("/data/sales/"+strings.Join(many, ","), "")); got != salesPaneMaxIDs {
		t.Errorf("drew %d panes, want at most %d", got, salesPaneMaxIDs)
	}
}

// TestSalesPaneLinks checks a group's link reaches each of its rows, the
// folded ones included.
func TestSalesPaneLinks(t *testing.T) {
	tmpl, err := salesPaneTemplate()
	if err != nil {
		t.Fatal(err)
	}
	line := salesvelocity.Line{Date: "2026-11-19", Source: "TCGplayer", Price: "1.00"}
	groups := []salesvelocity.Group{{
		Grade: "SP", Link: "https://example.com/p?a=1&b=2",
		Shown: []salesvelocity.Line{line, line}, More: []salesvelocity.Line{line},
	}}
	var buf strings.Builder
	err = tmpl.ExecuteTemplate(&buf, "sales-pane", groups)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`<a class="sales-src" href="https://example.com/p?a=1&amp;b=2"`,
		`data-track="ui.row.store" data-track-value="TCGPlayer" data-track-scope="sales"`,
	} {
		if got := strings.Count(out, want); got != 3 {
			t.Errorf("%d rows have %q, want all 3:\n%s", got, want, out)
		}
	}
	if got := strings.Count(out, "sales-row-more"); got != 1 {
		t.Errorf("%d rows are folded, want 1:\n%s", got, out)
	}
	// The folded rows follow the fold, and a phone hides the source's name
	// only beside its icon.
	for _, want := range []string{
		"1 more (show)</span><span class=\"sales-more-close\">Hide</span></summary></details>\n<div class=\"price-row sales-row sales-row-more\">",
		`height="14"><span class="sales-src-name">TCGplayer</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pane lacks %q:\n%s", want, out)
		}
	}
}

// A sealed product's header is its average alone: it only sells unopened.
func TestSalesPaneSealed(t *testing.T) {
	tmpl, err := salesPaneTemplate()
	if err != nil {
		t.Fatal(err)
	}
	groups := []salesvelocity.Group{{
		Grade: "Unopened", Avg: "120.00",
		Shown: []salesvelocity.Line{{Date: "2026-11-19", Source: "TCGplayer", Price: "120.00"}},
	}}
	var buf strings.Builder
	err = tmpl.ExecuteTemplate(&buf, "sales-pane", groups)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "Unopened") || strings.Contains(out, "Condition") {
		t.Errorf("a sealed pane names its condition:\n%s", out)
	}
	if !strings.Contains(out, "avg <b>$ 120.00</b>") {
		t.Errorf("a sealed pane lacks its average:\n%s", out)
	}
}

// TestSalesLink covers the printing, condition and language a sales row's
// link asks TCGplayer for.
func TestSalesLink(t *testing.T) {
	skipWithoutDatastore(t)
	b := testSite.backend()
	// Lightning Bolt (M10), whose two finishes share one product.
	const bolt = "78380203-7623-50bc-ab48-577cd655ee9a"
	for id, want := range map[string]url.Values{
		bolt:        {"Printing": {"Normal"}, "Condition": {"Lightly Played"}, "Language": {"English"}, "direct": {"false"}},
		bolt + "_f": {"Printing": {"Foil"}, "Condition": {"Lightly Played"}, "Language": {"English"}, "direct": {"false"}},
	} {
		link := salesLink(b, testSite.prices(), id, mtgban.SP)
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if inner := u.Query().Get("u"); inner != "" {
			u, err = url.Parse(inner)
			if err != nil {
				t.Fatal(err)
			}
		}
		if u.Path != "/product/32656" {
			t.Errorf("%s: path %q, want the product's page", id, u.Path)
		}
		if got := u.Query().Encode(); got != want.Encode() {
			t.Errorf("%s: asks for %q, want %q", id, got, want.Encode())
		}
	}
	if link := salesLink(b, testSite.prices(), "unknown", mtgban.NM); link != "" {
		t.Errorf("an unknown card links to %q", link)
	}
}

func TestSalesPrinting(t *testing.T) {
	cases := []struct {
		finish               string
		foil, etched, sealed bool
		want                 string
	}{
		{"nonfoil", false, false, false, "Normal"},
		{"reverseholofoil", true, false, false, "Reverse Holofoil"},
		{"etched", false, true, false, "Foil"},
		{"nonfoil", false, false, true, ""},
	}
	for _, c := range cases {
		co := &matcher.CardObject{}
		co.Finish, co.Foil, co.Etched, co.Sealed = c.finish, c.foil, c.etched, c.sealed
		if got := salesPrinting(co); got != c.want {
			t.Errorf("salesPrinting(%q, sealed %v) = %q, want %q", c.finish, c.sealed, got, c.want)
		}
	}
}

// A sealed page shows its sales as a card's does: in the Buyers column on
// desktop, in a list of their own on a phone.
func TestSealedSearchShowsSales(t *testing.T) {
	skipWithoutDatastore(t)
	readyToRender(t)
	signingEnabled(t, true)
	granted := signedAs(t, url.Values{"UserEmail": {"reader@example.com"}, "SearchSales": {"true"}}, time.Now().Add(time.Hour))
	uuids := backend().GetSealedUUIDsInSet("MH2")
	if len(uuids) == 0 {
		t.Skip("no MH2 sealed products")
	}
	box := uuids[0]
	saved := recentSalesStore.Snapshot()
	recentSalesStore.Publish(&salesvelocity.RecentSnapshot{Cards: map[string]*salesvelocity.Recent{box: {}}})
	t.Cleanup(func() { recentSalesStore.Publish(saved) })

	for agent, want := range map[string][]string{
		"": {`class="result-body with-sales`, `class="result-col buyers-col" data-buyers-mode="sales"`, `class="result-col sales-col" data-buyers-mode="sales"`, `class="sales-pane" data-card="` + box + `" data-pending`},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148": {`class="m-edge m-edge-buy" data-pane="sales"`, `id="sales-` + box + `" role="region"`, `class="sales-pane" data-card="` + box + `" data-pending`},
	} {
		r := httptest.NewRequest(http.MethodGet, "/sealed?q="+url.QueryEscape("id:"+box), nil)
		r.AddCookie(&http.Cookie{Name: "SearchBuyersMode", Value: "sales"})
		r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: granted})
		if agent != "" {
			r.Header.Set("User-Agent", agent)
		}
		rec := httptest.NewRecorder()
		testSite.Search(rec, r)
		for _, w := range want {
			if !strings.Contains(rec.Body.String(), w) {
				t.Errorf("agent %q: the page lacks %q", agent, w)
			}
		}
	}
}
