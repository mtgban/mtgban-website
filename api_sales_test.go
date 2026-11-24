package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

func TestBuyersMode(t *testing.T) {
	cases := []struct {
		chosen, gameDefault string
		canSales, sealed    bool
		want                string
	}{
		{"", "", true, false, "buylist"},
		{"", "sales", true, false, "sales"},
		// A logged-out reader would see only the prompt.
		{"", "sales", false, false, "buylist"},
		{"buylist", "sales", true, false, "buylist"},
		{"sales", "", true, false, "sales"},
		{"sales", "", false, false, "sales"},
		{"bogus", "", true, false, "buylist"},
		{"sales", "sales", true, true, "buylist"},
	}
	for _, c := range cases {
		got := buyersMode(c.chosen, c.gameDefault, c.canSales, c.sealed)
		if got != c.want {
			t.Errorf("buyersMode(%q, %q, %v, %v) = %q, want %q", c.chosen, c.gameDefault, c.canSales, c.sealed, got, c.want)
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
	fillRecentSales(&v, recentFixture(), httptest.NewRequest(http.MethodGet, "/search", nil), "a-signature", keys)
	if v.BuyersMode != "buylist" || !v.CanSales {
		t.Errorf("mode %q, can %v; want the buylist, logged in", v.BuyersMode, v.CanSales)
	}
	if !v.HasSales["sold"] || v.HasSales["unsold"] {
		t.Errorf("HasSales = %v, want only the card with orders", v.HasSales)
	}

	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	r.AddCookie(&http.Cookie{Name: "SearchBuyersMode", Value: "sales"})
	v = SearchVars{}
	fillRecentSales(&v, recentFixture(), r, "", keys)
	if v.BuyersMode != "sales" || v.CanSales {
		t.Errorf("logged out, chose Sales: mode %q, can %v", v.BuyersMode, v.CanSales)
	}
}

func TestSalesPaneAPI(t *testing.T) {
	signingEnabled(t, true)
	saved := recentSalesStore.Snapshot()
	recentSalesStore.Publish(recentFixture())
	t.Cleanup(func() { recentSalesStore.Publish(saved) })

	rec := httptest.NewRecorder()
	testSite.SalesPaneAPI(rec, httptest.NewRequest(http.MethodGet, "/data/sales/sold", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no signature: status %d, want 401", rec.Code)
	}

	sig := url.QueryEscape(signedAs(t, url.Values{"UserEmail": {"reader@example.com"}}, time.Now().Add(time.Hour)))
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
