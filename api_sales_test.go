package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
	if !strings.Contains(panes["unsold"], "No sales on record") {
		t.Errorf("unsold pane = %q", panes["unsold"])
	}

	phone := get("/data/sales/sold", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148")
	if !strings.Contains(phone["sold"], "m-sales-group") || !strings.Contains(phone["sold"], "Nov 19") {
		t.Errorf("phone pane = %s", phone["sold"])
	}

	many := make([]string, salesPaneMaxIDs+5)
	for i := range many {
		many[i] = "card" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if got := len(get("/data/sales/"+strings.Join(many, ","), "")); got != salesPaneMaxIDs {
		t.Errorf("drew %d panes, want at most %d", got, salesPaneMaxIDs)
	}
}
