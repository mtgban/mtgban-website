package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestRandomRedirectIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	testSite.RandomSearch(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/random", nil))
	testSite.RandomSearch(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/random?chart=a,b&modal=1", nil))
	testSite.RandomSealedSearch(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/randomsealed", nil))
	got := rows.rows()
	wantRow(t, got, "", "redirect.random", "card", 1)
	wantRow(t, got, "", "redirect.random", "chart_modal", 1)
	wantRow(t, got, "", "redirect.random", "sealed", 1)
}

func TestViewToggleIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	desktop := httptest.NewRequest(http.MethodGet, "/toggle-mobile?redirect=/search", nil)
	desktop.AddCookie(&http.Cookie{Name: "MobileView", Value: "false"})
	toggleMobileView(httptest.NewRecorder(), desktop)
	mobile := httptest.NewRequest(http.MethodGet, "/toggle-mobile", nil)
	mobile.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	toggleMobileView(httptest.NewRecorder(), mobile)
	got := rows.rows()
	wantRow(t, got, "", "view.toggle", "to_mobile", 1)
	wantRow(t, got, "", "view.toggle", "to_desktop", 1)
}

// goClickSite has one store, TEST, selling and buying the fixture card.
func goClickSite(t *testing.T) *site {
	t.Helper()
	info := mtgban.ScraperInfo{Name: "Test Store", Shorthand: "TEST"}
	inv := mtgban.InventoryRecord{"FIXTUREA-1": {{Conditions: "NM", Price: 1, Quantity: 1, URL: "https://store.example/sell"}}}
	bl := mtgban.BuylistRecord{"FIXTUREA-1": {{Conditions: "NM", BuyPrice: 1, Quantity: 1, URL: "https://store.example/buy"}}}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(inv, info)}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(bl, info)}
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}})
	return fixtureSite(t, b, sellers, vendors)
}

func TestGoClickIsCounted(t *testing.T) {
	s := goClickSite(t)
	rows := withFeatureCounter(t)
	for _, c := range []struct{ path, location string }{
		{"/go/r/TEST/FIXTUREA-1", "https://store.example/sell"},
		{"/go/i/TEST/FIXTUREA-1", "https://store.example/sell"},
		{"/go/b/TEST/FIXTUREA-1", "https://store.example/buy"},
		{"/go/TEST/FIXTUREA-1", "https://store.example/sell"},
	} {
		rec := httptest.NewRecorder()
		s.Redirect(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != c.location {
			t.Errorf("%s = %d %q, want 302 %q", c.path, rec.Code, rec.Header().Get("Location"), c.location)
		}
	}
	rec := httptest.NewRecorder()
	s.Redirect(rec, httptest.NewRequest(http.MethodGet, "/go/r/NOPE/FIXTUREA-1", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown store = %d, want 404", rec.Code)
	}
	got := rows.rows()
	wantRow(t, got, "TEST", "go.click", "r", 2)
	wantRow(t, got, "TEST", "go.click", "i", 1)
	wantRow(t, got, "TEST", "go.click", "b", 1)
	if n := len(find(got, "go.click")); n != 3 {
		t.Errorf("go.click rows = %d, want 3", n)
	}
}

func TestDeepLinksAreCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	testSite.CardRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/card/uma/55", nil))
	testSite.SealedRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sealed/uma", nil))
	got := rows.rows()
	wantRow(t, got, "", "redirect.card", "", 1)
	wantRow(t, got, "", "redirect.sealed", "", 1)
}

func TestPartnerAndDiscordLinksAreCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	rec := httptest.NewRecorder()
	partnerRedirect(rec, httptest.NewRequest(http.MethodGet, "/monroecards", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/screener" {
		t.Errorf("partner = %d %q, want 302 /screener", rec.Code, rec.Header().Get("Location"))
	}
	discordRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/discord", nil))
	got := rows.rows()
	wantRow(t, got, "", "redirect.partner", "", 1)
	wantRow(t, got, "", "redirect.discord", "", 1)
}
