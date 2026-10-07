package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/alerts"
)

// genPageNav marks the mobile view for every page a phone asks for, the
// error pages included, except the desktop-only ones. A request for no
// page, the settings modal reading the nav, keeps every entry.
func TestGenPageNavMarksTheMobileView(t *testing.T) {
	withSigMode(t, true, false)

	for _, c := range []struct {
		page   string
		mobile bool
	}{
		{"Search", true},
		{"Error", true},
		{"Upload", false},
		{"Arbitrage", false},
		{"Reverse", false},
		{"Global", false},
		{"", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		pageVars := genPageNav(testSite, req, c.page, "")
		if pageVars.IsMobile != c.mobile {
			t.Errorf("%q on a phone: IsMobile %v, want %v", c.page, pageVars.IsMobile, c.mobile)
		}
		trimmed := !slices.ContainsFunc(pageVars.Nav, func(n NavElem) bool { return n.Name == "Upload" })
		if trimmed != c.mobile {
			t.Errorf("%q on a phone: navbar trimmed %v, want %v", c.page, trimmed, c.mobile)
		}

		desktop := genPageNav(testSite, httptest.NewRequest(http.MethodGet, "/", nil), c.page, "")
		if desktop.IsMobile {
			t.Errorf("%q on a desktop is marked mobile", c.page)
		}
	}

	// A reader without the grant has no Upload entry in their navbar, and
	// its BANned notice still keeps the desktop layout.
	withSigMode(t, true, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	pageVars := genPageNav(testSite, req, "Upload", "")
	if slices.ContainsFunc(pageVars.Nav, func(n NavElem) bool { return n.Name == "Upload" }) {
		t.Fatal("a reader with no signature has Upload in their navbar")
	}
	if pageVars.IsMobile {
		t.Error("Upload's BANned notice on a phone is marked mobile")
	}
}

// The search page offers the alerts link on a phone as on a desktop: it
// asks whether the navbar offers Alerts, not whether the phone's trimmed
// navbar kept it.
func TestSearchOffersAlertsOnAPhone(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	s.alerts.SetStore(&alerts.Store{})

	saved := mobileEnabledPages
	t.Cleanup(func() { mobileEnabledPages = saved })
	mobileEnabledPages = slices.DeleteFunc(slices.Clone(saved), func(name string) bool { return name == "Alerts" })

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	pageVars := genPageNav(s, req, "Search", "")
	fillSearchReader(s, &pageVars.SearchVars, req)
	if !pageVars.CanAlerts {
		t.Error("a phone whose navbar leaves Alerts out gets no alerts link")
	}
}

// A phone's settings drawer lists the stores to sort by. The desktop page
// leaves them to its settings modal, which asks for its own.
func TestMobileSearchListsTheStores(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	publishStores(t,
		[]mtgban.Seller{mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market"})},
		[]mtgban.Vendor{mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"})})

	req := httptest.NewRequest(http.MethodGet, "/search?q=Counterspell", nil)
	req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	w := httptest.NewRecorder()
	testSite.Search(w, req)
	for _, store := range []string{"TCGMarket", "CK"} {
		if !strings.Contains(w.Body.String(), `<option value="`+store+`">`) {
			t.Errorf("the phone's settings drawer does not list %s", store)
		}
	}
}

// The desktop search page builds no store lists: its settings modal asks for
// its own. A stub stands in for the page's template to print what it was given.
func TestSearchListsTheStoresOnlyForAPhone(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, false, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	publishStores(t,
		[]mtgban.Seller{mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market"})},
		[]mtgban.Vendor{mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"})})
	prevCache := TemplateCache
	t.Cleanup(func() { TemplateCache = prevCache })
	stub := template.Must(template.New("search.html").Parse(`{{len .SellerKeys}} {{len .VendorKeys}}`))
	TemplateCache = map[string]*template.Template{"search.html": stub, "mobile/search.html": stub}

	for _, c := range []struct {
		reader string
		mobile bool
		want   string
	}{
		{"a desktop", false, "0 0"},
		{"a phone", true, "1 1"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/search?q=Counterspell", nil)
		if c.mobile {
			req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		}
		w := httptest.NewRecorder()
		testSite.Search(w, req)
		if got := w.Body.String(); got != c.want {
			t.Errorf("%s: the page got %q store keys, want %q", c.reader, got, c.want)
		}
	}
}
