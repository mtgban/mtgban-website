package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

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
