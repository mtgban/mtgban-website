package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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
		{"Upload", true},
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
		trimmed := !slices.ContainsFunc(pageVars.Nav, func(n NavElem) bool { return n.Name == "Arbitrage" })
		if trimmed != c.mobile {
			t.Errorf("%q on a phone: navbar trimmed %v, want %v", c.page, trimmed, c.mobile)
		}

		desktop := genPageNav(testSite, httptest.NewRequest(http.MethodGet, "/", nil), c.page, "")
		if desktop.IsMobile {
			t.Errorf("%q on a desktop is marked mobile", c.page)
		}
	}

	// A reader without the grant has no Arbitrage entry in their navbar, and
	// its BANned notice still keeps the desktop layout.
	withSigMode(t, true, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	pageVars := genPageNav(testSite, req, "Arbitrage", "")
	if slices.ContainsFunc(pageVars.Nav, func(n NavElem) bool { return n.Name == "Arbitrage" }) {
		t.Fatal("a reader with no signature has Arbitrage in their navbar")
	}
	if pageVars.IsMobile {
		t.Error("Arbitrage's BANned notice on a phone is marked mobile")
	}
}

// A desktop-only page shows a phone the desktop menu, whose view switch
// names the view the toggle leads to from the reader's own view.
func TestDesktopOnlyMenuNamesTheViewTheToggleLeadsTo(t *testing.T) {
	withSigMode(t, true, false)
	const iPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"

	for _, c := range []struct {
		reader, cookie, agent, label, cookieAfter string
	}{
		{"mobile view", "true", "", "Switch to Desktop View", "false"},
		{"desktop view", "false", "", "Switch to Mobile View", "true"},
		{"a phone on auto-detect", "", iPhone, "Switch to Desktop View", "false"},
		{"a desktop on auto-detect", "", "", "Switch to Mobile View", "true"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/arbit", nil)
		toggle := httptest.NewRequest(http.MethodGet, "/toggle-mobile?redirect=%2Farbit", nil)
		for _, r := range []*http.Request{req, toggle} {
			if c.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "MobileView", Value: c.cookie})
			}
			if c.agent != "" {
				r.Header.Set("User-Agent", c.agent)
			}
		}

		pageVars := genPageNav(testSite, req, "Arbitrage", "")
		page := renderPage(t, "arbit.html", pageVars.IsMobile, pageVars)
		if !strings.Contains(page, c.label) {
			t.Errorf("%s: the menu does not say %q", c.reader, c.label)
		}

		w := httptest.NewRecorder()
		toggleMobileView(w, toggle)
		got := ""
		for _, ck := range w.Result().Cookies() {
			if ck.Name == "MobileView" {
				got = ck.Value
			}
		}
		if got != c.cookieAfter {
			t.Errorf("%s: %q sets MobileView=%q, want %q", c.reader, c.label, got, c.cookieAfter)
		}
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
	if readerAlertChannels(s, req) == "" {
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
	withPrices(t,
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
	withPrices(t,
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
		got := w.Body.String()
		if got != c.want {
			t.Errorf("%s: the page got %q store keys, want %q", c.reader, got, c.want)
		}
	}
}

// A phone's menu lists the Screener, the TCG Syp List and Upload: each
// renders in the mobile layout (the Syp list as phone cards), and none is
// desktop only.
func TestPhoneMenuListsTheResponsivePages(t *testing.T) {
	nav := filterNavForMobile([]NavElem{
		{Name: "Newspaper"}, {Name: "TCG Syp List"}, {Name: "Screener (Beta)"}, {Name: "Upload"}, {Name: "Arbitrage"},
	})
	var names []string
	for _, n := range nav {
		names = append(names, n.Name)
	}
	want := []string{"Newspaper", "TCG Syp List", "Screener (Beta)", "Upload"}
	if !slices.Equal(names, want) {
		t.Errorf("phone menu %v, want %v", names, want)
	}
	for _, name := range []string{"TCG Syp List", "Screener (Beta)", "Upload"} {
		if desktopOnly(name) {
			t.Errorf("%s is desktop only, so a phone menu link would leave the mobile view", name)
		}
	}
}

// A phone page that links to the settings opens them on its own tab, which
// takes the modal's shell, its scripts and the icons it draws.
func TestPhoneSettingsLinksOpenTheModal(t *testing.T) {
	for _, dir := range []string{"templates", "templates/mobile"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, "base") {
				continue
			}
			_, files := renderTemplateFiles(name, true)
			page := dir + "/" + name
			if !slices.Contains(files, page) {
				continue
			}
			body, err := os.ReadFile(page)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), `settings=1"`) && !slices.Contains(files, "templates/partials/settings-modal.html") {
				t.Errorf("%s links to the settings and carries no modal", page)
			}
		}
	}
	for _, name := range []string{"upload.html", "news.html", "sleep.html", "user.html"} {
		pv := PageVars{IsMobile: true, UserNav: &NavElem{}, User: &UserVars{}, SettingsTab: "the-tab"}
		page := renderPage(t, name, true, pv)
		for _, want := range []string{`id="settings-modal"`, `src="/js/settings-loader.js`, `src="/js/utils.js`, `src="/js/offline/offline-images-ui.js`, `src="/js/icons.js`, `BAN_SETTINGS = { tab: "the-tab" }`} {
			n := strings.Count(page, want)
			if n != 1 {
				t.Errorf("%s on a phone: %d of %s, want 1", name, n, want)
			}
		}
	}
}

// Upload has its settings on a phone and on a desktop, by a link of its own
// on the phone, where a desktop has the navbar's gear.
func TestUploadOnAPhoneKeepsItsSettings(t *testing.T) {
	results := PageVars{UploadVars: UploadVars{UploadEntries: []UploadEntry{{}}}}
	for _, c := range []struct {
		name   string
		mobile bool
		pv     PageVars
		links  int
	}{
		{"the form on a phone", true, PageVars{}, 1},
		{"the results on a phone", true, results, 1},
		{"the form on a desktop", false, PageVars{}, 0},
		{"the results on a desktop", false, results, 0},
	} {
		c.pv.IsMobile = c.mobile
		c.pv.UserNav = &NavElem{}
		page := renderPage(t, "upload.html", c.mobile, c.pv)
		for _, want := range []string{`id="settings-modal"`, `src="/js/settings-loader.js`, `src="/js/utils.js`} {
			n := strings.Count(page, want)
			if n != 1 {
				t.Errorf("%s: %d of %s, want 1", c.name, n, want)
			}
		}
		n := strings.Count(page, `class="upload-share-link upload-settings-link"`)
		if n != c.links {
			t.Errorf("%s: %d settings links, want %d", c.name, n, c.links)
		}
	}
}
