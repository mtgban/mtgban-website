package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// The index prices and the custom-buylist gate do not need a loaded store
// list, so they pin the parts of the Upload tab's data a fixture run can see.
func TestUploadSettingsKeysReadTheGrant(t *testing.T) {
	withSigMode(t, true, true)

	if got := uploadSettingsKeys("").AltKeys; !slices.Equal(got, UploadIndexComparePriceList) {
		t.Errorf("AltKeys = %v, want UploadIndexComparePriceList", got)
	}
	if uploadSettingsKeys(testSig(map[string]string{"Upload": "true"})).CanUploadCustom {
		t.Error("CanUploadCustom without the UploadCustom grant")
	}
	if !uploadSettingsKeys(testSig(map[string]string{"UploadCustom": "true"})).CanUploadCustom {
		t.Error("CanUploadCustom false with the UploadCustom grant")
	}
}

// keepScrapers empties the loaded stores for the test, so every list is
// empty, which is still the contract: the functions return, in display
// order, whatever is loaded.
func TestSettingsKeysWithNoScrapers(t *testing.T) {
	keepScrapers(t)
	if sellers, vendors := searchSettingsKeys(); len(sellers) != 0 || len(vendors) != 0 {
		t.Errorf("search keys = %v %v, want none", sellers, vendors)
	}
	if got := arbitVendorKeys(arbitBlockedVendors(""), false); len(got) != 0 {
		t.Errorf("arbit keys = %v, want none", got)
	}
	if got := globalVendorKeys(globalProbeBlocklist()); len(got) != 0 {
		t.Errorf("global keys = %v, want none", got)
	}
	r, b := sleepBlocklists("")
	if s, v := sleepModalKeys(r, b); len(s) != 0 || len(v) != 0 {
		t.Errorf("sleep keys = %v %v, want none", s, v)
	}
}

// The search grids and the upload store lists leave out the stores only
// the price API serves, sealed ones included.
func TestSettingsKeysLeaveOutAPIOnlyStores(t *testing.T) {
	store := func(shorthand string, sealed bool) mtgban.ScraperInfo {
		return mtgban.ScraperInfo{Name: shorthand, Shorthand: shorthand, SealedMode: sealed}
	}
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("SHOP", false)),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("APISHOP", false)),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("SHOPSEALED", true)),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("APISEALED", true)),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("BUY", false)),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("APIBUY", false)),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("BUYSEALED", true)),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("APIBUYSEALED", true)),
	})
	withConfigCopy(t)
	Config().Stores.APIOnlyStores = []string{"APISHOP", "APISEALED", "APIBUY", "APIBUYSEALED"}

	sellers, vendors := searchSettingsKeys()
	singlesSellers, sealedSellers, singlesVendors, sealedVendors := uploadStoreLists("")
	for name, c := range map[string]struct{ got, want []string }{
		"search sellers":         {sellers, []string{"SHOP", "SHOPSEALED"}},
		"search vendors":         {vendors, []string{"BUY", "BUYSEALED"}},
		"upload singles sellers": {singlesSellers, []string{"SHOP"}},
		"upload sealed sellers":  {sealedSellers, []string{"SHOPSEALED"}},
		"upload singles vendors": {singlesVendors, []string{"BUY"}},
		"upload sealed vendors":  {sealedVendors, []string{"BUYSEALED"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
}

// The Global grid lists the sellers the Global page compares against,
// since those are what its cookie hides, and only the probe list's.
func TestGlobalVendorKeysListTheProbeSellers(t *testing.T) {
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Probe", Shorthand: "PROBE"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Off Probe", Shorthand: "OFFPROBE"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "API Shop", Shorthand: "APISHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Index", Shorthand: "INDEX", SealedMode: true, MetadataOnly: true}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Buyer", Shorthand: "BUY"}),
	})
	withConfigCopy(t)
	Config().Stores.APIOnlyStores = []string{"APISHOP"}
	Config().Stores.GlobalProbeList = []string{"PROBE", "APISHOP", "INDEX", "BUY"}

	got := globalVendorKeys(globalProbeBlocklist())
	if !slices.Equal(got, []string{"PROBE"}) {
		t.Errorf("global grid = %v, want [PROBE]", got)
	}
}

// The grant replaces the config block list, NONE clears it, and with no
// grant the config list stands.
func TestArbitBlockedVendorsReadsTheGrant(t *testing.T) {
	prev := Config().Stores.ArbitBlockVendors
	t.Cleanup(func() { Config().Stores.ArbitBlockVendors = prev })
	Config().Stores.ArbitBlockVendors = []string{"CONFIG_VENDOR"}

	cases := []struct {
		name string
		sig  string
		want []string
	}{
		{"NONE clears the list", testSig(map[string]string{"ArbitDisabledVendors": "NONE"}), nil},
		{"the grant's vendors", testSig(map[string]string{"ArbitDisabledVendors": "ZZA,ZZB"}), []string{"ZZA", "ZZB"}},
		{"no sig reads the config", "", []string{"CONFIG_VENDOR"}},
	}
	for _, c := range cases {
		if got := arbitBlockedVendors(c.sig); !slices.Equal(got, c.want) {
			t.Errorf("%s: arbitBlockedVendors = %v, want %v", c.name, got, c.want)
		}
	}
}

// A tab exists only for a page in the reader's nav, in nav order, and the
// Offline tab only with the grant the Search section checked.
func TestSettingsTabsFollowTheNav(t *testing.T) {
	nav := func(names ...string) []NavElem {
		var out []NavElem
		for _, name := range names {
			out = append(out, NavElem{Name: name, SettingsTab: ExtraNavs[name].SettingsTab})
		}
		return out
	}
	cases := []struct {
		name    string
		nav     []NavElem
		offline bool
		want    []string
	}{
		{"nothing", nil, false, nil},
		{"offline alone", nil, true, []string{"offline"}},
		{"search only", nav("Search"), false, []string{"search"}},
		{"global only", nav("Global"), false, []string{"global"}},
		{"each arbitrage route its own tab", nav("Global", "Arbit", "Reverse"), false,
			[]string{"global", "arbit", "reverse"}},
		{"nav order, offline last", nav("Sleepers", "Newspaper", "Upload", "Search"), true,
			[]string{"sleep", "news", "upload", "search", "offline"}},
		{"pages without settings add nothing", nav("Screener", "Alerts", "Search"), false, []string{"search"}},
	}
	for _, c := range cases {
		if got := settingsTabs(c.nav, c.offline); !slices.Equal(got, c.want) {
			t.Errorf("%s: settingsTabs = %v, want %v", c.name, got, c.want)
		}
	}
}

// Sub-pages carry their section's tab: Sealed opens on Search's.
func TestSettingsTabOnSubPages(t *testing.T) {
	for _, sub := range ExtraNavs["Search"].SubPages {
		if sub.Name == "Sealed" && sub.SettingsTab != "search" {
			t.Errorf("Sealed.SettingsTab = %q, want search", sub.SettingsTab)
		}
	}
	for _, sub := range ExtraNavs["Newspaper"].SubPages {
		if sub.Name == "TCG Syp List" && sub.SettingsTab != "news" {
			t.Errorf("Syp.SettingsTab = %q, want news", sub.SettingsTab)
		}
	}
}

// Each tab's cookies belong to the page that opens it, whose path the pane
// carries for settings.js to write them at.
func TestSettingsTabPathsFollowTheNav(t *testing.T) {
	var nav []NavElem
	for _, name := range []string{"Search", "Newspaper", "Sleepers", "Upload", "Global", "Arbit", "Reverse", "Screener"} {
		nav = append(nav, *ExtraNavs[name])
	}
	want := map[string]string{
		"search":  "/search",
		"news":    "/newspaper",
		"sleep":   "/sleepers",
		"upload":  "/upload",
		"global":  "/global",
		"arbit":   "/arbit",
		"reverse": "/reverse",
	}
	if got := settingsTabPaths(nav); !maps.Equal(got, want) {
		t.Errorf("settingsTabPaths = %v, want %v", got, want)
	}
}

// A cookie kept at /arbit reaches only requests under /arbit, so the modal
// on /search asks /arbit/settings-values for it. Root cookies stay out.
func TestSettingsValuesAnswersThisPathsCookies(t *testing.T) {
	mux := http.NewServeMux()
	s := newSite()
	for _, nav := range ExtraNavs {
		s.mountNav(mux, nav)
	}
	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/screener/settings-values", nil)); pattern == "/screener/settings-values" {
		t.Error("a page without a settings tab serves settings values")
	}

	req := httptest.NewRequest(http.MethodGet,
		"/arbit/settings-values?name=ArbitVendorsList&name=GlobalVendorsList&name=MTGBAN&name=SearchSellersList", nil)
	req.AddCookie(&http.Cookie{Name: "ArbitVendorsList", Value: "CK,SCG,"})
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: "sig"})
	req.AddCookie(&http.Cookie{Name: "SearchSellersList", Value: "TCG,"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Errorf("Cache-Control = %q, want private, no-store", cc)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ArbitVendorsList": "CK,SCG,", "GlobalVendorsList": ""}
	if !maps.Equal(got, want) {
		t.Errorf("values = %v, want %v", got, want)
	}
}

// grantSig mints a valid signature carrying the named grants, for a reader
// with an email, so gates that check the HMAC (offline mode) see it.
func grantSig(t *testing.T, grants ...string) string {
	t.Helper()
	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
	for _, g := range grants {
		fields.Set(g, "true")
	}
	return signedAs(t, fields, time.Now().Add(time.Hour))
}

// paneTabs reads the rendered panes' tabs, in document order.
func paneTabs(body string) []string {
	re := regexp.MustCompile(`class="settings-pane" role="tabpanel" data-tab="([a-z]+)"`)
	var tabs []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		tabs = append(tabs, m[1])
	}
	return tabs
}

func fetchSettingsModal(t *testing.T, sig string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/settings/modal", nil)
	if sig != "" {
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	}
	rec := httptest.NewRecorder()
	testSite.SettingsModal(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Errorf("Cache-Control = %q, want private, no-store", cc)
	}
	return rec.Body.String()
}

// The panes follow the sig the way the navbar does: nothing without one
// when the ACL grants Any nothing, every page's tab with every grant, and
// Global's tab for a reader with Global alone. The stores are emptied,
// so the grids render no rows; the panes and gates are what is checked.
func TestSettingsModalPanesFollowTheSig(t *testing.T) {
	signingEnabled(t, true)
	keepScrapers(t)

	t.Run("unsigned", func(t *testing.T) {
		if len(ACL()["Any"]) > 0 {
			t.Skip("this ACL grants Any some pages; the empty case needs none")
		}
		body := fetchSettingsModal(t, "")
		if got := paneTabs(body); len(got) != 0 {
			t.Errorf("panes = %v, want none", got)
		}
		if !strings.Contains(body, "No settings are available") {
			t.Error("empty body has no message")
		}
	})

	t.Run("every grant", func(t *testing.T) {
		sig := grantSig(t, "Search", "Upload", "Arbit", "Global", "Reverse",
			"Newspaper", "Sleepers", "SearchOfflineMode", "UploadCustom")
		body := fetchSettingsModal(t, sig)
		want := []string{"search", "sleep", "upload", "global", "arbit", "reverse", "offline"}
		if len(GetNewspaperUUIDs()) > 0 {
			want = []string{"search", "news", "sleep", "upload", "global", "arbit", "reverse", "offline"}
		}
		if got := paneTabs(body); !slices.Equal(got, want) {
			t.Errorf("panes = %v, want %v", got, want)
		}
		for _, id := range []string{
			`data-tab="arbit" data-path="/arbit"`,
			`data-tab="upload" data-path="/upload"`,
			`data-tab="offline" data-path=""`,
			`id="settings-search-listing"`, // unlocked for a signed reader
			`id="opt-customseller"`,        // the custom rule's controls
			`id="offline-img-editions-picker"`,
			`id="sleep-editions-picker"`,
		} {
			if !strings.Contains(body, id) {
				t.Errorf("body lacks %s", id)
			}
		}
	})

	t.Run("global alone", func(t *testing.T) {
		body := fetchSettingsModal(t, grantSig(t, "Global"))
		if got := paneTabs(body); !slices.Equal(got, []string{"global"}) {
			t.Errorf("panes = %v, want [global]", got)
		}
	})

	t.Run("upload without the custom grant", func(t *testing.T) {
		body := fetchSettingsModal(t, grantSig(t, "Upload"))
		if !strings.Contains(body, "Increase your tier to define a custom buylist") {
			t.Error("body lacks the custom buylist upsell")
		}
		if strings.Contains(body, `id="opt-customseller"`) {
			t.Error("body has the custom buylist controls without the grant")
		}
		if strings.Contains(body, `data-tab="offline"`) {
			t.Error("body has the Offline tab without SearchOfflineMode")
		}
	})
}

// The endpoint sits behind noSigning, so a sig this host did not write,
// whatever grants it claims, earns what no sig at all does.
func TestSettingsModalIgnoresAForgedSig(t *testing.T) {
	signingEnabled(t, true)
	keepScrapers(t)
	if len(ACL()["Any"]) > 0 {
		t.Skip("this ACL grants Any some pages; the empty case needs none")
	}
	forged := testSig(map[string]string{
		"Search": "true", "Upload": "true", "UploadCustom": "true", "SearchOfflineMode": "true",
	})
	for name, sig := range map[string]string{"no sig": "", "forged": forged} {
		body := fetchSettingsModal(t, sig)
		if got := paneTabs(body); len(got) != 0 {
			t.Errorf("%s: panes = %v, want none", name, got)
		}
		if !strings.Contains(body, "No settings are available") {
			t.Errorf("%s: body has no empty message", name)
		}
	}
}

// Listing Priority is locked for a reader with no signature at all, which
// the navbar's ACL for Any lets in on production.
func TestSettingsModalDataLocksListingWhenUnsigned(t *testing.T) {
	signingEnabled(t, true)
	req := httptest.NewRequest(http.MethodGet, "/api/settings/modal", nil)
	if v := settingsModalData(testSite, req); !v.ListingLocked {
		t.Error("ListingLocked false for an unsigned request")
	}
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: grantSig(t, "Search")})
	if v := settingsModalData(testSite, req); v.ListingLocked {
		t.Error("ListingLocked true for a signed request")
	}
}

// The Listing Priority pills are drawn locked, with no id for settings.js
// to bind, when the reader has no signature, and bound when they have one.
func TestSettingsBodyDrawsListingLocked(t *testing.T) {
	baseName, files := settingsBodyFiles()
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	render := func(locked bool) string {
		var buf bytes.Buffer
		v := settingsModalVars{Tabs: []string{"search"}, TabNames: settingsTabNames, ListingLocked: locked}
		if err := tmpl.ExecuteTemplate(&buf, baseName, v); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	locked, open := render(true), render(false)
	if !strings.Contains(locked, "settings-pills-locked") || strings.Contains(locked, `id="settings-search-listing"`) {
		t.Error("an unsigned reader's pills are not drawn locked")
	}
	if strings.Contains(open, "settings-pills-locked") || !strings.Contains(open, `id="settings-search-listing"`) {
		t.Error("a signed reader's pills are not bound to the cookie")
	}
}

func TestSettingsBodyDrawsStoreFactors(t *testing.T) {
	baseName, files := settingsBodyFiles()
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	v := settingsModalVars{
		Tabs: []string{"search"}, TabNames: settingsTabNames,
		SellerKeys: []string{"CK", "TCG"}, VendorKeys: []string{"CK"},
	}
	if err := tmpl.ExecuteTemplate(&buf, baseName, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `id="settings-store-factors"`) {
		t.Fatal("no store adjustments container")
	}
	if !strings.Contains(out, `&#34;k&#34;:&#34;CK&#34;`) && !strings.Contains(out, `"k":"CK"`) && !strings.Contains(out, `&quot;k&quot;:&quot;CK&quot;`) {
		t.Errorf("data-stores does not carry CK:\n%s", out)
	}
}
