package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apiproductlist"
)

func apiPlansPage(t *testing.T, sig string) string {
	t.Helper()
	return apiPlansPageAt(t, sig, "/api-plans")
}

// apiPlansPageAt renders the page for a request path of the caller's choosing.
func apiPlansPageAt(t *testing.T, sig, target string) string {
	t.Helper()
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config.APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config.APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic", "pokemon"}}

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if sig != "" {
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	}
	rec := httptest.NewRecorder()
	APIPlans(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

func TestAPIPlansRendersCatalog(t *testing.T) {
	body := apiPlansPage(t, "")
	for _, want := range []string{
		"À la carte", "$200", "Base Access", "$500", "All Access", "$800", "$150",
		"No Sealed or EV data", "Single region market overview", "Priority support", "Choose All Access",
		"one included, $150/month for each additional",
		"TCGplayer always included, your first store is on us, each additional is $150/month",
		`id="api-total-package">All Access</span> <strong id="api-total">$800</strong>`,
		`action="https://api.example/checkout"`,
		`name="package" id="api-package-all_data" value="all_data" checked`,
		`name="games" value="pokemon"`,
		`name="stores" value="CK" checked`,
		`name="return_to" value="https://mtgban.com/api-plans"`,
		`href="https://api.example/account"`,
		"/guide",
		`name="interval" value="monthly" checked`,
		`<fieldset class="api-fieldset" hidden>`,
		`<p class="api-note">Sign in with Patreon to request the trial key.</p>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, `href="/api-trial`) {
		t.Error("anonymous reader sees the trial button")
	}
	if strings.Contains(body, `value="quarterly"`) {
		t.Error("quarterly shown without an invite")
	}
	if strings.Contains(body, `name="stores" value="TCG"`) {
		t.Error("implied store offered as a checkbox")
	}
	if strings.Contains(body, "Patreon bundle") || strings.Contains(body, "Magic is included") {
		t.Error("page still mentions the Patreon bundle or an included game")
	}
	// Podium order: 500, 800, 200.
	base, all, carte := strings.Index(body, "Base Access"), strings.Index(body, "All Access"), strings.Index(body, "À la carte")
	if !(base < all && all < carte) {
		t.Errorf("cards out of podium order: base %d all %d carte %d", base, all, carte)
	}
	if strings.Contains(body, "on any package") || strings.Contains(body, "on the À la carte package") {
		t.Error("add-on note still shown under the cards")
	}
	if !strings.Contains(body, `class="card api-card api-card-top"`) || !strings.Contains(body, `id="api-package-all_data"`) {
		t.Error("the priciest package is not the podium card")
	}
}

func TestAPIPlansTrialButtonNeedsPledgeAndSecret(t *testing.T) {
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}

	setGatewaySecret(t, "")
	if strings.Contains(apiPlansPage(t, sign("Legacy", user, nil, DefaultSignatureDuration)), `href="/api-trial`) {
		t.Error("trial offered without a gateway secret")
	}

	setGatewaySecret(t, "s")
	noPledge := apiPlansPage(t, sign("", user, nil, DefaultSignatureDuration))
	if strings.Contains(noPledge, `href="/api-trial`) {
		t.Error("trial offered to a login with no pledge")
	}
	if !strings.Contains(noPledge, `<p class="api-note">The trial key is for supporters with an active <a href="https://www.patreon.com/mtgban" target="_blank" rel="noopener">MTGBAN Patreon</a> pledge.</p>`) {
		t.Error("no-pledge note missing for a signed-in reader")
	}
	// html/template percent-encodes the query value, including the scheme's slashes.
	page := apiPlansPage(t, sign("Legacy", user, nil, DefaultSignatureDuration))
	if !strings.Contains(page, `href="/api-trial?return_to=https%3a%2f%2fmtgban.com%2fapi-plans"`) {
		t.Error("trial missing for a pledged supporter")
	}
	if !strings.Contains(page, "Try the API before you commit") || !strings.Contains(page, "FULL ACCESS for 15 days") {
		t.Error("trial copy missing for a pledged supporter")
	}
}

func TestAPIPlansInviteRevealsQuarterly(t *testing.T) {
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = true, false
	rec := httptest.NewRecorder()
	APIPlans(rec, httptest.NewRequest(http.MethodGet, "/api-plans?invite=abc", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `value="quarterly"`) || !strings.Contains(body, `name="invite" value="abc"`) {
		t.Error("invite did not reveal quarterly or was dropped")
	}
	if !strings.Contains(body, "invite=abc") {
		t.Error("return_to dropped the invite")
	}
}

func TestAPIPlansJSONNil(t *testing.T) {
	if apiPlansJSON(nil) != "null" {
		t.Error("apiPlansJSON(nil) should be null")
	}
}

func TestFormatUSD(t *testing.T) {
	for cents, want := range map[int64]string{20000: "$200", 150000: "$1,500", 1250: "$12.50", 100000000: "$1,000,000"} {
		if got := formatUSD(cents); got != want {
			t.Errorf("%d: %s want %s", cents, got, want)
		}
	}
}

func TestPodiumOrder(t *testing.T) {
	three := []apiproductlist.Package{{Key: "a", Monthly: 200}, {Key: "b", Monthly: 500}, {Key: "c", Monthly: 800}}
	cards, top := podiumOrder(three)
	if top != "c" || cards[0].Key != "b" || cards[1].Key != "c" || cards[2].Key != "a" {
		t.Errorf("three packages: %+v top %q", cards, top)
	}
	two := []apiproductlist.Package{{Key: "x", Monthly: 900}, {Key: "y", Monthly: 100}}
	cards, top = podiumOrder(two)
	if top != "" || cards[0].Key != "y" || cards[1].Key != "x" {
		t.Errorf("two packages: %+v top %q", cards, top)
	}
	// The only input here not already in price order.
	if two[0].Key != "x" {
		t.Error("input was reordered in place")
	}
}

func TestAPIPlansManageLinkUsesTheHandoffWhenSignedIn(t *testing.T) {
	setGatewaySecret(t, "s")
	anon := apiPlansPage(t, "")
	if !strings.Contains(anon, `href="https://api.example/account"`) {
		t.Error("anonymous reader should be sent to the gateway login")
	}
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}
	signed := apiPlansPage(t, sign("", user, nil, DefaultSignatureDuration))
	if !strings.Contains(signed, `href="/api-login?return_to=https%3a%2f%2fmtgban.com%2fapi-plans"`) {
		t.Error("signed-in reader should be sent through the Patreon handoff")
	}
	if strings.Contains(signed, `href="https://api.example/account"`) {
		t.Error("signed-in reader still offered the magic-link route")
	}
}

// The gateway signs in whoever the email names, so Patreon must have confirmed it.
func TestAPIPlansUnverifiedEmailKeepsTheGatewayLink(t *testing.T) {
	setGatewaySecret(t, "s")
	unverified := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example"}
	body := apiPlansPage(t, sign("Legacy", unverified, nil, DefaultSignatureDuration))
	if !strings.Contains(body, `href="https://api.example/account"`) {
		t.Error("an unverified email should be sent to the gateway account page")
	}
	if strings.Contains(body, `href="/api-login`) {
		t.Error("an unverified email was offered a handoff the gateway refuses")
	}
	if strings.Contains(body, `href="/api-trial`) {
		t.Error("an unverified email was offered a trial the gateway refuses")
	}
}

// stubStores installs sellers with the given shorthands and restores the real ones after the test.
func stubStores(t *testing.T, shorthands ...string) {
	t.Helper()
	prev := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev); vendorsPtr.Store(prevVendors) })
	var sellers []mtgban.Seller
	for _, sh := range shorthands {
		sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: sh, Name: sh}))
	}
	sellersPtr.Store(&sellers)
	var vendors []mtgban.Vendor
	vendorsPtr.Store(&vendors)
}

// stubConfiguredStores names the scrapers this site boots with and restores the real config after the test.
func stubConfiguredStores(t *testing.T, shorthands ...string) {
	t.Helper()
	prev := Config.ScraperConfig.Config
	t.Cleanup(func() { Config.ScraperConfig.Config = prev })
	Config.ScraperConfig.Config = map[string]map[string][]string{"stub": {"retail": shorthands}}
}

func TestAPIPlansOffersOnlyTheStoresThisSiteCarries(t *testing.T) {
	stubConfiguredStores(t, "TCGLow", "CT0", "GN", "SZ")
	stubStores(t)
	body := apiPlansPage(t, "")
	for _, want := range []string{`name="stores" value="CT" checked`, `name="stores" value="GN"`, `name="stores" value="SZ"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, absent := range []string{`value="CK"`, `value="SCG"`, `value="HA"`} {
		if strings.Contains(body, `name="stores" `+absent) {
			t.Errorf("page offers a store this site does not carry: %s", absent)
		}
	}
}

func TestAPIPlansIgnoresASessionPublishedStore(t *testing.T) {
	stubConfiguredStores(t, "TCGLow", "CT0")
	// An upload session publishes into the served snapshot, which the price list must not read.
	stubStores(t, "TCGLow", "CT0", "GN")
	body := apiPlansPage(t, "")
	if !strings.Contains(body, `name="stores" value="CT" checked`) {
		t.Error("page lacks the configured store")
	}
	if strings.Contains(body, `name="stores" value="GN"`) {
		t.Error("a session-published store reached the price list")
	}
}

func TestAPIPlansFallsBackToTheLoadedScrapers(t *testing.T) {
	stubConfiguredStores(t)
	stubStores(t, "TCGLow", "SZ")
	body := apiPlansPage(t, "")
	if !strings.Contains(body, `name="stores" value="SZ" checked`) {
		t.Error("with nothing configured the page should offer what is loaded")
	}
	if strings.Contains(body, `name="stores" value="CK"`) {
		t.Error("page offers a store neither configured nor loaded")
	}
}

func TestAPIPlansOffersEveryStoreWhenNoneAreLoaded(t *testing.T) {
	stubConfiguredStores(t)
	stubStores(t)
	body := apiPlansPage(t, "")
	if !strings.Contains(body, `name="stores" value="CK" checked`) || !strings.Contains(body, `name="stores" value="AF"`) {
		t.Error("with no scrapers loaded the page should fall back to the whole list")
	}
}

func TestAPIPlansDisablesTheStoreBoxesItHides(t *testing.T) {
	stubStores(t)
	// The page opens on a preset package, so a no-JS submit must not send stores=.
	body := apiPlansPage(t, "")
	if !strings.Contains(body, `name="stores" value="CK" checked disabled`) {
		t.Error("the hidden store boxes are not disabled")
	}
	// A change link names an explicit package, and then the boxes are live again.
	explicit := apiPlansPageAt(t, "", "/api-plans?package=starter")
	if !strings.Contains(explicit, `name="stores" value="CK" checked>`) {
		t.Error("an explicit package should leave the store boxes enabled")
	}
	if strings.Contains(explicit, `<fieldset class="api-fieldset" id="api-stores" hidden>`) {
		t.Error("an explicit package should show the stores fieldset")
	}
}

func TestAPIPlansKeepsAStoreTheCustomerPaysFor(t *testing.T) {
	stubConfiguredStores(t, "TCGLow", "SZ", "MS")
	stubStores(t)
	body := apiPlansPageAt(t, "", "/api-plans?change=1&package=starter&stores=CK,SZ")
	for _, want := range []string{`name="stores" value="CK"`, `name="stores" value="SZ"`, `name="stores" value="MS"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, `name="stores" value="HA"`) {
		t.Error("page offers a store this site does not carry and the reader does not pay for")
	}
}

func TestEveryPackageIconIsDrawn(t *testing.T) {
	for _, p := range apiProducts.Packages {
		if _, ok := tierIcons[p.Icon]; !ok {
			t.Errorf("package %s: the page has no %q icon", p.Key, p.Icon)
		}
	}
}
