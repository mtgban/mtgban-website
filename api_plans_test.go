package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
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
		`id="api-total-package">All Access</span> <strong id="api-total">$800</strong>`,
		`action="https://api.example/checkout"`,
		`name="package" id="api-package-all_data" value="all_data" checked`,
		`name="games" value="pokemon"`,
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

// scraperStub names the served scrapers, the scraper config, and the search blocklists of a test site.
type scraperStub struct {
	config       map[string]map[string][]string
	sellers      []string
	vendors      []string
	sealed       []string
	names        map[string]string
	overrides    map[string]string
	retailBlock  []string
	buylistBlock []string
}

// stubScrapers installs the stub and restores the real scrapers and config after the test.
func stubScrapers(t *testing.T, s scraperStub) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevCfg, prevRetail, prevBuylist := Config.ScraperConfig, Config.SearchRetailBlockList, Config.SearchBuylistBlockList
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		Config.ScraperConfig, Config.SearchRetailBlockList, Config.SearchBuylistBlockList = prevCfg, prevRetail, prevBuylist
	})
	info := func(sh string) mtgban.ScraperInfo {
		name, ok := s.names[sh]
		if !ok {
			name = sh
		}
		return mtgban.ScraperInfo{Shorthand: sh, Name: name, SealedMode: slices.Contains(s.sealed, sh)}
	}
	sellers := []mtgban.Seller{}
	for _, sh := range s.sellers {
		sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, info(sh)))
	}
	vendors := []mtgban.Vendor{}
	for _, sh := range s.vendors {
		vendors = append(vendors, mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, info(sh)))
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	Config.ScraperConfig = ScraperConfig{Config: s.config, NameOverride: s.overrides}
	Config.SearchRetailBlockList, Config.SearchBuylistBlockList = s.retailBlock, s.buylistBlock
}

// magicStub mirrors the live magic config: split tcg_* and cardkingdom_* keys, blocklists, sealed scrapers, a session store.
var magicStub = scraperStub{
	config: map[string]map[string][]string{
		"tcg_index":          {"retail": {"TCGLow", "TCGDirectLow"}},
		"tcg_market":         {"retail": {"TCGMarket"}},
		"tcg_syplist":        {"buylist": {"SYP"}},
		"cardkingdom":        {"retail": {"CK"}, "buylist": {"CKBLLast"}},
		"cardkingdom_graded": {"retail": {"CKGraded"}},
		"cardkingdom_sealed": {"retail": {"CKSealed"}},
		"abugames":           {"retail": {"ABU"}, "buylist": {"ABUCredit"}},
		"starcitygames":      {"retail": {"SCG"}, "buylist": {"SCGBL"}},
		"strikezone":         {"retail": {"SZ"}},
		"manapool":           {"retail": {"MP"}},
		"magiccorner":        {"retail": {"MC"}},
		"sealed_ev":          {"retail": {"CKEV"}},
		"coolstuffinc":       {"retail": {"CSI"}},
	},
	sellers: []string{"TCGLow", "TCGDirectLow", "TCGMarket", "CK", "CKGraded", "ABU", "SCG", "SZ", "MP", "MC", "CKSealed", "CKEV", "GN"},
	vendors: []string{"SYP", "CKBLLast", "ABUCredit", "SCGBL"},
	sealed:  []string{"CKEV"},
	names: map[string]string{
		"TCGLow": "TCG Low", "TCGDirectLow": "TCG Direct Low", "TCGMarket": "TCG Market", "SYP": "TCG SYP List",
		"CK": "Card Kingdom", "CKBLLast": "Card Kingdom", "CKGraded": "card kingdom Graded",
		"CKSealed": "Card Kingdom Sealed", "CKEV": "Card Kingdom EV",
		"ABU": "ABU Games", "ABUCredit": "ABU Credit",
		"SCG": "StarCityGames", "SCGBL": "StarCityGames",
		"SZ": "Strike Zone", "MP": "mana pool",
		"MC": "Magic Corner", "GN": "Game Nerdz",
	},
	// The second entry renames a family, not a scraper.
	overrides:    map[string]string{"StarCityGames": "Star City Games", "ABU": "ABU Games"},
	retailBlock:  []string{"TCGDirectLow", "MC"},
	buylistBlock: []string{"SCGBL"},
}

func TestStoreFamiliesFromTheServedScrapers(t *testing.T) {
	stubScrapers(t, magicStub)
	implied, selectable := storeFamilies()
	// The tcg_* keys merge into one family, named by the price list.
	if len(implied) != 1 || implied[0].Key != "tcg" || implied[0].Name != "TCGplayer" || !slices.Equal(implied[0].Shorthands, []string{"SYP", "TCGLow", "TCGMarket"}) {
		t.Errorf("implied %+v", implied)
	}
	want := []StoreFamily{
		{Key: "abugames", Name: "ABU Games", Shorthands: []string{"ABU", "ABUCredit"}},
		{Key: "cardkingdom", Name: "Card Kingdom", Shorthands: []string{"CK", "CKBLLast", "CKGraded"}},
		{Key: "manapool", Name: "mana pool", Shorthands: []string{"MP"}},
		{Key: "starcitygames", Name: "Star City Games", Shorthands: []string{"SCG"}},
		{Key: "strikezone", Name: "Strike Zone", Shorthands: []string{"SZ"}},
	}
	if !slices.EqualFunc(selectable, want, func(a, b StoreFamily) bool {
		return a.Key == b.Key && a.Name == b.Name && slices.Equal(a.Shorthands, b.Shorthands)
	}) {
		t.Errorf("selectable %+v, want %+v", selectable, want)
	}
}

func TestFamilyName(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"MKM Low", "MKM Trend"}, "MKM"},
		{[]string{"Card Kingdom Graded", "Card Kingdom"}, "Card Kingdom"},
		{[]string{"card kingdom graded", "Card Kingdom", "Card Kingdom"}, "Card Kingdom"},
		{[]string{"TCG Market", "TCG Low", "TCG Direct Low"}, "TCG"},
		{[]string{"Card Kingdom", "Cardmarket"}, "Cardmarket"},
		{[]string{"Solo"}, "Solo"},
		{[]string{"Foo Bar", "Baz Qux Long"}, "Foo Bar"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := familyName(c.names); got != c.want {
			t.Errorf("%q: got %q want %q", c.names, got, c.want)
		}
	}
}

func TestStoreFamiliesEmptyWithNothingServed(t *testing.T) {
	stubScrapers(t, scraperStub{config: magicStub.config})
	implied, selectable := storeFamilies()
	if len(implied) != 0 || len(selectable) != 0 {
		t.Errorf("implied %+v selectable %+v", implied, selectable)
	}
}

func TestAPIPlansStoreRowComesFromTheServedScrapers(t *testing.T) {
	stubScrapers(t, magicStub)
	body := apiPlansPage(t, "")
	if !strings.Contains(body, "TCGplayer always included, your first store is on us, each additional is $150/month") {
		t.Error("legend lacks the implied family")
	}
	for _, want := range []string{`name="stores" value="abugames" checked disabled> ABU Games`, `name="stores" value="cardkingdom" disabled> Card Kingdom`, `name="stores" value="starcitygames" disabled> Star City Games`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, absent := range []string{"tcg", "tcg_index", "magiccorner", "cardkingdom_graded", "cardkingdom_sealed", "sealed", "sealed_ev", "coolstuffinc", "GN", "CK"} {
		if strings.Contains(body, `name="stores" value="`+absent+`"`) {
			t.Errorf("page offers %s", absent)
		}
	}
	if strings.Contains(body, "No stores are loaded") {
		t.Error("empty-row sentence shown with stores loaded")
	}
	// An explicit package leaves the boxes live and the fieldset shown.
	explicit := apiPlansPageAt(t, "", "/api-plans?package=starter")
	if !strings.Contains(explicit, `name="stores" value="abugames" checked>`) {
		t.Error("an explicit package should leave the store boxes enabled")
	}
	if strings.Contains(explicit, `<fieldset class="api-fieldset" id="api-stores" hidden>`) {
		t.Error("an explicit package should show the stores fieldset")
	}
}

func TestAPIPlansSaysWhenNoStoresAreLoaded(t *testing.T) {
	stubScrapers(t, scraperStub{config: magicStub.config})
	body := apiPlansPageAt(t, "", "/api-plans?package=starter")
	if !strings.Contains(body, `<p class="api-note">No stores are loaded on this site right now.</p>`) {
		t.Error("empty row does not say so")
	}
	if strings.Contains(body, `name="stores"`) {
		t.Error("empty row renders a store box")
	}
}

func TestAPIPlansKeepsAStoreTheCustomerPaysFor(t *testing.T) {
	stubScrapers(t, magicStub)
	body := apiPlansPageAt(t, "", "/api-plans?change=1&package=starter&stores=cardkingdom,Retired&stores=tcg")
	for _, want := range []string{`name="stores" value="abugames">`, `name="stores" value="cardkingdom" checked>`, `name="stores" value="starcitygames">`, `name="stores" value="retired" checked> retired`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(body, `value="cardkingdom"`) != 1 {
		t.Error("an offered family was rendered twice")
	}
	if strings.Contains(body, `name="stores" value="tcg"`) {
		t.Error("the implied family became a checkbox")
	}
	// A legacy change link names shorthands; each maps to its family.
	legacy := apiPlansPageAt(t, "", "/api-plans?change=1&package=starter&stores=CK,sz")
	for _, want := range []string{`name="stores" value="abugames">`, `name="stores" value="cardkingdom" checked>`, `name="stores" value="strikezone" checked>`} {
		if !strings.Contains(legacy, want) {
			t.Errorf("legacy link: page lacks %q", want)
		}
	}
	if strings.Contains(legacy, `value="ck"`) || strings.Contains(legacy, `value="sz"`) {
		t.Error("a legacy shorthand became its own box")
	}
	if !strings.Contains(legacy, `"storeKeys":["cardkingdom","strikezone"]`) {
		t.Error("the configurator data lacks the resolved store keys")
	}
	// Outside a change request the query names nothing to keep.
	plain := apiPlansPageAt(t, "", "/api-plans?package=starter&stores=retired")
	if strings.Contains(plain, `value="retired"`) {
		t.Error("a stores query outside a change request added a box")
	}
}

func TestAPIStoresServesTheFamilies(t *testing.T) {
	stubScrapers(t, magicStub)
	savedGame := Config.Game
	t.Cleanup(func() { Config.Game = savedGame })
	Config.Game = "magic"
	rec := httptest.NewRecorder()
	APIPlans(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q", got)
	}
	var doc struct {
		Game    string        `json:"game"`
		Implied []StoreFamily `json:"implied"`
		Stores  []StoreFamily `json:"stores"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Game != "magic" {
		t.Errorf("game %q", doc.Game)
	}
	if len(doc.Implied) != 1 || doc.Implied[0].Key != "tcg" || doc.Implied[0].Name != "TCGplayer" || !slices.Equal(doc.Implied[0].Shorthands, []string{"SYP", "TCGLow", "TCGMarket"}) {
		t.Errorf("implied %+v", doc.Implied)
	}
	if len(doc.Stores) != 5 || doc.Stores[0].Name != "ABU Games" || doc.Stores[1].Name != "Card Kingdom" || doc.Stores[2].Name != "mana pool" || doc.Stores[3].Name != "Star City Games" {
		t.Errorf("stores %+v", doc.Stores)
	}
	for _, f := range append(doc.Implied, doc.Stores...) {
		if f.Key != strings.ToLower(f.Key) {
			t.Errorf("key %q is not lowercase", f.Key)
		}
	}
	if !strings.Contains(rec.Body.String(), `{"key":"cardkingdom","name":"Card Kingdom","shorthands":["CK","CKBLLast","CKGraded"]}`) {
		t.Errorf("body %s", rec.Body.String())
	}
}

func TestAPIStoresEmptyListsAreArrays(t *testing.T) {
	// Loaded, but nothing the scraper config names.
	stubScrapers(t, scraperStub{sellers: []string{"GN"}, vendors: []string{"GN"}})
	rec := httptest.NewRecorder()
	APIPlans(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
	if body := rec.Body.String(); !strings.Contains(body, `"implied":[]`) || !strings.Contains(body, `"stores":[]`) {
		t.Errorf("body %s", body)
	}
}

func TestAPIStoresIsUnavailableWhileLoading(t *testing.T) {
	for _, stub := range []scraperStub{{}, {config: magicStub.config, sellers: magicStub.sellers}, {config: magicStub.config, vendors: magicStub.vendors}} {
		stubScrapers(t, stub)
		rec := httptest.NewRecorder()
		APIPlans(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d", rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control %q", got)
		}
		if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"Stores are still loading."}` {
			t.Errorf("body %s", got)
		}
	}
}

func TestAPIStoresIsGetOnly(t *testing.T) {
	stubScrapers(t, magicStub)
	rec := httptest.NewRecorder()
	APIPlans(rec, httptest.NewRequest(http.MethodPost, "/api-plans/stores.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d", rec.Code)
	}
}

func TestEveryPackageIconIsDrawn(t *testing.T) {
	for _, p := range apiProducts.Packages {
		if _, ok := tierIcons[p.Icon]; !ok {
			t.Errorf("package %s: the page has no %q icon", p.Key, p.Icon)
		}
	}
}
