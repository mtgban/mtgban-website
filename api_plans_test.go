package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apiproductlist"
	"github.com/mtgban/mtgban-website/internal/pledge"
)

func apiPlansPage(t *testing.T, sig string) string {
	t.Helper()
	return apiPlansPageAt(t, sig, "/api-plans")
}

// apiPlansPageAt renders the page for a request path of the caller's choosing.
func apiPlansPageAt(t *testing.T, sig, target string) string {
	t.Helper()
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config().APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config().APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config().APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []matcher.Game{"magic", "pokemon"}, NewspaperOnSale: savedCfg.NewspaperOnSale, HistoryOnSale: savedCfg.HistoryOnSale}

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if sig != "" {
		req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
	}
	rec := httptest.NewRecorder()
	testSite.APIPlans(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

// withHistoryOnSale puts the history package on sale for one test.
func withHistoryOnSale(t *testing.T) {
	t.Helper()
	saved := Config()
	config := *saved
	config.APIGateway.HistoryOnSale = true
	liveConfig.Store(&config)
	t.Cleanup(func() { liveConfig.Store(saved) })
}

// Until the gateway sells history, the page keeps it off: no section, no card.
func TestAPIPlansHidesHistoryUntilOnSale(t *testing.T) {
	body := apiPlansPage(t, "")
	if strings.Contains(body, `id="api-package-history"`) || strings.Contains(body, "api-history") {
		t.Error("history shown with history_on_sale off")
	}
	if got := strings.Count(body, `class="card api-card`); got != 3 {
		t.Errorf("want three package cards, got %d", got)
	}
	if strings.Contains(body, `"key":"history"`) {
		t.Error("history package in the configurator data with history_on_sale off")
	}
	withHistoryOnSale(t)
	if body := apiPlansPage(t, ""); !strings.Contains(body, `"key":"history"`) {
		t.Error("history package missing from the configurator data with history_on_sale on")
	}
}

func TestAPIPlansRendersCatalog(t *testing.T) {
	withHistoryOnSale(t)
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
		"Price History", "$300", "Daily prices, a year back", "Updated twice a day",
		`name="package" id="api-package-history" value="history"`,
		`<section class="api-section api-history">`,
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
	// History sits in its own section after the podium, off the podium's grid.
	hist := strings.Index(body, `id="api-package-history"`)
	if !(carte < hist) {
		t.Errorf("history card before the podium: carte %d history %d", carte, hist)
	}
	if strings.Count(body, `class="card api-card`) != 4 {
		t.Errorf("want four package cards, got %d", strings.Count(body, `class="card api-card`))
	}
}

// A change link naming history is ignored while the package is off sale,
// so a crafted query can't pick a package the page does not render.
func TestAPIPlansChangeLinkIgnoresHistoryOffSale(t *testing.T) {
	body := apiPlansPageAt(t, "", "/api-plans?package=history")
	if !strings.Contains(body, `name="package" id="api-package-all_data" value="all_data" checked`) {
		t.Error("the top card should stay checked when history is off sale")
	}
	if !strings.Contains(body, `id="api-total-package">All Access</span>`) {
		t.Error("the total should still name the top card")
	}

	withHistoryOnSale(t)
	body = apiPlansPageAt(t, "", "/api-plans?package=history")
	if !strings.Contains(body, `name="package" id="api-package-history" value="history" checked`) {
		t.Error("the history card should check once history is on sale")
	}
}

func TestAPIPlansTrialButtonNeedsPledgeAndSecret(t *testing.T) {
	user := &pledge.User{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}

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
	withSigMode(t, true, false)
	rec := httptest.NewRecorder()
	testSite.APIPlans(rec, httptest.NewRequest(http.MethodGet, "/api-plans?invite=abc", nil))
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
	cards, top, history := podiumOrder(three)
	if top != "c" || cards[0].Key != "b" || cards[1].Key != "c" || cards[2].Key != "a" || len(history) != 0 {
		t.Errorf("three packages: %+v top %q history %+v", cards, top, history)
	}
	two := []apiproductlist.Package{{Key: "x", Monthly: 900}, {Key: "y", Monthly: 100}}
	cards, top, _ = podiumOrder(two)
	if top != "" || cards[0].Key != "y" || cards[1].Key != "x" {
		t.Errorf("two packages: %+v top %q", cards, top)
	}
	if two[0].Key != "x" {
		t.Error("input was reordered in place")
	}
	// A history package leaves the podium to the price packages.
	four := append(slices.Clone(three), apiproductlist.Package{Key: "h", Monthly: 300, Modes: []string{"history"}})
	cards, top, history = podiumOrder(four)
	if top != "c" || len(cards) != 3 || len(history) != 1 || history[0].Key != "h" {
		t.Errorf("with history: %+v top %q history %+v", cards, top, history)
	}
}

func TestAPIPlansManageLinkUsesTheHandoffWhenSignedIn(t *testing.T) {
	setGatewaySecret(t, "s")
	anon := apiPlansPage(t, "")
	if !strings.Contains(anon, `href="https://api.example/account"`) {
		t.Error("anonymous reader should be sent to the gateway login")
	}
	user := &pledge.User{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}
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
	unverified := &pledge.User{Email: "ann@example.com", FullName: "Ann Example"}
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
	country      map[string]string
	metadata     []string
	overrides    map[string]string
	retailBlock  []string
	buylistBlock []string
}

// stubScrapers installs the stub and restores the real scrapers, index and
// config after the test.
func stubScrapers(t *testing.T, s scraperStub) {
	t.Helper()
	prevOverrides := Config().ScraperConfig.NameOverride
	prevRetail, prevBuylist := Config().Stores.SearchRetailBlockList, Config().Stores.SearchBuylistBlockList
	t.Cleanup(func() {
		Config().ScraperConfig.NameOverride = prevOverrides
		Config().Stores.SearchRetailBlockList, Config().Stores.SearchBuylistBlockList = prevRetail, prevBuylist
	})
	info := func(sh string) mtgban.ScraperInfo {
		name, ok := s.names[sh]
		if !ok {
			name = sh
		}
		return mtgban.ScraperInfo{
			Shorthand:    sh,
			Name:         name,
			SealedMode:   slices.Contains(s.sealed, sh),
			CountryFlag:  s.country[sh],
			MetadataOnly: slices.Contains(s.metadata, sh),
		}
	}
	sellers := []mtgban.Seller{}
	for _, sh := range s.sellers {
		sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, info(sh)))
	}
	vendors := []mtgban.Vendor{}
	for _, sh := range s.vendors {
		vendors = append(vendors, mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, info(sh)))
	}
	withPrices(t, sellers, vendors)
	withScraperIndex(t, buildScraperIndex(s.config))
	Config().ScraperConfig.NameOverride = s.overrides
	Config().Stores.SearchRetailBlockList, Config().Stores.SearchBuylistBlockList = s.retailBlock, s.buylistBlock
}

// magicStub mirrors the live magic config: split tcg_* and cardkingdom_* keys, blocklists, sealed scrapers, a session store.
var magicStub = scraperStub{
	config: map[string]map[string][]string{
		"tcg_index":          {"retail": {"TCGLow", "TCGDirectLow"}},
		"tcg_market":         {"retail": {"TCGMarket"}},
		"tcg_syplist":        {"buylist": {"SYP"}},
		"cardkingdom":        {"retail": {"CK"}, "buylist": {"CKBLLast"}},
		"cardkingdom_graded": {"retail": {"CKGraded"}},
		"cardkingdom_sealed": {"retail": {"CKSealed", "CKBox"}},
		"abugames":           {"retail": {"ABU"}, "buylist": {"ABUCredit"}},
		"starcitygames":      {"retail": {"SCG"}, "buylist": {"SCGBL"}},
		"strikezone":         {"retail": {"SZ"}},
		"manapool":           {"retail": {"MP"}},
		"magiccorner":        {"retail": {"MC"}},
		"sealed_ev":          {"retail": {"CKEV"}},
		"coolstuffinc":       {"retail": {"CSI"}},
		"cardmarket":         {"retail": {"MKM", "MKMPS", "MKMLow", "MKMTrend"}},
		"tcg_sealed":         {"retail": {"TCGSealed"}},
	},
	sellers: []string{"TCGLow", "TCGDirectLow", "TCGMarket", "CK", "CKGraded", "ABU", "SCG", "SZ", "MP", "MC", "CKSealed", "CKEV", "GN", "MKM", "MKMPS", "MKMLow", "MKMTrend", "TCGSealed", "CKBox"},
	vendors: []string{"SYP", "CKBLLast", "ABUCredit", "SCGBL"},
	sealed:  []string{"CKEV", "CKSealed", "TCGSealed", "CKBox"},
	names: map[string]string{
		"TCGLow": "TCG Low", "TCGDirectLow": "TCG Direct Low", "TCGMarket": "TCG Market", "SYP": "TCG SYP List",
		"CK": "Card Kingdom", "CKBLLast": "Card Kingdom", "CKGraded": "card kingdom Graded",
		"CKSealed": "Card Kingdom Sealed", "CKEV": "Card Kingdom EV",
		"ABU": "ABU Games", "ABUCredit": "ABU Credit",
		"SCG": "StarCityGames", "SCGBL": "StarCityGames",
		"SZ": "Strike Zone", "MP": "mana pool",
		"MC": "Magic Corner", "GN": "Game Nerdz",
		"MKM": "Cardmarket", "MKMPS": "Cardmarket Powersellers", "MKMLow": "MKM Low", "MKMTrend": "MKM Trend",
		"TCGSealed": "TCG Sealed", "CKBox": "Card Kingdom Box",
	},
	country:  map[string]string{"MKM": "EU", "MKMPS": "EU", "MKMLow": "EU", "MKMTrend": "EU", "MC": "IT"},
	metadata: []string{"MKMLow", "MKMTrend"},
	// The second entry renames a family, not a scraper.
	overrides:    map[string]string{"StarCityGames": "Star City Games", "ABU": "ABU Games"},
	retailBlock:  []string{"TCGDirectLow", "MC"},
	buylistBlock: []string{"SCGBL"},
}

func TestStoreFamiliesFromTheServedScrapers(t *testing.T) {
	stubScrapers(t, magicStub)
	implied, selectable, sealed := storeFamilies(currentPrices())
	// The tcg_* keys merge into one family, named by the price list.
	if len(implied) != 1 || implied[0].Key != "tcg" || implied[0].Name != "TCGplayer" || !slices.Equal(implied[0].Shorthands, []string{"SYP", "TCGLow", "TCGMarket"}) || !implied[0].Base {
		t.Errorf("implied %+v", implied)
	}
	want := []StoreFamily{
		{Key: "abugames", Name: "ABU Games", Shorthands: []string{"ABU", "ABUCredit"}, Base: true},
		{Key: "cardkingdom", Name: "Card Kingdom", Shorthands: []string{"CK", "CKBLLast", "CKGraded"}, Base: true},
		// Its two indexes are metadata-only, so Base Access covers part of it.
		{Key: "cardmarket", Name: "Cardmarket", Shorthands: []string{"MKM", "MKMLow", "MKMPS", "MKMTrend"}, Base: true},
		{Key: "manapool", Name: "mana pool", Shorthands: []string{"MP"}, Base: true},
		{Key: "starcitygames", Name: "Star City Games", Shorthands: []string{"SCG"}, Base: true},
		{Key: "strikezone", Name: "Strike Zone", Shorthands: []string{"SZ"}, Base: true},
	}
	if !slices.EqualFunc(selectable, want, sameFamily) {
		t.Errorf("selectable %+v, want %+v", selectable, want)
	}
	// The sealed_ev key is the EV estimate, not a store, so no family is keyed sealed.
	wantSealed := []StoreFamily{
		{Key: "tcg", Name: "TCGplayer", Shorthands: []string{"TCGSealed"}},
		{Key: "cardkingdom", Name: "Card Kingdom", Shorthands: []string{"CKBox", "CKSealed"}},
	}
	if !slices.EqualFunc(sealed, wantSealed, sameFamily) {
		t.Errorf("sealed %+v, want %+v", sealed, wantSealed)
	}

	// A served foreign store is selectable but outside Base Access.
	stub := magicStub
	stub.retailBlock = []string{"TCGDirectLow"}
	stubScrapers(t, stub)
	_, selectable, _ = storeFamilies(currentPrices())
	i := slices.IndexFunc(selectable, func(f StoreFamily) bool { return f.Key == "magiccorner" })
	if i < 0 || selectable[i].Base {
		t.Errorf("magiccorner %+v", selectable)
	}
}

// sameFamily compares every field of two families.
func sameFamily(a, b StoreFamily) bool {
	return a.Key == b.Key && a.Name == b.Name && slices.Equal(a.Shorthands, b.Shorthands) && a.Base == b.Base
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
		{[]string{"Cardmarket", "Cardmarket Powersellers", "MKM Low", "MKM Trend"}, "Cardmarket"},
		{[]string{"MKM Low", "MKM Trend", "Cardmarket Powersellers", "Cardmarket"}, "Cardmarket"},
		{[]string{"A", "A One", "B", "B Two"}, "A"},
		{[]string{"B", "B One", "B Two", "A", "A One"}, "B"},
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
	implied, selectable, sealed := storeFamilies(currentPrices())
	if len(implied) != 0 || len(selectable) != 0 || len(sealed) != 0 {
		t.Errorf("implied %+v selectable %+v sealed %+v", implied, selectable, sealed)
	}
}

func TestAPIPlansStoreRowComesFromTheServedScrapers(t *testing.T) {
	stubScrapers(t, magicStub)
	body := apiPlansPage(t, "")
	if !strings.Contains(body, "TCGplayer always included, your first store is on us, each additional is $150/month") {
		t.Error("legend lacks the implied family")
	}
	for _, want := range []string{`name="stores" value="abugames" checked disabled> ABU Games`, `name="stores" value="cardkingdom" checked disabled> Card Kingdom`, `name="stores" value="starcitygames" checked disabled> Star City Games`} {
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
	// Every package shows the fieldset; an explicit one leaves the boxes live.
	if strings.Contains(body, `id="api-stores" hidden`) {
		t.Error("a preset package hides the stores fieldset")
	}
	explicit := apiPlansPageAt(t, "", "/api-plans?package=starter")
	if !strings.Contains(explicit, `name="stores" value="abugames" checked>`) {
		t.Error("an explicit package should leave the store boxes enabled")
	}
	if strings.Contains(explicit, `id="api-stores" hidden`) {
		t.Error("an explicit package should show the stores fieldset")
	}
}

// chipIn is the label in the row with that id holding attr, from <label to </label>.
func chipIn(t *testing.T, body, row, attr string) string {
	t.Helper()
	start := strings.Index(body, `id="`+row+`"`)
	if start < 0 {
		t.Fatalf("no %s row", row)
	}
	rest := body[start:]
	if end := strings.Index(rest, `class="api-store-row"`); end >= 0 {
		rest = rest[:end]
	}
	i := strings.Index(rest, attr)
	if i < 0 {
		t.Fatalf("%s row lacks %s", row, attr)
	}
	open := strings.LastIndex(rest[:i], "<label")
	return rest[open : i+strings.Index(rest[i:], "</label>")]
}

func TestAPIPlansStoreRowsLitByThePackage(t *testing.T) {
	stubScrapers(t, magicStub)
	body := apiPlansPage(t, "")
	if !strings.Contains(body, `<fieldset class="api-fieldset" id="api-stores">`) {
		t.Error("the stores fieldset is hidden or missing on All Access")
	}
	tcg := chipIn(t, body, "api-stores-singles", `data-family="tcg"`)
	if !strings.Contains(tcg, `class="api-choice api-choice-locked"`) || !strings.Contains(tcg, `<input type="checkbox" checked disabled> TCGplayer`) || strings.Contains(tcg, "name=") {
		t.Errorf("tcg chip %s", tcg)
	}
	for _, want := range []string{`name="stores" value="cardkingdom" checked disabled`, `data-family="cardmarket" data-base="true"`} {
		if !strings.Contains(body, want) {
			t.Errorf("All Access lacks %s", want)
		}
	}
	for _, family := range []string{"tcg", "cardkingdom"} {
		if l := chipIn(t, body, "api-stores-sealed", `data-family="`+family+`"`); !strings.Contains(l, "checked") {
			t.Errorf("All Access sealed %s unchecked: %s", family, l)
		}
	}
	if strings.Contains(body, "api-choice-off") {
		t.Error("All Access has an unlit chip")
	}
	if !strings.Contains(body, `<span class="api-legend-note" data-when="explicit" hidden>`) || !strings.Contains(body, `<span class="api-legend-note" data-when="preset">Lit stores are included in the package</span>`) {
		t.Error("All Access legend notes in the wrong state")
	}

	// Magic Corner served and unblocked: a family outside Base Access.
	stub := magicStub
	stub.retailBlock = []string{"TCGDirectLow"}
	stubScrapers(t, stub)
	base := apiPlansPageAt(t, "", "/api-plans?package=all_stores")
	if ck := chipIn(t, base, "api-stores-singles", `data-family="cardkingdom"`); strings.Contains(ck, "api-choice-off") || !strings.Contains(ck, `value="cardkingdom" checked disabled`) {
		t.Errorf("Base Access cardkingdom %s", ck)
	}
	mc := chipIn(t, base, "api-stores-singles", `data-family="magiccorner"`)
	if !strings.Contains(mc, `class="api-choice api-choice-off"`) || !strings.Contains(mc, `data-base="false"`) || !strings.Contains(mc, `value="magiccorner" disabled>`) || strings.Contains(mc, "checked") {
		t.Errorf("Base Access magiccorner %s", mc)
	}
	for _, family := range []string{"tcg", "cardkingdom"} {
		if l := chipIn(t, base, "api-stores-sealed", `data-family="`+family+`"`); !strings.Contains(l, "api-choice-off") || strings.Contains(l, "checked") {
			t.Errorf("Base Access sealed %s lit: %s", family, l)
		}
	}

	stubScrapers(t, magicStub)
	starter := apiPlansPageAt(t, "", "/api-plans?package=starter")
	if !strings.Contains(starter, `name="stores" value="abugames" checked>`) || !strings.Contains(starter, `name="stores" value="cardkingdom">`) {
		t.Error("starter boxes are not live with the first checked")
	}
	if l := chipIn(t, starter, "api-stores-sealed", `data-family="cardkingdom"`); !strings.Contains(l, "api-choice-off") {
		t.Errorf("starter sealed lit: %s", l)
	}
	if !strings.Contains(starter, `<span class="api-legend-note" data-when="explicit">`) || !strings.Contains(starter, `<span class="api-legend-note" data-when="preset" hidden>Lit stores are included in the package</span>`) {
		t.Error("starter legend notes in the wrong state")
	}
}

func TestAPIPlansSealedRowOnlyWhenServed(t *testing.T) {
	stub := magicStub
	stub.sellers = slices.DeleteFunc(slices.Clone(magicStub.sellers), func(sh string) bool {
		return sh == "TCGSealed" || sh == "CKSealed" || sh == "CKBox"
	})
	stub.sealed = []string{"CKEV"}
	stubScrapers(t, stub)
	body := apiPlansPage(t, "")
	if strings.Contains(body, `id="api-stores-sealed"`) {
		t.Error("sealed row drawn with no sealed store served")
	}
	if !strings.Contains(body, `id="api-stores-singles"`) {
		t.Error("singles row missing")
	}
}

// A preset package submits no stores: every box is disabled and no paid box is kept.
func TestAPIPlansPresetPackageSubmitsNoStores(t *testing.T) {
	stubScrapers(t, magicStub)
	body := apiPlansPageAt(t, "", "/api-plans?change=1&package=all_stores&stores=cardkingdom,retired")
	boxes := strings.Split(body, `name="stores"`)[1:]
	if len(boxes) == 0 {
		t.Fatal("no store boxes")
	}
	for _, box := range boxes {
		if box = box[:strings.Index(box, ">")]; !strings.Contains(box, "disabled") {
			t.Errorf("live box on a preset package: %s", box)
		}
	}
	if strings.Contains(body, `value="retired"`) {
		t.Error("a paid store box on a preset package")
	}
}

// A package with no store scope, the history one, lights no store chip.
func TestAPIPlansHistoryScopeLightsNoStore(t *testing.T) {
	withHistoryOnSale(t)
	stubScrapers(t, magicStub)
	body := apiPlansPageAt(t, "", "/api-plans?package=history")
	parts := strings.Split(body, `name="stores"`)
	if len(parts) < 2 {
		t.Fatal("no store boxes")
	}
	for i := 1; i < len(parts); i++ {
		label := parts[i-1][strings.LastIndex(parts[i-1], "<label"):]
		box := parts[i][:strings.Index(parts[i], ">")]
		if !strings.Contains(label, "api-choice-off") || !strings.Contains(box, "disabled") || strings.Contains(box, "checked") {
			t.Errorf("history lights a store: %s name=\"stores\"%s", label, box)
		}
	}
	for _, family := range []string{"tcg", "cardkingdom"} {
		if l := chipIn(t, body, "api-stores-sealed", `data-family="`+family+`"`); !strings.Contains(l, "api-choice-off") {
			t.Errorf("history sealed %s lit: %s", family, l)
		}
	}
}

func TestAPIPlansJSONCarriesScopeAndSealed(t *testing.T) {
	body := apiPlansPage(t, "")
	for key, want := range map[string]string{
		"all_data":   `"scope":"ALL_ACCESS","sealed":true`,
		"all_stores": `"scope":"BASE_ACCESS","sealed":false`,
		"starter":    `"scope":"explicit"`,
	} {
		i := strings.Index(body, `{"key":"`+key+`"`)
		if i < 0 {
			t.Fatalf("no %s package in the configurator data", key)
		}
		if pkg := body[i : i+strings.Index(body[i:], "}")]; !strings.Contains(pkg, want) {
			t.Errorf("%s: %s lacks %s", key, pkg, want)
		}
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
	if !strings.Contains(body, `name="stores" value="retired" checked>`) || strings.Contains(body, `value="retired" checked disabled`) {
		t.Error("the paid store box is not checked and live on starter")
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

// enforceSigning serves a nav's sub-pages unsigned only when the ACL's Any
// tier grants that nav, so stores.json must not hang off the API page: the
// gateway reads it without a signature whether or not the pricing page is public.
func TestAPIStoresIsNotGatedByTheAPIPage(t *testing.T) {
	for _, sub := range ExtraNavs["API"].SubPages {
		if sub.Link == "/api-plans/stores.json" {
			t.Fatal("/api-plans/stores.json is a sub-page of the API page, so its access follows the pricing page's ACL")
		}
	}
}

func TestAPIStoresServesTheFamilies(t *testing.T) {
	stubScrapers(t, magicStub)
	savedGame := Config().Game
	t.Cleanup(func() { Config().Game = savedGame })
	Config().Game = "magic"
	rec := httptest.NewRecorder()
	testSite.APIStores(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
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
		Sealed  []StoreFamily `json:"sealed"`
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
	if len(doc.Stores) != 6 || doc.Stores[0].Name != "ABU Games" || doc.Stores[1].Name != "Card Kingdom" || doc.Stores[2].Name != "Cardmarket" || doc.Stores[3].Name != "mana pool" || doc.Stores[4].Name != "Star City Games" {
		t.Errorf("stores %+v", doc.Stores)
	}
	wantSealed := []StoreFamily{
		{Key: "tcg", Name: "TCGplayer", Shorthands: []string{"TCGSealed"}},
		{Key: "cardkingdom", Name: "Card Kingdom", Shorthands: []string{"CKBox", "CKSealed"}},
	}
	if !slices.EqualFunc(doc.Sealed, wantSealed, sameFamily) {
		t.Errorf("sealed %+v, want %+v", doc.Sealed, wantSealed)
	}
	for _, f := range append(append(doc.Implied, doc.Stores...), doc.Sealed...) {
		if f.Key != strings.ToLower(f.Key) {
			t.Errorf("key %q is not lowercase", f.Key)
		}
	}
	if !strings.Contains(rec.Body.String(), `{"key":"cardkingdom","name":"Card Kingdom","shorthands":["CK","CKBLLast","CKGraded"],"base":true}`) {
		t.Errorf("body %s", rec.Body.String())
	}
}

func TestAPIStoresEmptyListsAreArrays(t *testing.T) {
	// Loaded, but nothing the scraper config names.
	stubScrapers(t, scraperStub{sellers: []string{"GN"}, vendors: []string{"GN"}})
	rec := httptest.NewRecorder()
	testSite.APIStores(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
	if body := rec.Body.String(); !strings.Contains(body, `"implied":[]`) || !strings.Contains(body, `"stores":[]`) || !strings.Contains(body, `"sealed":[]`) {
		t.Errorf("body %s", body)
	}
}

func TestAPIStoresIsUnavailableWhileLoading(t *testing.T) {
	for _, stub := range []scraperStub{{}, {config: magicStub.config, sellers: magicStub.sellers}, {config: magicStub.config, vendors: magicStub.vendors}} {
		stubScrapers(t, stub)
		rec := httptest.NewRecorder()
		testSite.APIStores(rec, httptest.NewRequest(http.MethodGet, "/api-plans/stores.json", nil))
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
	testSite.APIStores(rec, httptest.NewRequest(http.MethodPost, "/api-plans/stores.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d", rec.Code)
	}
}

// The newspaper add-on reaches the page and its data only once the flag is set.
func TestAPIPlansNewspaperAddonBehindTheFlag(t *testing.T) {
	withConfigCopy(t)
	Config().APIGateway.NewspaperOnSale = false
	off := apiPlansPage(t, "")
	for _, absent := range []string{`name="addons"`, "api-card-addon", "Newspaper reports", `"mode_addons"`, `"newspaper":`, `"addon_applies"`} {
		if strings.Contains(off, absent) {
			t.Errorf("off sale, the page carries %s", absent)
		}
	}

	Config().APIGateway.NewspaperOnSale = true
	on := apiPlansPage(t, "")
	for _, present := range []string{
		`"mode_addons":["newspaper"]`,
		`"newspaper":`,
		`"addon_applies":{"newspaper":["starter","all_stores"]}`,
		`Add Newspaper reports, $200/month`,
	} {
		if !strings.Contains(on, present) {
			t.Errorf("on sale, the page lacks %s", present)
		}
	}
	if strings.Contains(on, `id="api-mode-addons"`) {
		t.Error("the add-ons fieldset is still drawn")
	}
	if strings.Contains(on, `data-package="all_data">`) {
		t.Error("the add-on is offered on a card it does not apply to")
	}
	for _, key := range []string{"starter", "all_stores"} {
		box := strings.Index(on, `<input type="checkbox" name="addons" value="newspaper" data-package="`+key+`">`)
		card := strings.Index(on, `id="api-package-`+key+`"`)
		if box < 0 || card < 0 {
			t.Fatalf("%s: checkbox %d card %d", key, box, card)
		}
		next := strings.Index(on[card:], `class="card api-card`)
		end := len(on)
		if next >= 0 {
			end = card + next
		}
		if box < card || box > end {
			t.Errorf("%s: checkbox %d outside its card %d..%d", key, box, card, end)
		}
	}
	for key, want := range map[string]bool{"starter": false, "all_stores": false, "all_data": true} {
		card := on[strings.Index(on, `id="api-package-`+key+`"`):]
		card = card[:strings.Index(card, `</section>`)]
		if next := strings.Index(card, `class="card api-card`); next >= 0 {
			card = card[:next]
		}
		if got := strings.Contains(card, `<li>Includes the Newspaper reports</li>`); got != want {
			t.Errorf("%s: newspaper bullet %v, want %v", key, got, want)
		}
	}
}

// Caveats are drawn as a crosses list after the bullets, on the packages that have them.
func TestAPIPlansDrawsCaveatsAsCrosses(t *testing.T) {
	body := apiPlansPage(t, "")
	if n := strings.Count(body, `<ul class="api-caveats">`); n != 2 {
		t.Errorf("caveat lists = %d, want 2", n)
	}
	if n := strings.Count(body, `<li>No Sealed or EV data</li>`); n != 2 {
		t.Errorf("sealed caveats = %d, want 2", n)
	}
	top := strings.Index(body, `<div class="card api-card api-card-top">`)
	if top < 0 {
		t.Fatal("no top card")
	}
	rest := body[top+1:]
	end := len(rest)
	if i := strings.Index(rest, `class="card api-card`); i >= 0 {
		end = i
	}
	if i := strings.Index(rest, `</section>`); i >= 0 && i < end {
		end = i
	}
	if strings.Contains(rest[:end], "api-caveats") {
		t.Error("the top card has caveats")
	}
}

// One trial note sits below the cards, and every card carries the billed note.
func TestAPIPlansTrialNoteBelowTheCards(t *testing.T) {
	body := apiPlansPage(t, "")
	if n := strings.Count(body, "api-trial-note"); n != 1 {
		t.Fatalf("trial notes = %d, want 1", n)
	}
	third := 0
	for i := 0; i < 3; i++ {
		j := strings.Index(body[third:], `class="card api-card`)
		if j < 0 {
			t.Fatal("fewer than three cards")
		}
		third += j + 1
	}
	note, conf := strings.Index(body, "api-trial-note"), strings.Index(body, "api-configurator")
	if !(third < note && note < conf) {
		t.Errorf("note out of place: third card %d note %d configurator %d", third, note, conf)
	}
	if n := strings.Count(body, "Billed monthly, cancel any time"); n != 3 {
		t.Errorf("billed notes = %d, want 3", n)
	}

	user := &pledge.User{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}
	setGatewaySecret(t, "s")
	page := apiPlansPage(t, sign("Legacy", user, nil, DefaultSignatureDuration))
	n := strings.Index(page, "api-trial-note")
	if n < 0 || !strings.Contains(page[n:n+400], `href="/api-trial`) {
		t.Error("trial link missing from the note")
	}
}

func TestEveryPackageIconIsDrawn(t *testing.T) {
	for _, p := range apiProducts.Packages {
		if _, ok := tierIcons[p.Icon]; !ok {
			t.Errorf("package %s: the page has no %q icon", p.Key, p.Icon)
		}
	}
}
