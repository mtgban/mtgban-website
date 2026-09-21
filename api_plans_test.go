package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/apiproductlist"
)

func apiPlansPage(t *testing.T, sig string) string {
	t.Helper()
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config.APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config.APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic", "pokemon"}}

	req := httptest.NewRequest(http.MethodGet, "/api-plans", nil)
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
		"TCGplayer plus one store", "$200", "All EU/US stores, no sealed", "$500", "All data", "$800",
		"$150", "$1,000", "$1,500",
		`action="https://api.example/checkout"`,
		`name="package" value="starter"`,
		`name="games" value="pokemon"`,
		`name="stores" value="CK" checked`,
		`name="return_to" value="https://mtgban.com/api-plans"`,
		`href="https://api.example/account"`,
		"/guide",
		`name="interval" value="monthly" checked`,
		`<fieldset class="api-fieldset" hidden>`,
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
}

func TestAPIPlansTrialButtonNeedsPledgeAndSecret(t *testing.T) {
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example"}

	t.Setenv("TRIAL_SECRET", "")
	if strings.Contains(apiPlansPage(t, sign("Legacy", user, nil)), `href="/api-trial`) {
		t.Error("trial offered without TRIAL_SECRET")
	}

	t.Setenv("TRIAL_SECRET", "s")
	if strings.Contains(apiPlansPage(t, sign("", user, nil)), `href="/api-trial`) {
		t.Error("trial offered to a login with no pledge")
	}
	// html/template percent-encodes the query value, including the scheme's slashes.
	page := apiPlansPage(t, sign("Legacy", user, nil))
	if !strings.Contains(page, `href="/api-trial?return_to=https%3a%2f%2fmtgban.com%2fapi-plans"`) {
		t.Error("trial missing for a pledged supporter")
	}
	if !strings.Contains(page, "15 days") {
		t.Error("trial length missing from the page")
	}
	if !strings.Contains(page, "15 days of all data") {
		t.Error("trial note length missing from the page")
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

func TestAddonScope(t *testing.T) {
	packages := []apiproductlist.Package{
		{Key: "starter", Name: "Starter"},
		{Key: "all_stores", Name: "All Stores"},
		{Key: "all_data", Name: "All Data"},
	}
	every := apiproductlist.Addon{Key: "extra_game", AppliesTo: []string{"starter", "all_stores", "all_data"}}
	if got := addonScope(every, packages); got != "on any package" {
		t.Errorf("addon applying to all packages: got %q", got)
	}
	one := apiproductlist.Addon{Key: "extra_store", AppliesTo: []string{"starter"}}
	if got := addonScope(one, packages); got != "on the Starter package" {
		t.Errorf("addon applying to one package: got %q", got)
	}
}

func TestScopeBullets(t *testing.T) {
	cat := &apiproductlist.ProductList{
		Stores: []apiproductlist.Store{{Key: "TCG", Name: "TCGplayer", Implied: true}},
	}

	one := apiproductlist.Package{StoreScope: apiproductlist.StoreScopeExplicit, IncludedStores: 1}
	got := scopeBullets(one, cat)
	if !strings.Contains(got[0], "of your choice") {
		t.Errorf("explicit one store: %v", got)
	}
	if got[0] != "One store of your choice, TCGplayer always included" {
		t.Errorf("explicit one store wording: %v", got)
	}

	two := apiproductlist.Package{StoreScope: apiproductlist.StoreScopeExplicit, IncludedStores: 2}
	got = scopeBullets(two, cat)
	if got[0] != "2 stores of your choice, TCGplayer always included" {
		t.Errorf("explicit two stores wording: %v", got)
	}
	if got[1] != "Add more stores as you need them" {
		t.Errorf("explicit second bullet: %v", got)
	}

	base := apiproductlist.Package{StoreScope: apiproductlist.StoreScopeBase}
	got = scopeBullets(base, cat)
	if !strings.Contains(strings.Join(got, " "), "EU and US") {
		t.Errorf("base bullets: %v", got)
	}

	all := apiproductlist.Package{StoreScope: apiproductlist.StoreScopeAll}
	got = scopeBullets(all, cat)
	if !strings.Contains(strings.Join(got, " "), "Sealed product included") {
		t.Errorf("all bullets: %v", got)
	}

	multi := &apiproductlist.ProductList{
		Stores: []apiproductlist.Store{
			{Key: "TCG", Name: "TCGplayer", Implied: true},
			{Key: "CK", Name: "Card Kingdom", Implied: true},
		},
	}
	got = scopeBullets(one, multi)
	if got[0] != "One store of your choice, TCGplayer, Card Kingdom always included" {
		t.Errorf("explicit wording with two implied stores: %v", got)
	}
}

func TestFormatUSD(t *testing.T) {
	for cents, want := range map[int64]string{20000: "$200", 150000: "$1,500", 1250: "$12.50", 100000000: "$1,000,000"} {
		if got := formatUSD(cents); got != want {
			t.Errorf("%d: %s want %s", cents, got, want)
		}
	}
}
