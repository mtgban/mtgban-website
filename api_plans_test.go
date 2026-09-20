package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		`name="stores" value="CK"`,
		`name="return_to" value="https://mtgban.com/api-plans"`,
		`href="https://api.example/account"`,
		"/guide",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, `href="/api-trial"`) {
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
	if strings.Contains(apiPlansPage(t, sign("Legacy", user, nil)), `href="/api-trial"`) {
		t.Error("trial offered without TRIAL_SECRET")
	}

	t.Setenv("TRIAL_SECRET", "s")
	if strings.Contains(apiPlansPage(t, sign("", user, nil)), `href="/api-trial"`) {
		t.Error("trial offered to a login with no pledge")
	}
	if !strings.Contains(apiPlansPage(t, sign("Legacy", user, nil)), `href="/api-trial"`) {
		t.Error("trial missing for a pledged supporter")
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
}

func TestFormatUSD(t *testing.T) {
	for cents, want := range map[int64]string{20000: "$200", 150000: "$1,500", 1250: "$12.50", 100000000: "$1,000,000"} {
		if got := formatUSD(cents); got != want {
			t.Errorf("%d: %s want %s", cents, got, want)
		}
	}
}
