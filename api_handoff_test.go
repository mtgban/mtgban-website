package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/apihandoff"
)

func handoffRequest(t *testing.T, handler http.HandlerFunc, path, sig string) *httptest.ResponseRecorder {
	t.Helper()
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config.APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config.APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic"}}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if sig != "" {
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestAPITrialRedirectsWithVerifiableToken(t *testing.T) {
	t.Setenv("TRIAL_SECRET", "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example"}
	rec := handoffRequest(t, APITrial, "/api-trial?return_to=https://pokemon.mtgban.com/api-plans", sign("Legacy", user, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Scheme+"://"+loc.Host+loc.Path != "https://api.example/trial" {
		t.Fatalf("location %q", rec.Header().Get("Location"))
	}
	claims, err := apihandoff.Verify([]byte("trial-secret"), loc.Query().Get("t"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Email != "ann@example.com" || claims.Name != "Ann Example" || claims.Purpose != apihandoff.PurposeTrial || claims.Nonce == "" {
		t.Errorf("claims %+v", claims)
	}
	if loc.Query().Get("return_to") != "https://pokemon.mtgban.com/api-plans" {
		t.Errorf("return_to dropped: %q", loc.RawQuery)
	}
}

func TestAPITrialNeedsAPledge(t *testing.T) {
	t.Setenv("TRIAL_SECRET", "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	rec := handoffRequest(t, APITrial, "/api-trial", sign("", user, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPITrialPledge) {
		t.Errorf("status %d, body lacks the pledge message", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("redirected without a pledge")
	}
}

func TestAPILoginWorksWithoutAPledge(t *testing.T) {
	t.Setenv("TRIAL_SECRET", "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob"}
	rec := handoffRequest(t, APILogin, "/api-login", sign("", user, nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/session?t=") {
		t.Errorf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	claims, err := apihandoff.Verify([]byte("trial-secret"), loc.Query().Get("t"), time.Now())
	if err != nil || claims.Purpose != apihandoff.PurposeLogin {
		t.Errorf("claims %+v err %v", claims, err)
	}
}

func TestAPIHandoffDisabledWithoutSecret(t *testing.T) {
	t.Setenv("TRIAL_SECRET", "")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	rec := handoffRequest(t, APILogin, "/api-login", sign("Legacy", user, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPIHandoffOff) {
		t.Errorf("status %d, body lacks the disabled message", rec.Code)
	}
}

func TestAPIHandoffNavEntriesAreRegisteredButNotListed(t *testing.T) {
	for _, name := range []string{"APITrial", "APILogin"} {
		nav, ok := ExtraNavs[name]
		if !ok || nav.Public || nav.Handle == nil {
			t.Errorf("%s: missing, public, or without a handler", name)
		}
		for _, o := range OrderNav {
			if o == name {
				t.Errorf("%s must not be in OrderNav", name)
			}
		}
	}
}
