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

// setGatewaySecret installs the shared secret the handoff signs with; empty turns the handoff off.
func setGatewaySecret(t *testing.T, secret string) {
	t.Helper()
	saved, savedGame := Config.APIUserSecrets, Config.Game
	t.Cleanup(func() { Config.APIUserSecrets, Config.Game = saved, savedGame })
	Config.Game = "magic"
	Config.APIUserSecrets = map[string]string{}
	if secret != "" {
		Config.APIUserSecrets[apiGatewayUser] = secret
	}
}

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
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example"}
	rec := handoffRequest(t, APITrial, "/api-trial?return_to=https://pokemon.mtgban.com/api-plans", sign("Legacy", user, nil, DefaultSignatureDuration))
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
	if claims.Email != "ann@example.com" || claims.Name != "Ann Example" || claims.Purpose != apihandoff.PurposeTrial || claims.Game != "magic" || claims.Nonce == "" {
		t.Errorf("claims %+v", claims)
	}
	if loc.Query().Get("return_to") != "https://pokemon.mtgban.com/api-plans" {
		t.Errorf("return_to dropped: %q", loc.RawQuery)
	}
}

func TestAPITrialNeedsAPledge(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	rec := handoffRequest(t, APITrial, "/api-trial", sign("", user, nil, DefaultSignatureDuration))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPITrialPledge) {
		t.Errorf("status %d, body lacks the pledge message", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("redirected without a pledge")
	}
}

func TestAPILoginWorksWithoutAPledge(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob"}
	rec := handoffRequest(t, APILogin, "/api-login", sign("", user, nil, DefaultSignatureDuration))
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
	setGatewaySecret(t, "")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	rec := handoffRequest(t, APILogin, "/api-login", sign("Legacy", user, nil, DefaultSignatureDuration))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPIHandoffOff) {
		t.Errorf("status %d, body lacks the disabled message", rec.Code)
	}
}

func TestAPIHandoffsAreHiddenSubPagesOfTheAPIPage(t *testing.T) {
	api, ok := ExtraNavs["API"]
	if !ok {
		t.Fatal("API nav missing")
	}
	for _, want := range []string{"/api-trial", "/api-login"} {
		found := false
		for _, sub := range api.SubPages {
			if sub.Link == want {
				found = true
				if sub.ShouldHide == nil || !sub.ShouldHide() {
					t.Errorf("%s is listed in the navbar", want)
				}
			}
		}
		if !found {
			t.Errorf("%s is not a sub-page of the API page", want)
		}
	}
	for _, name := range []string{"APITrial", "APILogin"} {
		if _, ok := ExtraNavs[name]; ok {
			t.Errorf("%s still has its own nav entry", name)
		}
	}
}

func TestAPIPlansDispatchesHandoffSubPages(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob"}
	rec := handoffRequest(t, APIPlans, "/api-login", sign("", user, nil, DefaultSignatureDuration))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/session?t=") {
		t.Errorf("login via the API page: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = handoffRequest(t, APIPlans, "/api-trial", sign("", user, nil, DefaultSignatureDuration))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPITrialPledge) {
		t.Errorf("trial via the API page: status %d", rec.Code)
	}
}

func TestAPIHandoffIgnoresATamperedSignature(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	// handoffRequest turns SigCheck off; a tampered cookie must still be refused with it on.
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config.APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config.APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, true
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic"}}
	// Signed after DevMode is set, so the signature carries the same link the check expects.
	sig := sign("Legacy", user, nil, DefaultSignatureDuration)
	req := httptest.NewRequest(http.MethodGet, "/api-login", nil)
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig[:len(sig)-4] + "AAAA"})
	rec := httptest.NewRecorder()
	APILogin(rec, req)
	if rec.Code == http.StatusFound {
		t.Fatal("a tampered signature minted a handoff token")
	}
	if verifiedSignature(req) != "" {
		t.Error("tampered signature verified")
	}
	good := httptest.NewRequest(http.MethodGet, "/api-login", nil)
	good.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	if verifiedSignature(good) != sig {
		t.Error("a valid signature did not verify")
	}
}

func TestAPIHandoffDropsUntrustedReturnTo(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob"}
	rec := handoffRequest(t, APILogin, "/api-login?return_to=https://evil.example/steal", sign("", user, nil, DefaultSignatureDuration))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Has("return_to") {
		t.Errorf("untrusted return_to forwarded: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
