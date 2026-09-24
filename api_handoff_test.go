package main

import (
	"encoding/base64"
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

// handoffRequest runs handler with signatures checked, as production does,
// for a reader signed in on tier as user. An invite link is a tier with no
// user, and a reader with neither is signed out.
func handoffRequest(t *testing.T, handler http.HandlerFunc, path, tier string, user *PatreonUserData) *httptest.ResponseRecorder {
	t.Helper()
	signingEnabled(t, true)
	savedCfg := Config.APIGateway
	t.Cleanup(func() { Config.APIGateway = savedCfg })
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic"}}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tier != "" || user != nil {
		// Signed after the mode is set, so it carries the link the check expects.
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sign(tier, user, nil, DefaultSignatureDuration)})
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestAPITrialRedirectsWithVerifiableToken(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}
	rec := handoffRequest(t, APITrial, "/api-trial?return_to=https://pokemon.mtgban.com/api-plans", "Legacy", user)
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

// Auth signs no login without a pledge, so the signature is built by hand
// to reach the check: a trial needs one, a sign-in does not.
func TestAPITrialNeedsAPledge(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	signingEnabled(t, true)
	savedCfg := Config.APIGateway
	t.Cleanup(func() { Config.APIGateway = savedCfg })
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic"}}
	sig := signedAs(t, url.Values{"UserEmail": {"ann@example.com"}, "UserName": {"Ann"}}, time.Now().Add(time.Hour))

	trial := httptest.NewRequest(http.MethodGet, "/api-trial", nil)
	trial.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	rec := httptest.NewRecorder()
	APITrial(rec, trial)
	if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), ErrMsgAPITrialPledge) {
		t.Errorf("trial without a pledge: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}

	login := httptest.NewRequest(http.MethodGet, "/api-login", nil)
	login.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	rec = httptest.NewRecorder()
	APILogin(rec, login)
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/session?t=") {
		t.Errorf("sign-in without a pledge: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAPILoginRedirectsWithVerifiableToken(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob", EmailVerified: true}
	rec := handoffRequest(t, APILogin, "/api-login", "Legacy", user)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/session?t=") {
		t.Errorf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	claims, err := apihandoff.Verify([]byte("trial-secret"), loc.Query().Get("t"), time.Now())
	if err != nil || claims.Purpose != apihandoff.PurposeLogin {
		t.Errorf("claims %+v err %v", claims, err)
	}
}

// The gateway signs in whoever the token's email names, so an email Patreon
// has not confirmed is one anybody could have typed.
func TestAPIHandoffNeedsAConfirmedEmail(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "victim@example.com", FullName: "Mallory"}
	for _, handler := range []http.HandlerFunc{APILogin, APITrial} {
		rec := handoffRequest(t, handler, "/api-login", "Legacy", user)
		if rec.Header().Get("Location") != "" {
			t.Fatal("minted a handoff token for an unconfirmed Patreon email")
		}
		if !strings.Contains(rec.Body.String(), ErrMsgAPIEmailUnconfirmed) {
			t.Error("the refusal does not say to confirm the email")
		}
	}
}

// Readers with no email to hand over: signed out, or holding an invite link,
// which carries a tier and nobody's identity.
func TestAPIHandoffNeedsAPatreonLogin(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	for name, tier := range map[string]string{"signed out": "", "invite link": "Legacy"} {
		rec := handoffRequest(t, APILogin, "/api-login", tier, nil)
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s: minted a handoff token with no email", name)
		}
		if !strings.Contains(rec.Body.String(), ErrMsg) {
			t.Errorf("%s: the refusal does not say why", name)
		}
	}
}

// Whoever is refused for want of a login is offered one, and the Patreon round
// trip comes back to the handoff: its state is the page the button is on.
func TestAPIHandoffRefusalOffersALogin(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	signingEnabled(t, true)
	savedPatreon := Config.Patreon
	t.Cleanup(func() { Config.Patreon = savedPatreon })
	Config.Patreon = PatreonConfig{Client: map[string]string{"ban": "client-id"}}

	rec := httptest.NewRecorder()
	APILogin(rec, httptest.NewRequest(http.MethodGet, "https://www.mtgban.com/api-login", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "patreon.com/oauth2/authorize") || !strings.Contains(body, "client-id") {
		t.Error("the refusal offers no Patreon login")
	}
	if !strings.Contains(body, "window.location.pathname + window.location.search") {
		t.Error("the login does not come back to the page it was offered on")
	}
}

func TestAPIHandoffDisabledWithoutSecret(t *testing.T) {
	setGatewaySecret(t, "")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann", EmailVerified: true}
	rec := handoffRequest(t, APILogin, "/api-login", "Legacy", user)
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
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob", EmailVerified: true}
	rec := handoffRequest(t, APIPlans, "/api-login", "Legacy", user)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/session?t=") {
		t.Errorf("login via the API page: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = handoffRequest(t, APIPlans, "/api-trial", "Legacy", user)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://api.example/trial?t=") {
		t.Errorf("trial via the API page: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAPIHandoffIgnoresATamperedSignature(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "ann@example.com", FullName: "Ann", EmailVerified: true}
	signingEnabled(t, true)
	savedCfg := Config.APIGateway
	t.Cleanup(func() { Config.APIGateway = savedCfg })
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

	// Deleting the unconfirmed flag is an edit like any other.
	flagged := sign("Legacy", &PatreonUserData{Email: "victim@example.com", FullName: "Mallory"}, nil, DefaultSignatureDuration)
	v := parseSig(flagged)
	v.Del("UserEmailUnverified")
	_, flaggedOK := signatureIsValid(flagged)
	_, strippedOK := signatureIsValid(base64.StdEncoding.EncodeToString([]byte(v.Encode())))
	if !flaggedOK || strippedOK {
		t.Errorf("flagged signature verifies: %v, with the flag deleted: %v", flaggedOK, strippedOK)
	}
}

func TestAPIHandoffDropsUntrustedReturnTo(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	user := &PatreonUserData{Email: "bob@example.com", FullName: "Bob", EmailVerified: true}
	rec := handoffRequest(t, APILogin, "/api-login?return_to=https://evil.example/steal", "Legacy", user)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Has("return_to") {
		t.Errorf("untrusted return_to forwarded: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// A ?sig= on the link is whoever made the link, not the reader who
// followed it, so it must never be the one signed in.
func TestAPIHandoffIgnoresASigOnTheLink(t *testing.T) {
	setGatewaySecret(t, "trial-secret")
	signingEnabled(t, true)
	other := sign("Legacy", &PatreonUserData{Email: "mallory@example.com", FullName: "Mallory", EmailVerified: true}, nil, DefaultSignatureDuration)
	path := "/api-login?sig=" + url.QueryEscape(other)

	ann := &PatreonUserData{Email: "ann@example.com", FullName: "Ann", EmailVerified: true}
	rec := handoffRequest(t, APILogin, path, "Legacy", ann)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	claims, err := apihandoff.Verify([]byte("trial-secret"), loc.Query().Get("t"), time.Now())
	if err != nil || claims.Email != "ann@example.com" {
		t.Errorf("signed-in reader handed over as %q (err %v)", claims.Email, err)
	}

	rec = handoffRequest(t, APILogin, path, "", nil)
	if rec.Header().Get("Location") != "" {
		t.Errorf("reader with no login handed over: %q", rec.Header().Get("Location"))
	}
}
