package main

import (
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apihandoff"
)

// setGatewaySecret installs the shared secret the handoff signs with; empty turns the handoff off.
func setGatewaySecret(t *testing.T, secret string) {
	t.Helper()
	saved, savedGame := Config().APIUserSecrets, Config().Game
	t.Cleanup(func() { Config().APIUserSecrets, Config().Game = saved, savedGame })
	Config().Game = "magic"
	Config().APIUserSecrets = map[string]string{}
	if secret != "" {
		Config().APIUserSecrets[apiGatewayUser] = secret
	}
}

// handoffSetup configures the gateway and a Patreon client, with signatures
// checked as production does them.
func handoffSetup(t *testing.T) {
	t.Helper()
	signingEnabled(t, true)
	savedGateway, savedPatreon := Config().APIGateway, Config().Patreon
	t.Cleanup(func() { Config().APIGateway, Config().Patreon = savedGateway, savedPatreon })
	Config().APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []mtgmatcher.Game{"magic"}}
	Config().Patreon.Source = "main"
	Config().Patreon.Client = map[string]string{"main": "client-id"}
}

// handoffStart asks handler for path on mtgban.com, as a reader whose site
// cookie is cookie (none when empty).
func handoffStart(t *testing.T, handler http.HandlerFunc, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// patreonRedirect reads where a started handoff sends the reader, and the
// nonce cookie it set.
func patreonRedirect(t *testing.T, rec *httptest.ResponseRecorder) (*url.URL, *http.Cookie) {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Scheme+"://"+loc.Host+loc.Path != patreonAuthorizeURL {
		t.Fatalf("status %d location %q, want Patreon's authorize page", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == handoffCookie {
			return loc, c
		}
	}
	t.Fatal("no handoff cookie set")
	return nil, nil
}

// handoffFinish runs the callback's handoff half for the reader Patreon named,
// with nonce in this browser's cookie (none when empty).
func handoffFinish(t *testing.T, state handoffState, nonce string, user *PatreonUserData, tier string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth?code=x", nil)
	if nonce != "" {
		req.AddCookie(&http.Cookie{Name: handoffCookie, Value: nonce})
	}
	rec := httptest.NewRecorder()
	testSite.finishAPIHandoff(rec, req, state, user, tier)
	return rec
}

// gatewayToken reads the token a finished handoff carries to path, "" for
// none.
func gatewayToken(t *testing.T, rec *httptest.ResponseRecorder, path string) (apihandoff.Claims, *url.URL) {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.String() == "" || !strings.HasPrefix(loc.String(), "https://api.example"+path+"?") {
		t.Fatalf("status %d location %q, want the gateway's %s", rec.Code, rec.Header().Get("Location"), path)
	}
	claims, err := apihandoff.Verify([]byte("handoff-secret"), loc.Query().Get("t"), time.Now())
	if err != nil {
		t.Fatalf("the token does not verify: %v", err)
	}
	return claims, loc
}

var ann = &PatreonUserData{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}

// A handoff starts at Patreon whatever the site cookie says, signed in or
// not: it asks for the scopes the tier needs, and keeps a nonce in a cookie
// the callback can read on its way back from patreon.com.
func TestAPIHandoffStartsAtPatreon(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	mallory := sign("Legacy", &PatreonUserData{Email: "mallory@example.com", FullName: "Mallory", EmailVerified: true}, nil, DefaultSignatureDuration)

	for _, tc := range []struct {
		handler http.HandlerFunc
		path    string
		purpose string
	}{
		{testSite.APILogin, "/api-login", apihandoff.PurposeLogin},
		{testSite.APITrial, "/api-trial", apihandoff.PurposeTrial},
		{testSite.APIPlans, "/api-login", apihandoff.PurposeLogin},
		{testSite.APIPlans, "/api-trial", apihandoff.PurposeTrial},
	} {
		for _, cookie := range []string{"", mallory} {
			loc, nonce := patreonRedirect(t, handoffStart(t, tc.handler, tc.path+"?sig="+url.QueryEscape(mallory), cookie))
			q := loc.Query()
			if q.Get("client_id") != "client-id" || q.Get("redirect_uri") != "https://mtgban.com/auth" || !strings.Contains(q.Get("scope"), "campaigns.members") {
				t.Errorf("%s: authorize query %v", tc.path, q)
			}
			state, isHandoff := parseHandoffState(q.Get("state"))
			if !isHandoff || state.purpose != tc.purpose || state.nonce == "" || state.nonce != nonce.Value {
				t.Errorf("%s: state %+v, cookie %q", tc.path, state, nonce.Value)
			}
			if !nonce.HttpOnly || !nonce.Secure || nonce.SameSite != http.SameSiteLaxMode || nonce.Path != "/auth" || nonce.MaxAge <= 0 {
				t.Errorf("%s: nonce cookie %+v", tc.path, nonce)
			}
		}
	}

	_, again := patreonRedirect(t, handoffStart(t, testSite.APILogin, "/api-login", ""))
	_, first := patreonRedirect(t, handoffStart(t, testSite.APILogin, "/api-login", ""))
	if again.Value == first.Value {
		t.Error("two handoffs shared a nonce")
	}
}

// return_to rides the state to the gateway when it names a site of ours.
func TestAPIHandoffCarriesOnlyOurReturnTo(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	for target, want := range map[string]string{
		"https://pokemon.mtgban.com/api-plans": "https://pokemon.mtgban.com/api-plans",
		"https://evil.example/steal":           "",
	} {
		loc, nonce := patreonRedirect(t, handoffStart(t, testSite.APILogin, "/api-login?return_to="+url.QueryEscape(target), ""))
		state, _ := parseHandoffState(loc.Query().Get("state"))
		if state.returnTo != want {
			t.Errorf("return_to %s: state carries %q, want %q", target, state.returnTo, want)
		}
		state.returnTo = target
		_, gw := gatewayToken(t, handoffFinish(t, state, nonce.Value, ann, "Legacy"), "/session")
		if got := gw.Query().Get("return_to"); got != want {
			t.Errorf("return_to %s: the gateway gets %q, want %q", target, got, want)
		}
	}
}

// The token names the reader Patreon answered for, with the purpose asked.
func TestAPIHandoffFinishesWithPatreonsReader(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	for purpose, path := range map[string]string{apihandoff.PurposeLogin: "/session", apihandoff.PurposeTrial: "/trial"} {
		rec := handoffFinish(t, handoffState{purpose: purpose, nonce: "n1"}, "n1", ann, "Legacy")
		claims, _ := gatewayToken(t, rec, path)
		if claims.Email != "ann@example.com" || claims.Name != "Ann Example" || claims.Purpose != purpose || claims.Game != "magic" {
			t.Errorf("%s: claims %+v", purpose, claims)
		}
		spent := false
		for _, c := range rec.Result().Cookies() {
			spent = spent || (c.Name == handoffCookie && c.MaxAge < 0)
		}
		if !spent {
			t.Errorf("%s: the nonce cookie was not cleared", purpose)
		}
	}
}

// A callback finishes only a handoff this browser started: a code from
// somebody else's Patreon account, sent to this browser in a link, finds no
// nonce to match and hands over nobody.
func TestAPIHandoffFinishesOnlyWhatThisBrowserStarted(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	for name, tc := range map[string]struct {
		state  handoffState
		cookie string
	}{
		"no cookie":       {handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, ""},
		"another nonce":   {handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n2"},
		"no nonce":        {handoffState{purpose: apihandoff.PurposeLogin}, ""},
		"unknown purpose": {handoffState{purpose: "admin", nonce: "n1"}, "n1"},
	} {
		rec := handoffFinish(t, tc.state, tc.cookie, ann, "Legacy")
		if rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), html.EscapeString(ErrMsgAPIHandoffStale)) {
			t.Errorf("%s: status %d, location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// The gateway signs in whoever the email names, so Patreon must have confirmed
// it, and both handoffs are for supporters, as the site login is.
func TestAPIHandoffRefusals(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	unconfirmed := &PatreonUserData{Email: "ann@example.com", FullName: "Ann"}
	for name, tc := range map[string]struct {
		purpose string
		user    *PatreonUserData
		tier    string
		want    string
	}{
		"unconfirmed email": {apihandoff.PurposeLogin, unconfirmed, "Legacy", ErrMsgAPIEmailUnconfirmed},
		"no email":          {apihandoff.PurposeLogin, &PatreonUserData{EmailVerified: true}, "Legacy", ErrMsgAPIHandoffStale},
		"a trial, no tier":  {apihandoff.PurposeTrial, ann, "", ErrMsgAPITrialPledge},
		"a login, no tier":  {apihandoff.PurposeLogin, ann, "", ErrMsgAPILoginPledge},
	} {
		rec := handoffFinish(t, handoffState{purpose: tc.purpose, nonce: "n1"}, "n1", tc.user, tc.tier)
		if rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), html.EscapeString(tc.want)) {
			t.Errorf("%s: status %d, want the message %q", name, rec.Code, tc.want)
		}
	}
}

func TestAPIHandoffDisabledWithoutSecret(t *testing.T) {
	setGatewaySecret(t, "")
	handoffSetup(t)
	rec := handoffStart(t, testSite.APILogin, "/api-login", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPIHandoffOff) {
		t.Errorf("start: status %d, body lacks the disabled message", rec.Code)
	}
	rec = handoffFinish(t, handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n1", ann, "Legacy")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ErrMsgAPIHandoffOff) {
		t.Errorf("finish: status %d, body lacks the disabled message", rec.Code)
	}
}

// A site login's state is the page to come back to, and stays a login.
func TestParseHandoffState(t *testing.T) {
	for _, state := range []string{"", "/search?q=x;main", ";main", "handoffs"} {
		if _, isHandoff := parseHandoffState(state); isHandoff {
			t.Errorf("%q read as a handoff", state)
		}
	}
	got, isHandoff := parseHandoffState(handoffStatePrefix + url.Values{"p": {"trial"}, "n": {"abc"}, "r": {"https://mtgban.com/x"}}.Encode())
	if !isHandoff || got != (handoffState{purpose: "trial", nonce: "abc", returnTo: "https://mtgban.com/x"}) {
		t.Errorf("parsed %+v", got)
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
				if sub.ShouldHide == nil || !sub.ShouldHide(testSite) {
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

// A handoff Patreon gave no reader for - turned down there, or a code that
// could not be exchanged - ends on the API page with the nonce cleared, as
// one that fails later does. A site login keeps going home.
func TestAPIHandoffFailingAtPatreonEndsOnTheAPIPage(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Admin"] == nil {
		LogPages["Admin"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Admin") })
	}
	state := handoffStatePrefix + url.Values{"p": {apihandoff.PurposeLogin}, "n": {"n1"}}.Encode()

	callback := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth?"+query, nil)
		req.Host = "mtgban.com"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.AddCookie(&http.Cookie{Name: handoffCookie, Value: "n1"})
		rec := httptest.NewRecorder()
		testSite.Auth(rec, req)
		return rec
	}
	// No secret configured, so the token exchange fails without a request.
	for name, query := range map[string]string{
		"turned down at Patreon": url.Values{"error": {"access_denied"}, "state": {state}}.Encode(),
		"a code not exchanged":   url.Values{"code": {"x"}, "state": {state}}.Encode(),
	} {
		rec := callback(query)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), html.EscapeString(ErrMsgAPIHandoffNoAnswer)) {
			t.Errorf("%s: status %d location %q, want the API page's message", name, rec.Code, rec.Header().Get("Location"))
		}
		cleared := false
		for _, c := range rec.Result().Cookies() {
			cleared = cleared || (c.Name == handoffCookie && c.MaxAge < 0)
		}
		if !cleared {
			t.Errorf("%s: the nonce cookie was left behind", name)
		}
	}

	if rec := callback("state=" + url.QueryEscape("/search;main")); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("a site login with no code: status %d location %q, want home", rec.Code, rec.Header().Get("Location"))
	}
}
