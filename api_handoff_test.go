package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/patreon"
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
// checked as production does them, and returns what the handoff logs.
func handoffSetup(t *testing.T) *strings.Builder {
	t.Helper()
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	var logged strings.Builder
	LogPages["Admin"] = log.New(&logged, "", 0)
	savedGateway, savedPatreon := Config().APIGateway, Config().Patreon
	t.Cleanup(func() { Config().APIGateway, Config().Patreon = savedGateway, savedPatreon })
	Config().APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []mtgmatcher.Game{"magic"}}
	Config().Patreon.Source = "main"
	Config().Patreon.Client = map[string]string{"main": "client-id"}
	return &logged
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
func handoffFinish(t *testing.T, state handoffState, nonce string, user *pledge.User, tier string, tierErr error) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth?code=x", nil)
	if nonce != "" {
		req.AddCookie(&http.Cookie{Name: handoffCookie, Value: nonce})
	}
	rec := httptest.NewRecorder()
	testSite.finishAPIHandoff(rec, req, state, user, tier, tierErr)
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

var ann = &pledge.User{Email: "ann@example.com", FullName: "Ann Example", EmailVerified: true}

// A handoff starts at Patreon whatever the site cookie says, signed in or
// not: it asks for the scopes the tier needs, and keeps a nonce in a cookie
// the callback can read on its way back from patreon.com.
func TestAPIHandoffStartsAtPatreon(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	mallory := sign("Legacy", &pledge.User{Email: "mallory@example.com", FullName: "Mallory", EmailVerified: true}, nil, DefaultSignatureDuration)

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
		_, gw := gatewayToken(t, handoffFinish(t, state, nonce.Value, ann, "Legacy", nil), "/session")
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
		rec := handoffFinish(t, handoffState{purpose: purpose, nonce: "n1"}, "n1", ann, "Legacy", nil)
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
	logged := handoffSetup(t)
	for name, tc := range map[string]struct {
		state   handoffState
		cookie  string
		outcome string
	}{
		"no cookie":       {handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "", "no nonce cookie"},
		"another nonce":   {handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n2", "nonce mismatch"},
		"no nonce":        {handoffState{purpose: apihandoff.PurposeLogin}, "", "no nonce cookie"},
		"unknown purpose": {handoffState{purpose: "admin", nonce: "n1"}, "n1", "unknown purpose"},
	} {
		logged.Reset()
		rec := handoffFinish(t, tc.state, tc.cookie, ann, "Legacy", nil)
		if rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), html.EscapeString(ErrMsgAPIHandoffStale)) {
			t.Errorf("%s: status %d, location %q", name, rec.Code, rec.Header().Get("Location"))
		}
		if !strings.HasSuffix(logged.String(), "outcome="+tc.outcome+"\n") {
			t.Errorf("%s: logged %q, want outcome %q", name, logged.String(), tc.outcome)
		}
	}
}

// The gateway signs in whoever the email names, so Patreon must have confirmed
// it, and both handoffs are for supporters, as the site login is.
func TestAPIHandoffRefusals(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	logged := handoffSetup(t)
	unconfirmed := &pledge.User{Email: "ann@example.com", FullName: "Ann"}
	for name, tc := range map[string]struct {
		purpose string
		user    *pledge.User
		tier    string
		tierErr error
		want    string
		outcome string
	}{
		"unconfirmed email":    {apihandoff.PurposeLogin, unconfirmed, "Legacy", nil, ErrMsgAPIEmailUnconfirmed, `email="ann@example.com" tier="Legacy" outcome=unverified email`},
		"no email":             {apihandoff.PurposeLogin, &pledge.User{EmailVerified: true}, "Legacy", nil, ErrMsgAPIHandoffNoEmail, "outcome=no email"},
		"a trial, no tier":     {apihandoff.PurposeTrial, ann, "", nil, ErrMsgAPITrialPledge, `purpose=trial email="ann@example.com" tier="" outcome=no tier`},
		"a login, no tier":     {apihandoff.PurposeLogin, ann, "", nil, ErrMsgAPILoginPledge, `purpose=login email="ann@example.com" tier="" outcome=no tier`},
		"a login":              {apihandoff.PurposeLogin, ann, "Legacy", nil, "", `purpose=login email="ann@example.com" tier="Legacy" outcome=ok`},
		"Patreon gave no tier": {apihandoff.PurposeLogin, ann, "", context.DeadlineExceeded, ErrMsgAPITierNoAnswer, `purpose=login email="ann@example.com" tier="" outcome=tier lookup failed`},
	} {
		logged.Reset()
		rec := handoffFinish(t, handoffState{purpose: tc.purpose, nonce: "n1"}, "n1", tc.user, tc.tier, tc.tierErr)
		if tc.want != "" && (rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), html.EscapeString(tc.want))) {
			t.Errorf("%s: status %d, want the message %q", name, rec.Code, tc.want)
		}
		if strings.Count(logged.String(), "handoff: ") != 1 || !strings.Contains(logged.String(), tc.outcome+"\n") {
			t.Errorf("%s: logged %q, want one line ending %q", name, logged.String(), tc.outcome)
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
	rec = handoffFinish(t, handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n1", ann, "Legacy", nil)
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
	logged := handoffSetup(t)
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
	for name, tc := range map[string]struct{ query, outcome string }{
		"turned down at Patreon": {url.Values{"error": {"access_denied"}, "state": {state}}.Encode(), "no code from Patreon"},
		"a code not exchanged":   {url.Values{"code": {"x"}, "state": {state}}.Encode(), "token exchange failed"},
	} {
		logged.Reset()
		rec := callback(tc.query)
		if !strings.Contains(logged.String(), `handoff: purpose=login email="" tier="" outcome=`+tc.outcome+"\n") {
			t.Errorf("%s: logged %q, want outcome %q", name, logged.String(), tc.outcome)
		}
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

// handoffCallback brings state back to /auth with the handoff cookie set to
// cookie: through to the finish with Ann named, or turned down at Patreon.
func handoffCallback(t *testing.T, state handoffState, cookie string, finish bool) *httptest.ResponseRecorder {
	t.Helper()
	if finish {
		return handoffFinish(t, state, cookie, ann, "Legacy", nil)
	}
	encoded := handoffStatePrefix + url.Values{"p": {state.purpose}, "n": {state.nonce}}.Encode()
	req := httptest.NewRequest(http.MethodGet, "/auth?"+url.Values{"error": {"access_denied"}, "state": {encoded}}.Encode(), nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: handoffCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	testSite.Auth(rec, req)
	return rec
}

// Of two tabs whose handoffs started together, the later one finishes in
// whichever order the callbacks come back, whether the earlier one fails at
// Patreon or reaches the finish: only a callback holding the cookie's nonce
// spends it.
func TestAPIHandoffTheLaterTabFinishesInEitherOrder(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	earlier := handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}
	later := handoffState{purpose: apihandoff.PurposeLogin, nonce: "n2"}

	for _, earlierFinishes := range []bool{false, true} {
		for _, laterFirst := range []bool{false, true} {
			order := []handoffState{earlier, later}
			if laterFirst {
				order = []handoffState{later, earlier}
			}
			// The browser holds the later start's nonce
			jar := later.nonce
			finished := map[string]bool{}
			for _, tab := range order {
				rec := handoffCallback(t, tab, jar, tab == later || earlierFinishes)
				finished[tab.nonce] = rec.Code == http.StatusFound
				for _, c := range rec.Result().Cookies() {
					if c.Name == handoffCookie && c.MaxAge < 0 {
						jar = ""
					}
				}
			}
			if !finished[later.nonce] || finished[earlier.nonce] {
				t.Errorf("earlier finishes %v, later first %v: finished %v, want only the later tab", earlierFinishes, laterFirst, finished)
			}
		}
	}
}

// patreonAnswer is a transport Patreon answers every request through, with a
// 200 and itself as the body.
type patreonAnswer string

func (a patreonAnswer) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(a))), Request: req}, nil
}

// Nothing a caller sends, nor anything Patreon answers, can write a line of
// its own into the admin log: a purpose the site never sends is logged as
// unknown, and Patreon's fields are quoted, from the identity lookup on.
func TestAPIHandoffLogsOneLineWhateverItIsSent(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	logged := handoffSetup(t)
	forged := "\nhandoff: purpose=login email=x tier=Vintage outcome=ok"
	state := handoffStatePrefix + url.Values{"p": {apihandoff.PurposeLogin + forged}, "n": {"n1"}}.Encode()
	identity := patreonAnswer(`{"data":{"attributes":{"email":"ann@example.com\nx","full_name":"Ann\nhandoff: purpose=login email=x tier=Vintage outcome=ok","is_email_verified":true}}}`)
	_, err := Pledge.UserIDs(context.Background(), &patreon.Client{Client: &http.Client{Transport: identity}})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth?"+url.Values{"state": {state}}.Encode(), nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	testSite.Auth(httptest.NewRecorder(), req)
	handoffFinish(t, handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n1", &pledge.User{Email: "ann@example.com" + forged, EmailVerified: true}, "Legacy", nil)

	lines := strings.Split(strings.TrimSuffix(logged.String(), "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "handoff: purpose=unknown ") {
		t.Errorf("logged %q, want three lines, the second for an unknown purpose", lines)
	}
}

// patreonStatus is a transport Patreon refuses every request through, with
// itself as the status.
type patreonStatus int

func (code patreonStatus) RoundTrip(req *http.Request) (*http.Response, error) {
	body := io.NopCloser(strings.NewReader(`{"errors":[{"code_name":"refused"}]}`))
	return &http.Response{StatusCode: int(code), Body: body, Request: req}, nil
}

// A tier lookup whose token Patreon refused, or that Patreon failed, ends the
// handoff saying Patreon did not answer; only one for no such member tells
// the reader they do not pledge.
func TestAPIHandoffTellsARefusedTierLookupFromNoPledge(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	ctx := context.Background()
	for code, want := range map[int]string{
		http.StatusUnauthorized: ErrMsgAPITierNoAnswer,
		http.StatusForbidden:    ErrMsgAPITierNoAnswer,
		http.StatusBadGateway:   ErrMsgAPITierNoAnswer,
		http.StatusNotFound:     ErrMsgAPILoginPledge,
	} {
		client := &patreon.Client{Client: &http.Client{Transport: patreonStatus(code)}}
		_, err := Pledge.UserTier(ctx, client, "m1")
		var tierErr error
		if pledge.DidNotAnswer(ctx, err) {
			tierErr = err
		}
		rec := handoffFinish(t, handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "n1", ann, "", tierErr)
		if !strings.Contains(rec.Body.String(), html.EscapeString(want)) {
			t.Errorf("%d: status %d, want the message %q", code, rec.Code, want)
		}
	}
}

// Only a tier lookup Patreon never answered is told apart from a reader who
// pledges nothing, who is told so.
func TestPatreonDidNotAnswer(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()
	unreachable := fmt.Errorf("cannot decode membership data: %w", &url.Error{Op: "Get", URL: patreon.PatreonMemberURL, Err: context.DeadlineExceeded})
	for name, tc := range map[string]struct {
		ctx  context.Context
		err  error
		want bool
	}{
		"an answer":         {context.Background(), nil, false},
		"no tier":           {context.Background(), errors.New("empty tier title"), false},
		"an error answered": {context.Background(), errors.New(`user data error: ["not found"]`), false},
		"no answer":         {context.Background(), unreachable, true},
		"out of time":       {expired, errors.New("unexpected EOF"), true},
		"an edge's 502":     {context.Background(), fmt.Errorf("cannot decode membership data: %w", &patreon.StatusError{StatusCode: http.StatusBadGateway}), true},
		"no such member":    {context.Background(), fmt.Errorf("cannot decode membership data: %w", &patreon.StatusError{StatusCode: http.StatusNotFound}), false},
		"a refused token":   {context.Background(), fmt.Errorf("cannot decode membership data: %w", &patreon.StatusError{StatusCode: http.StatusForbidden}), true},
		"cut short":         {context.Background(), fmt.Errorf("cannot decode membership data: %w", fmt.Errorf("%w: unexpected EOF", patreon.ErrUnreadable)), true},
		"answered in time":  {expired, nil, false},
	} {
		got := pledge.DidNotAnswer(tc.ctx, tc.err)
		if got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
