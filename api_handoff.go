package main

import (
	"crypto/hmac"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/apihandoff"
)

// Messages the handoff pages show instead of redirecting.
const (
	ErrMsgAPITrialPledge      = "The API trial is for supporters with an active pledge"
	ErrMsgAPILoginPledge      = "API sign-in from this site is for supporters with an active pledge"
	ErrMsgAPIHandoffOff       = "API sign-in from this site is not available right now"
	ErrMsgAPIEmailUnconfirmed = "Confirm your email with Patreon, then try again"
	ErrMsgAPIHandoffStale     = "That sign-in link has expired: start again from this page"
	ErrMsgAPIHandoffNoAnswer  = "Patreon did not confirm who you are: start again from this page"
	ErrMsgAPIHandoffNoEmail   = "Patreon did not share an email address for your account: add one there, then try again"
	ErrMsgAPITierNoAnswer     = "Patreon did not say which tier you pledge to: start again from this page"
)

// apiGatewayUser is the api_user_secrets entry the gateway calls this site
// with. The same secret signs the handoff tokens the gateway verifies, so a
// deployment that lets the gateway in already has everything the handoff
// needs.
const apiGatewayUser = "gateway@mtgban.com"

// apiGatewaySecret is the shared secret for this site, empty when the
// gateway is not configured, which turns the handoffs off.
func apiGatewaySecret() string {
	return Config().APIUserSecrets[apiGatewayUser]
}

// APITrial hands a pledged supporter to the gateway to start a trial.
func (s *site) APITrial(w http.ResponseWriter, r *http.Request) {
	s.apiHandoff(w, r, apihandoff.PurposeTrial)
}

// APILogin signs a Patreon user into the gateway.
func (s *site) APILogin(w http.ResponseWriter, r *http.Request) {
	s.apiHandoff(w, r, apihandoff.PurposeLogin)
}

// handoffCookie holds the nonce a handoff's OAuth state carries, so the
// callback finishes only a handoff this browser started: without it, a code
// from somebody else's Patreon account would sign this reader in as them.
const handoffCookie = "MTGBAN_HANDOFF"

// handoffWindow is how long a reader has on Patreon's pages to approve.
const handoffWindow = 10 * time.Minute

// handoffStatePrefix marks the OAuth state of a handoff, which Auth finishes
// in finishAPIHandoff rather than as a site login.
const handoffStatePrefix = "handoff:"

// patreonAuthorizeURL is where both the site login and a handoff ask Patreon.
const patreonAuthorizeURL = "https://www.patreon.com/oauth2/authorize"

// apiHandoff sends the reader to Patreon to say who they are; the gateway
// token is minted from Patreon's answer in finishAPIHandoff, never from the
// site's cookie, which travels in links and scripts can read.
func (s *site) apiHandoff(w http.ResponseWriter, r *http.Request, purpose string) {
	origin := requestOrigin(r)
	patreonConfig := Infrastructure().Patreon
	clientID := patreonConfig.Client[patreonConfig.Source]
	nonce := ""
	var err error
	if apiGatewaySecret() != "" && origin != "" && clientID != "" {
		nonce, err = apihandoff.NewNonce()
		if err != nil {
			log.Println("apihandoff: NewNonce:", err)
		}
	}
	if nonce == "" {
		s.renderAPIHandoffError(w, r, ErrMsgAPIHandoffOff)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     handoffCookie,
		Value:    nonce,
		Path:     "/auth",
		MaxAge:   int(handoffWindow.Seconds()),
		HttpOnly: true,
		// Always: the handoff runs over HTTPS, and Chrome and Firefox keep
		// a Secure cookie on http://localhost too
		Secure: true,
		// Lax, so the cookie rides the redirect back from patreon.com
		SameSite: http.SameSiteLaxMode,
	})
	state := url.Values{"p": {purpose}, "n": {nonce}}
	if rt := r.FormValue("return_to"); trustedReturnTo(rt) {
		state.Set("r", rt)
	}
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {origin + "/auth"},
		"scope":         {"identity identity[email] campaigns campaigns.members"},
		"state":         {handoffStatePrefix + state.Encode()},
	}
	http.Redirect(w, r, patreonAuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

// handoffState is what a handoff's OAuth state carries back: the purpose,
// the nonce its cookie holds, and where the gateway returns the reader.
type handoffState struct {
	purpose, nonce, returnTo string
}

// parseHandoffState reads a handoff's OAuth state; false for a site login's.
func parseHandoffState(state string) (handoffState, bool) {
	raw, isHandoff := strings.CutPrefix(state, handoffStatePrefix)
	if !isHandoff {
		return handoffState{}, false
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return handoffState{}, true
	}
	return handoffState{purpose: v.Get("p"), nonce: v.Get("n"), returnTo: v.Get("r")}, true
}

// handoffPaths is where each purpose goes on the gateway.
var handoffPaths = map[string]string{
	apihandoff.PurposeLogin: "/session",
	apihandoff.PurposeTrial: "/trial",
}

// finishAPIHandoff mints the gateway token for the reader Patreon just named,
// with the tier the site would give them, once the nonce shows this browser
// started the handoff. tierErr is why Patreon gave no answer for the tier.
func (s *site) finishAPIHandoff(w http.ResponseWriter, r *http.Request, state handoffState, user *PatreonUserData, tier string, tierErr error) {
	// One use: whatever happens next, this handoff is spent
	spendHandoffCookie(w, r, state)

	secret := apiGatewaySecret()
	path, known := handoffPaths[state.purpose]
	cookie := readCookie(r, handoffCookie)
	email := ""
	if user != nil {
		email = user.Email
	}
	msg, outcome := "", "ok"
	nonce := ""
	switch {
	case secret == "":
		msg, outcome = ErrMsgAPIHandoffOff, "no gateway secret"
	case !known:
		msg, outcome = ErrMsgAPIHandoffStale, "unknown purpose"
	// Gone after handoffWindow; a second tab's handoff replaces the first's
	case cookie == "":
		msg, outcome = ErrMsgAPIHandoffStale, "no nonce cookie"
	case !hmac.Equal([]byte(cookie), []byte(state.nonce)):
		msg, outcome = ErrMsgAPIHandoffStale, "nonce mismatch"
	case email == "":
		msg, outcome = ErrMsgAPIHandoffNoEmail, "no email"
	// The gateway signs in whoever the email names, so Patreon must have
	// confirmed it.
	case !user.EmailVerified:
		msg, outcome = ErrMsgAPIEmailUnconfirmed, "unverified email"
	case tierErr != nil:
		msg, outcome = ErrMsgAPITierNoAnswer, "tier lookup failed"
	case tier == "" && state.purpose == apihandoff.PurposeTrial:
		msg, outcome = ErrMsgAPITrialPledge, "no tier"
	case tier == "":
		msg, outcome = ErrMsgAPILoginPledge, "no tier"
	default:
		var err error
		nonce, err = apihandoff.NewNonce()
		if err != nil {
			log.Println("apihandoff: NewNonce:", err)
			msg, outcome = ErrMsgAPIHandoffOff, "no token nonce"
		}
	}
	logHandoff(state, email, tier, outcome)
	if msg != "" {
		s.renderAPIHandoffError(w, r, msg)
		return
	}

	token := apihandoff.Mint([]byte(secret), apihandoff.Claims{
		Email:   user.Email,
		Name:    user.FullName,
		Purpose: state.purpose,
		Game:    string(Config().Game),
		Nonce:   nonce,
		Expires: time.Now().Add(apihandoff.TTL),
	})
	q := url.Values{"t": {token}}
	// Only a site of ours is forwarded; the gateway falls back to the pricing page otherwise.
	if trustedReturnTo(state.returnTo) {
		q.Set("return_to", state.returnTo)
	}
	http.Redirect(w, r, Config().APIGateway.URL+path+"?"+q.Encode(), http.StatusFound)
}

// failAPIHandoff ends a handoff Patreon gave no reader for: the reader turned
// it down, or the code could not be exchanged or read, which outcome says.
func (s *site) failAPIHandoff(w http.ResponseWriter, r *http.Request, state handoffState, outcome string) {
	spendHandoffCookie(w, r, state)
	logHandoff(state, "", "", outcome)
	s.renderAPIHandoffError(w, r, ErrMsgAPIHandoffNoAnswer)
}

// logHandoff records how a handoff ended, as the site login records its own.
// The purpose comes back in the request and the email from Patreon, so the
// one is logged only when this site sends it and the other quoted.
func logHandoff(state handoffState, email, tier, outcome string) {
	purpose := state.purpose
	_, known := handoffPaths[purpose]
	if !known {
		purpose = "unknown"
	}
	LogPages["Admin"].Printf("handoff: purpose=%s email=%q tier=%q outcome=%s", purpose, email, tier, outcome)
}

// spendHandoffCookie drops the nonce when state carries it, so a handoff is
// finished at most once; an older tab's callback leaves the newer tab's.
func spendHandoffCookie(w http.ResponseWriter, r *http.Request, state handoffState) {
	cookie := readCookie(r, handoffCookie)
	if cookie != "" && hmac.Equal([]byte(cookie), []byte(state.nonce)) {
		clearHandoffCookie(w)
	}
}

// clearHandoffCookie drops the nonce, so a handoff is finished at most once.
func clearHandoffCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: handoffCookie, Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// renderAPIHandoffError shows the API page with why the handoff stopped.
func (s *site) renderAPIHandoffError(w http.ResponseWriter, r *http.Request, msg string) {
	pageVars := genPageNav(s, r, "API", verifiedSignature(r))
	pageVars.ErrorMessage = msg
	render(w, "api-plans.html", pageVars)
}

// trustedReturnTo is true for an absolute http(s) URL on one of our hosts.
func trustedReturnTo(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return trustedHostname(u.Host)
}
