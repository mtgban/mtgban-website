package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/mtgban/mtgban-website/apihandoff"
)

// Messages the handoff pages show instead of redirecting.
const (
	ErrMsgAPITrialPledge      = "The API trial is for supporters with an active pledge"
	ErrMsgAPIHandoffOff       = "API sign-in from this site is not available right now"
	ErrMsgAPIEmailUnconfirmed = "Confirm your email with Patreon, then log in again to continue"
)

// apiGatewayUser is the api_user_secrets entry the gateway calls this site
// with. The same secret signs the handoff tokens the gateway verifies, so a
// deployment that lets the gateway in already has everything the handoff
// needs.
const apiGatewayUser = "gateway@mtgban.com"

// apiGatewaySecret is the shared secret for this site, empty when the
// gateway is not configured, which turns the handoffs off.
func apiGatewaySecret() string {
	return Config.APIUserSecrets[apiGatewayUser]
}

// APITrial hands a pledged supporter to the gateway to start a trial.
func APITrial(w http.ResponseWriter, r *http.Request) {
	apiHandoff(w, r, apihandoff.PurposeTrial, "/trial")
}

// APILogin signs a Patreon user into the gateway.
func APILogin(w http.ResponseWriter, r *http.Request) {
	apiHandoff(w, r, apihandoff.PurposeLogin, "/session")
}

// apiHandoff mints the token for the signed-in reader and redirects to path on the gateway.
func apiHandoff(w http.ResponseWriter, r *http.Request, purpose, path string) {
	sig := verifiedSignature(r)
	email := GetParamFromSig(sig, "UserEmail")
	secret := apiGatewaySecret()

	msg := ""
	login := false
	nonce := ""
	switch {
	case secret == "":
		msg = ErrMsgAPIHandoffOff
	case email == "":
		msg = ErrMsg
		login = true
	// The gateway signs in whoever the email names, so Patreon must have
	// confirmed it.
	case GetParamFromSig(sig, "UserEmailUnverified") == "true":
		msg = ErrMsgAPIEmailUnconfirmed
		login = true
	case purpose == apihandoff.PurposeTrial && GetParamFromSig(sig, "UserTier") == "":
		msg = ErrMsgAPITrialPledge
	default:
		var err error
		nonce, err = apihandoff.NewNonce()
		if err != nil {
			log.Println("apihandoff: NewNonce:", err)
			msg = ErrMsgAPIHandoffOff
		}
	}
	if msg != "" {
		pageVars := genPageNav(r, "API", sig)
		pageVars.IsMobile = isMobileRequest(r)
		if pageVars.IsMobile {
			pageVars.Nav = filterNavForMobile(pageVars.Nav)
		}
		pageVars.ErrorMessage = msg
		if login {
			// The home page carries the Patreon button, which comes back here.
			pageVars.PatreonLogin = pageVars.PatreonURL != ""
			render(w, "home.html", pageVars)
			return
		}
		render(w, "api-plans.html", pageVars)
		return
	}

	token := apihandoff.Mint([]byte(secret), apihandoff.Claims{
		Email:   email,
		Name:    GetParamFromSig(sig, "UserName"),
		Purpose: purpose,
		Game:    Config.Game,
		Nonce:   nonce,
		Expires: time.Now().Add(apihandoff.TTL),
	})
	q := url.Values{"t": {token}}
	// Only a site of ours is forwarded; the gateway falls back to the pricing page otherwise.
	if rt := r.FormValue("return_to"); trustedReturnTo(rt) {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, Config.APIGateway.URL+path+"?"+q.Encode(), http.StatusFound)
}

// trustedReturnTo is true for an absolute http(s) URL on one of our hosts.
func trustedReturnTo(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return trustedHostname(u.Host)
}
