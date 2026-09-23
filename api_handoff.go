package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mtgban/mtgban-website/apihandoff"
)

// Messages the handoff pages show instead of redirecting.
const (
	ErrMsgAPITrialPledge = "The API trial is for supporters with an active pledge"
	ErrMsgAPIHandoffOff  = "API sign-in from this site is not available right now"
)

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
	secret := os.Getenv("TRIAL_SECRET")

	msg := ""
	nonce := ""
	switch {
	case secret == "":
		msg = ErrMsgAPIHandoffOff
	case email == "":
		msg = ErrMsg
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
		render(w, "api-plans.html", pageVars)
		return
	}

	token := apihandoff.Mint([]byte(secret), apihandoff.Claims{
		Email:   email,
		Name:    GetParamFromSig(sig, "UserName"),
		Purpose: purpose,
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
