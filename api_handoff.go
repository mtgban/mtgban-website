package main

import (
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
	sig := getSignatureFromCookies(r)
	email := GetParamFromSig(sig, "UserEmail")
	secret := os.Getenv("TRIAL_SECRET")

	msg := ""
	switch {
	case secret == "":
		msg = ErrMsgAPIHandoffOff
	case email == "":
		msg = ErrMsg
	case purpose == apihandoff.PurposeTrial && GetParamFromSig(sig, "UserTier") == "":
		msg = ErrMsgAPITrialPledge
	}
	if msg != "" {
		pageVars := genPageNav(r, "API", sig)
		pageVars.Title = "BAN API"
		pageVars.ErrorMessage = msg
		render(w, "api-plans.html", pageVars)
		return
	}

	token := apihandoff.Mint([]byte(secret), apihandoff.Claims{
		Email:   email,
		Name:    GetParamFromSig(sig, "UserName"),
		Purpose: purpose,
		Expires: time.Now().Add(apihandoff.TTL),
	})
	q := url.Values{"t": {token}}
	if rt := r.FormValue("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, Config.APIGateway.URL+path+"?"+q.Encode(), http.StatusFound)
}
