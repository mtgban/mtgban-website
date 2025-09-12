package main

import (
	"net/http"
	"time"
)

// Handler for / renders the home.html page
func Home(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	errmsg := r.FormValue("errmsg")
	message := ""

	switch errmsg {
	case "TokenNotFound":
		message = "There was a problem authenticating you with Patreon."
	case "UserNotFound", "TierNotFound":
		message = ErrMsg
	case "logout":
		// Invalidate the current cookie
		setCookie(w, "MTGBAN", "", time.Now(), true)

		http.Redirect(w, r, ServerURL, http.StatusFound)
		return
	}

	pageVars := genPageNav("Home", sig)
	pageVars.ErrorMessage = message

	render(w, "home.html", pageVars)
}
