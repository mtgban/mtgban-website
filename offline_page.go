package main

import "net/http"

// offlineModeAllowed authenticates the caller and checks the OfflineMode
// ACL flag baked into their signed cookie.
func offlineModeAllowed(r *http.Request) (string, bool) {
	if DevMode && !SigCheck {
		return "dev@localhost", true
	}
	email := signedUserEmail(r)
	if email == "" {
		return "", false
	}
	sig := getSignatureFromCookies(r)
	return email, GetParamFromSig(sig, "OfflineMode") == "true"
}

// OfflinePage renders the offline search shell.
func OfflinePage(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav("Offline", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	render(w, "offline.html", pageVars)
}
