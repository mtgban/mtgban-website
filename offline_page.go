package main

import "net/http"

// offlineModeAllowed authenticates the caller and checks the SearchOfflineMode
// ACL flag, both off the one signature it checked.
func offlineModeAllowed(r *http.Request) (string, bool) {
	if DevMode && !SigCheck {
		return "dev@localhost", true
	}
	sig := verifiedRequestSignature(r)
	email := GetParamFromSig(sig, "UserEmail")
	if email == "" {
		return "", false
	}
	return email, GetParamFromSig(sig, "SearchOfflineMode") == "true"
}

// OfflinePage renders the offline search shell.
func (s *site) OfflinePage(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav(s, r, "Offline", sig)
	pageVars.SettingsTab = "offline"
	render(w, "offline.html", pageVars)
}
