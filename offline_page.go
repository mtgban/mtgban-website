package main

import "net/http"

// OfflinePage renders the offline search shell stub (phase 4 fills the body).
func OfflinePage(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav("Offline", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	render(w, "offline.html", pageVars)
}
