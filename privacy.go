package main

import (
	"net/http"
)

// Privacy renders the public privacy policy. It carries the cookie and
// third-party (Amazon Associates) disclosures required to keep the site
// in good standing with the affiliate programs we participate in.
func Privacy(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav("Privacy", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	render(w, "privacy.html", pageVars)
}
