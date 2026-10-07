package main

import (
	"net/http"
)

// Privacy renders the public privacy policy. It carries the cookie and
// third-party (Amazon Associates) disclosures required to keep the site
// in good standing with the affiliate programs we participate in.
func (s *site) Privacy(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav(s, r, "Privacy", sig)
	render(w, "privacy.html", pageVars)
}
