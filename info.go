package main

import (
	"net/http"
)

// Handler for /info renders the info.html page with tier/feature comparison
func Info(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav("Info", sig)

	render(w, "info.html", pageVars)
}
