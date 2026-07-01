package main

import (
	"net/http"
	"strings"
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
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	pageVars.PopularSearches = getPopularSearches()

	// The chart "add a card" modal loads the homepage in an iframe with
	// ?modal=1&chart=<roster>. In that mode we render chrome-free and carry the
	// roster forward so a search from here lands back on the results page still
	// in modal context (with the add-to-chart affordance).
	pageVars.ModalMode = r.FormValue("modal") == "1"
	pageVars.ChartIDsCSV = strings.Join(parseChartIDs(r.FormValue("chart")), ",")

	render(w, "home.html", pageVars)
}
