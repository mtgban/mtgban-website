package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Handler for / renders the home.html page
func (s *site) Home(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	sig := verifiedSignature(r)
	errmsg := r.FormValue("errmsg")
	message := ""

	switch errmsg {
	case "TokenNotFound":
		message = "There was a problem authenticating you with Patreon."
	case "UserNotFound", "TierNotFound":
		message = ErrMsg
	case "logout":
		// Drop the renewal session this browser holds. With the database
		// down the cookie goes anyway and the row waits for the prune.
		sessionID := readCookie(r, sessionCookie)
		if sessionID != "" && UserStateDB != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			err := UserStateDB.DeletePatreonSession(ctx, sessionID)
			cancel()
			if err != nil {
				LogPages["Admin"].Println("DeletePatreonSession", err)
			}
		}
		clearSessionCookie(w, r)

		// Invalidate the current cookie
		clearSignatureCookie(w, r, signatureCookie)
		clearSignatureCookie(w, r, legacySignatureCookie)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pageVars := genPageNav(s, r, "Home", sig)
	pageVars.ErrorMessage = message

	pageVars.PopularSearches = getPopularSearches(ds)

	// The chart "add a card" modal loads the homepage in an iframe with
	// ?modal=1&chart=<roster>. In that mode we render chrome-free and carry the
	// roster forward so a search from here lands back on the results page still
	// in modal context (with the add-to-chart affordance).
	pageVars.ModalMode = r.FormValue("modal") == "1"
	chartIDs, _ := parseChartIDs(ds.backend, r.FormValue("chart"))
	pageVars.ChartIDsCSV = strings.Join(chartIDs, ",")

	render(w, "home.html", pageVars)
}
