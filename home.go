package main

import (
	"net/http"
)

// Handler for / renders the home.html page
func Home(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Home", r)
	pageVars.ErrorMessage = ""

	// Try auto-login only if not already logged in
	if !pageVars.IsLoggedIn {
		authCookie, authErr := r.Cookie("auth_token")
		refreshCookie, refreshErr := r.Cookie("refresh_token")

		if authErr == nil && authCookie.Value != "" &&
			refreshErr == nil && refreshCookie.Value != "" {
			newSession, authErr := authService.refreshAuthTokens(r, w, refreshCookie.Value, authCookie.Value)
			if authErr == nil && newSession != nil {
				authService.logWithContext(r, "user %s logged in automatically", maskEmail(newSession.User.Email))
				pageVars.InfoMessage = "You've been logged in successfully."
				pageVars.IsLoggedIn = true
				pageVars.UserEmail = newSession.User.Email
				pageVars.UserTier = getTierFromUser(&newSession.User)
				pageVars.ShowLogin = false
			} else {
				authService.logWithContext(r, "auto-login failed, clearing cookies: %v", authErr)
				authService.clearAuthCookies(w, r)
				pageVars.IsLoggedIn = false
				pageVars.ShowLogin = true
			}
		}
	}

	//render template
	render(w, "home.html", pageVars)
}
