package main

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/mileusna/useragent"
)

// isMobileRequest checks if the request should use mobile templates.
// Priority: cookie override > User-Agent detection (phones only, not tablets).
func isMobileRequest(r *http.Request) bool {
	// Check for explicit user override via cookie
	if c, err := r.Cookie("MobileView"); err == nil {
		return c.Value == "true"
	}
	// Default: phones only, tablets get desktop
	ua := useragent.Parse(r.UserAgent())
	return ua.Mobile
}

// toggleMobileView handles requests to switch between mobile and desktop views.
// GET /toggle-mobile?redirect=/current-page
func toggleMobileView(w http.ResponseWriter, r *http.Request) {
	current := false
	if c, err := r.Cookie("MobileView"); err == nil {
		current = c.Value == "true"
	} else {
		// No cookie yet — user is on auto-detect, so they're toggling away from current
		ua := useragent.Parse(r.UserAgent())
		current = ua.Mobile
	}

	// Flip the value
	val := "true"
	if current {
		val = "false"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "MobileView",
		Value:    val,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 365, // 1 year
		HttpOnly: false,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	redirect := r.FormValue("redirect")
	if !isLocalRedirect(redirect) {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// isLocalRedirect reports whether target is a path on this site, so that a
// redirect parameter cannot send a visitor elsewhere.
//
// The leading slash is not enough on its own. "//evil.com" is
// protocol-relative, and "/\evil.com" is the same thing to a browser, which
// reads the backslash as a slash - that second one is what the old prefix
// test let through. Anything naming a scheme or a host is refused outright.
func isLocalRedirect(target string) bool {
	if !strings.HasPrefix(target, "/") {
		return false
	}
	if len(target) > 1 && (target[1] == '/' || target[1] == '\\') {
		return false
	}
	u, err := url.Parse(target)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// Pages that have mobile templates - only these show in mobile nav.
// Subpages (Sets, Sealed, Archive, etc.) that use the same handler/template are included.
var mobileEnabledPages = []string{
	"Home",
	"Search",
	"Sets",
	"Sealed",
	"Newspaper",
	"Sleepers",
	"Admin",
	"Guide",
}

// filterNavForMobile removes nav entries that don't have mobile templates.
func filterNavForMobile(nav []NavElem) []NavElem {
	var filtered []NavElem
	for _, n := range nav {
		if slices.Contains(mobileEnabledPages, n.Name) {
			filtered = append(filtered, n)
		}
	}
	return filtered
}
