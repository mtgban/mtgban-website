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

	// Where to go back to comes from the query, so a stranger's link chooses
	// it and it is only followed when it names a path on this site.
	//
	// Checked here rather than behind a helper on purpose: the analysis
	// credits a check it can see beside the redirect it guards, and a helper
	// returning a string reads to it as though nothing was checked at all.
	//
	// Three spellings leave the site if only the leading slash is asked
	// about. A browser reads the backslash of "/\evil.test" as the second
	// half of an authority; it strips tabs and newlines before it resolves
	// anything, so "/<tab>/evil.test" arrives as "//evil.test"; and url.Parse
	// settles neither, because Go keeps a backslash in the path where a
	// browser does not.
	asked := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(r.FormValue("redirect"))

	// Default out, and take what was asked for only inside the check - the
	// analysis follows the value itself, not a flag set about it, so the
	// assignment has to sit in the guarded branch to count as guarded.
	redirect := "/"
	if strings.HasPrefix(asked, "/") && !strings.HasPrefix(asked, "//") && !strings.HasPrefix(asked, `/\`) {
		parsed, err := url.Parse(asked)
		if err == nil && parsed.Scheme == "" && parsed.Host == "" && parsed.Opaque == "" {
			redirect = asked
		}
	}
	http.Redirect(w, r, redirect, http.StatusFound)
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
