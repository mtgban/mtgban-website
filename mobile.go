package main

import (
	"net/http"
	"slices"

	"github.com/mileusna/useragent"
)

// isMobileRequest returns true if the request comes from a mobile or tablet device.
func isMobileRequest(r *http.Request) bool {
	ua := useragent.Parse(r.UserAgent())
	return ua.Mobile || ua.Tablet
}

// Pages that have mobile templates - only these show in mobile nav.
// Subpages (Sets, Sealed, Archive, etc.) that use the same handler/template are included.
var mobileEnabledPages = []string{
	"Home",
	"Search",
	"Sealed",
	"Newspaper",
	"Sleepers",
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
