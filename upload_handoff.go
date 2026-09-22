package main

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// HandoffOrigins are the sites allowed to hand a card list to the upload
// page. A browser extension reading a storefront cannot post the list here
// itself: the upload needs the session, this cookie is same-site, and a
// request made from another origin arrives without it. What it can do is open
// this page - a normal top-level navigation, so the session comes along - and
// pass the rows to it window to window.
//
// This page is what receives them. It exists so an extension does not have to
// drive the upload form itself, reaching into a picker and pressing a button
// that were built for a person: the shape of that form is ours to change, and
// anything outside this repository copying it would break the next time it
// did.
//
// What an origin here is granted is narrow but real: it can cause a card list
// of its choosing to be priced in the session of whoever opened the page, and
// the answer is what they are shown. The rows are submitted as soon as they
// arrive - there is no step where they are looked over first - so an allowed
// origin decides what gets valued, not what it is worth.
//
// Nothing beyond that. The page does not read the session, does not answer
// with what it holds, changes nothing that outlasts the request, and cannot be
// reached at all by someone signed out.
// The bare cardmarket.com is deliberately not here. It redirects to the
// www host before a page loads, so a content script never runs on it and
// no message ever arrives from it - and this list is what an origin is
// granted the above by. Widening it for a host that only ever redirects
// away would be surface bought for nothing.
var HandoffOrigins = []string{
	"https://www.cardmarket.com",
}

// What to call each of those in the results heading. Keyed the same way
// HandoffOrigins is, so an origin added to one and forgotten in the other
// shows up as a list from nowhere rather than as a wrong name.
var handoffNames = map[string]string{
	"https://www.cardmarket.com": "Cardmarket",
}

// uploadSourceFrom names the storefront a handed-over list was read from,
// for the results heading, along with the link back to it.
//
// The name is derived here rather than sent. The heading is rendered and
// the same string is written to the upload log, and a name chosen by
// whoever posted the form would be a name in both. What crosses is a URL,
// and only one whose origin is on the list above - anything else is a
// posted list like any other and says so.
func uploadSourceFrom(raw string) (name string, link string) {
	if raw == "" {
		return "", ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}

	origin := parsed.Scheme + "://" + parsed.Host
	if !slices.Contains(HandoffOrigins, origin) {
		return "", ""
	}
	name = handoffNames[origin]
	if name == "" {
		return "", ""
	}

	// The seller, where the path names one: Cardmarket files an offers page
	// under /<language>/<Game>/Users/<seller>/Offers/... A list read from
	// somewhere else on the same site is still from that site, so a missing
	// seller loses the name and not the heading.
	parts := strings.Split(parsed.Path, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "Users" && parts[i+1] != "" {
			name += " \u2014 " + parts[i+1]
			break
		}
	}

	// Rebuilt rather than echoed back. Host excludes userinfo, so
	// https://user:pass@www.cardmarket.com/... passes the check above and
	// parsed.String() would put those credentials straight into the href on
	// the results page. Nothing that gets this far should carry any - only
	// an allowed origin's URL is accepted, and the extension sends
	// location.href - but the heading is not the place to find out.
	clean := url.URL{
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawPath:  parsed.RawPath,
		RawQuery: parsed.RawQuery,
		Fragment: parsed.Fragment,
	}

	return name, clean.String()
}

// uploadQuery names the list in the results heading, and the page to link
// it back to where there is one.
//
// The order is the order the handler takes its input in: an argument
// search beats a paste, a paste beats a remote document, and a file is
// what is left. It lives here rather than inline so that the choice of
// branch is something a test can hold - a handed-over list is only told
// from a pasted one by which of these arms it lands in.
func uploadQuery(hashes []string, textArea, handedFrom, gdocURL, gdocName, filename string) (query string, link string) {
	switch {
	case len(hashes) != 0:
		return "hashes", ""
	case textArea != "":
		// A paste is all a handed-over list looks like by the time it
		// reaches the upload, so it says where it was read from when it
		// can say anything at all.
		if name, source := uploadSourceFrom(handedFrom); name != "" {
			return name, source
		}
		return "pasted text", ""
	case gdocURL != "":
		// Show the source's own name when the loader could retrieve one,
		// and let the results header link back to it
		if gdocName != "" {
			return gdocName, gdocURL
		}
		return "remote URL", gdocURL
	}
	return filename, ""
}

// UploadHandoff renders the page an extension hands a card list to.
//
// It carries no list of its own. The rows arrive after it loads, from the
// window that opened it, and the form is submitted from here - same origin,
// same session, an ordinary upload by the time it reaches the handler.
func UploadHandoff(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	pageVars := genPageNav(r, "Upload", sig)
	pageVars.Title = "Receiving a card list"
	pageVars.HandoffOrigins = HandoffOrigins

	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	render(w, "upload_handoff.html", pageVars)
}
