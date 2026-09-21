package main

import (
	"net/http"
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
var HandoffOrigins = []string{
	"https://www.cardmarket.com",
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
