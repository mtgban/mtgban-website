package main

import (
	"cmp"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
)

// handoffOrigins returns the sites allowed to hand a card list to the upload
// page, each with how its results are headed, from the
// infrastructure file's handoff_origins.
//
// A site opening the page cannot post the list to /upload itself: the upload
// needs the session, this cookie is same-site, and a request made from another
// origin arrives without it. What it can do is open this page - a normal
// top-level navigation, so the session comes along - and pass the rows to it
// window to window. That keeps the shape of the upload form ours to change.
//
// What an origin here is granted is narrow but real: it can cause a card list
// of its choosing to be priced in the session of whoever opened the page, and
// the answer is what they are shown. The rows are submitted as soon as they
// arrive - there is no step where they are looked over first - so an allowed
// origin decides what gets valued, not what it is worth. Nothing beyond that:
// the page does not read the session, does not answer with what it holds, and
// changes nothing that outlasts the request.
//
// An entry that is not a bare https scheme and host is left out: one reached
// over http could be anyone on the way, and one with a path would never equal
// what a message reports.
func handoffOrigins() map[string]infrastructure.HandoffOrigin {
	origins := map[string]infrastructure.HandoffOrigin{}
	for origin, entry := range Infrastructure().HandoffOrigins {
		if validHandoffOrigin(origin) {
			origins[origin] = entry
		}
	}
	return origins
}

// validHandoffOrigin reports whether origin is an https scheme and a host,
// nothing more, spelled the way a browser reports it: lowercase, with no
// default port and no trailing dot.
func validHandoffOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		origin == parsed.Scheme+"://"+parsed.Host && origin == strings.ToLower(origin) &&
		parsed.Port() != "443" && !strings.HasSuffix(parsed.Hostname(), ".")
}

// uploadSourceFrom names the site a handed-over list was read from,
// for the results heading, along with the link back to it.
//
// The name is derived here rather than sent. The heading is rendered and
// the same string is written to the upload log, and a name chosen by
// whoever posted the form would be a name in both. What crosses is a URL,
// and only one whose origin handoffOrigins allows - anything else is a
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
	entry, found := handoffOrigins()[origin]
	if !found {
		return "", ""
	}
	name = cmp.Or(entry.Name, parsed.Host)

	// The seller, where the entry says which segment names one. A list read
	// from somewhere else on the same site is still from that site, so a
	// missing seller loses the name and not the heading.
	parts := strings.Split(parsed.Path, "/")
	for i := 0; entry.Seller != "" && i+1 < len(parts); i++ {
		if parts[i] == entry.Seller && parts[i+1] != "" {
			name += " - " + parts[i+1]
			break
		}
	}

	// Rebuilt rather than echoed back. Host excludes userinfo, so
	// https://user:pass@www.cardmarket.com/... passes the check above and
	// parsed.String() would put those credentials straight into the href on
	// the results page. Nothing that gets this far should carry any - only
	// an allowed origin's URL is accepted, and a sender passes its own
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
func uploadQuery(shared bool, hashes []string, textArea, handedFrom, remoteURL, remoteName, filename string) (query string, link string) {
	switch {
	case shared:
		// Reopened from a share link: the rows say nothing about where
		// they first came from, and the owner is not named.
		return "a shared list", ""
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
	case remoteURL != "":
		// Show the source's own name when the loader could retrieve one,
		// and let the results header link back to it
		if remoteName != "" {
			return remoteName, remoteURL
		}
		return "remote URL", remoteURL
	}
	return filename, ""
}

// UploadHandoff renders the page another site hands a card list to.
//
// It carries no list of its own. The rows arrive after it loads, from the
// window that opened it, and the form is submitted from here - same origin,
// same session, an ordinary upload by the time it reaches the handler.
//
// This one is served without the signing middleware, so it is also the
// page somebody lands on knowing nothing about the site, and it does its
// own asking: a signature this host wrote, carrying the Upload grant, or
// the page says so and declines to receive anything. Refusing here rather
// than at the far end is the difference between reading somebody's whole
// shelf and then being told no, and being told no before the walk starts.
func (s *site) UploadHandoff(w http.ResponseWriter, r *http.Request) {
	// The grant is only worth reading off a signature this host wrote,
	// since the whole of it travels in a cookie the reader holds.
	sig := verifiedSignature(r)
	signed := sig != ""

	pageVars := genPageNav(s, r, "Upload", sig)
	pageVars.Title = "Card list handoff"
	pageVars.HandoffOrigins = slices.Sorted(maps.Keys(handoffOrigins()))

	canUpload, _ := strconv.ParseBool(GetParamFromSig(sig, "Upload"))
	if DevMode && !SigCheck {
		canUpload = true
	}

	// Two ways to arrive without it, and they want different sentences:
	// somebody with no signature at all has not joined, and somebody whose
	// tier does not carry Upload has, and needs to hear which way is up.
	//
	// This line is also the whole of what the page needs to know, so it is
	// all that is passed: a reader who is being told why is a reader whose
	// list is not being taken, and the two cannot disagree if there is
	// only one of them.
	//
	// It is the info line rather than the error one. An ErrorMessage is
	// the whole page in base.html - it renders in place of the content
	// block, not alongside it - and what this page has to say is the part
	// underneath: what it would have done, and the button that gets there.
	if !canUpload {
		pageVars.InfoMessage = ErrMsg
		if signed {
			pageVars.InfoMessage = ErrMsgPlus
		}
	}

	// The middleware used to count this page; it no longer sees it.
	recordPageHit(r)

	// A phone gets the handoff in the mobile layout, though the Upload page
	// it belongs to keeps the desktop one, so it marks the mobile view itself.
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	render(w, "upload_handoff.html", pageVars)
}
