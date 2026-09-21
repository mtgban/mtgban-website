package main

import (
	"strings"
	"testing"
)

// TestHandoffNamesItsOrigins pins that the page carries the origins the server
// named, in the shape the script reads them from.
//
// That list is the whole of the page's security: anything able to open it can
// talk to it, so the origin is what says whether it is listened to. The script
// itself is held to using it in tests/upload-handoff.test.js.
func TestHandoffNamesItsOrigins(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:        &NavElem{Short: "b"},
		Title:          "Receiving a card list",
		HandoffOrigins: []string{"https://www.cardmarket.com"},
	})

	if !strings.Contains(page, "data-handoff-origins=") {
		t.Fatal("the page carries no origin list")
	}
	if !strings.Contains(page, "https://www.cardmarket.com") {
		t.Error("the allowed origin is not on the page")
	}
	if !strings.Contains(page, "/js/upload-handoff.js") {
		t.Error("the page does not load the script that reads it")
	}
}

// TestHandoffPostsToTheUpload pins that the rows go to the upload handler from
// this page, which is what makes them carry the session: a request made from
// the extension's own origin would arrive without the cookie.
func TestHandoffPostsToTheUpload(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:        &NavElem{Short: "b"},
		HandoffOrigins: HandoffOrigins,
	})

	for _, want := range []string{
		`method="post"`,
		`action="/upload"`,
		`name="textArea"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the form is missing %s", want)
		}
	}
}

// TestHandoffWithNoOriginsTakesNothing pins that an empty list renders as an
// empty list rather than as nothing at all: a page that listens to nobody,
// not one whose attribute is missing and might be read as anything.
func TestHandoffWithNoOriginsTakesNothing(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav: &NavElem{Short: "b"},
	})

	if !strings.Contains(page, `data-handoff-origins="[]"`) {
		t.Error("an empty origin list did not render as an empty array")
	}
}

// TestHandoffOriginsAreHTTPS pins what the list is allowed to hold. An origin
// reached over http could be anyone on the way.
func TestHandoffOriginsAreHTTPS(t *testing.T) {
	if len(HandoffOrigins) == 0 {
		t.Fatal("no origins configured")
	}
	for _, origin := range HandoffOrigins {
		if !strings.HasPrefix(origin, "https://") {
			t.Errorf("origin %q is not https", origin)
		}
		// An origin is a scheme and a host, nothing more: a trailing path
		// would never equal what a message reports and would silently refuse
		// everything.
		if strings.Count(origin, "/") != 2 {
			t.Errorf("origin %q is not a bare scheme and host", origin)
		}
	}
}
