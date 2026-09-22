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
		// Where the rows were read, which is what lets the results say
		// "Cardmarket" instead of "pasted text".
		`name="uploadSource"`,
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

// The results heading used to call a handed-over list "pasted text", which
// is what it is by the time it reaches the upload handler and not where it
// came from. These name the difference.
func TestUploadSourceFrom(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		link string
	}{{
		name: "a seller's offers page names the seller",
		raw:  "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles",
		want: "Cardmarket — Lemhast",
		link: "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles",
	}, {
		name: "the seller survives the filters the walk carries",
		raw:  "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles?idLanguages=1&site=4",
		want: "Cardmarket — Lemhast",
		link: "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles?idLanguages=1&site=4",
	}, {
		// Host excludes userinfo, so this passes the origin check. Echoing
		// the URL back would put the credentials into the href on the
		// results page.
		name: "credentials do not ride along into the link",
		raw:  "https://user:pass@www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles",
		want: "Cardmarket — Lemhast",
		link: "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles",
	}, {
		// Somewhere else on the same site is still that site.
		name: "a page naming no seller keeps the site",
		raw:  "https://www.cardmarket.com/en/Magic/Products/Singles/Urzas-Legacy",
		want: "Cardmarket",
		link: "https://www.cardmarket.com/en/Magic/Products/Singles/Urzas-Legacy",
	}, {
		// The whole point of deriving the name here: a host nobody allowed
		// cannot put words in the heading, or in the upload log beside it.
		name: "an origin that was never allowed names nothing",
		raw:  "https://example.test/en/Magic/Users/Nobody/Offers/Singles",
	}, {
		name: "nor does one that only looks like it",
		raw:  "https://www.cardmarket.com.example.test/en/Magic/Users/X/Offers/Singles",
	}, {
		name: "nor the same host over plain http",
		raw:  "http://www.cardmarket.com/en/Magic/Users/X/Offers/Singles",
	}, {
		name: "an empty source is an ordinary paste",
		raw:  "",
	}, {
		name: "and so is something that is not a URL",
		raw:  "://",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, link := uploadSourceFrom(tc.raw)
			if name != tc.want {
				t.Errorf("name = %q, want %q", name, tc.want)
			}
			if link != tc.link {
				t.Errorf("link = %q, want %q", link, tc.link)
			}
		})
	}
}

// An origin allowed to hand rows over but never given a name would show up
// as a list from nowhere, which reads as a bug rather than as the omission
// it is.
func TestEveryHandoffOriginHasAName(t *testing.T) {
	for _, origin := range HandoffOrigins {
		if handoffNames[origin] == "" {
			t.Errorf("%s is allowed to hand over a list but has no name", origin)
		}
	}
}

// The results heading is chosen by which arm of uploadQuery the request
// lands in, and a handed-over list is told from a pasted one by nothing
// else. These pin the order, so a refactor that moves the paste path has
// to move this with it.
func TestUploadQuery(t *testing.T) {
	const offers = "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles"

	tests := []struct {
		name      string
		hashes    []string
		textArea  string
		handed    string
		gdocURL   string
		gdocName  string
		filename  string
		wantQuery string
		wantLink  string
	}{{
		name:      "a handed-over list names where it was read",
		textArea:  "a,b\n1,2\n",
		handed:    offers,
		wantQuery: "Cardmarket \u2014 Lemhast",
		wantLink:  offers,
	}, {
		name:      "a list handed from somewhere unallowed is a paste",
		textArea:  "a,b\n1,2\n",
		handed:    "https://example.test/en/Magic/Users/Nobody/Offers/Singles",
		wantQuery: "pasted text",
	}, {
		name:      "and so is one handed from nowhere",
		textArea:  "a,b\n1,2\n",
		wantQuery: "pasted text",
	}, {
		// The source is only ever consulted on the paste arm. A file
		// upload that happened to carry the field must not pick it up.
		name:      "a file keeps its name however the form was filled",
		handed:    offers,
		filename:  "collection.csv",
		wantQuery: "collection.csv",
	}, {
		name:      "hashes come first",
		hashes:    []string{"abc"},
		textArea:  "a,b\n1,2\n",
		handed:    offers,
		wantQuery: "hashes",
	}, {
		name:      "a paste comes before a remote document",
		textArea:  "a,b\n1,2\n",
		gdocURL:   "https://docs.example/doc",
		wantQuery: "pasted text",
	}, {
		name:      "a named remote document names itself",
		gdocURL:   "https://docs.example/doc",
		gdocName:  "My Binder",
		wantQuery: "My Binder",
		wantLink:  "https://docs.example/doc",
	}, {
		name:      "an unnamed one says what it is",
		gdocURL:   "https://docs.example/doc",
		wantQuery: "remote URL",
		wantLink:  "https://docs.example/doc",
	}, {
		name:      "a file is what is left",
		filename:  "collection.csv",
		wantQuery: "collection.csv",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			query, link := uploadQuery(tc.hashes, tc.textArea, tc.handed, tc.gdocURL, tc.gdocName, tc.filename)
			if query != tc.wantQuery {
				t.Errorf("query = %q, want %q", query, tc.wantQuery)
			}
			if link != tc.wantLink {
				t.Errorf("link = %q, want %q", link, tc.wantLink)
			}
		})
	}
}
