package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/docparse"
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

// The list is fetched a page at a time on the far side and then uploaded
// here, so there are seconds where a still page is the only thing anybody
// can see. The spinner is what says the page is still working, and it is
// markup rather than something the script builds, so it is on screen from
// the moment the line is shown.
func TestHandoffSpinsWhileItWaits(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:        &NavElem{Short: "b"},
		HandoffOrigins: HandoffOrigins,
	})

	if !strings.Contains(page, `class="handoff-spinner"`) {
		t.Error("the progress line carries no spinner")
	}
	// Hidden to begin with: a page opened by hand shows the guide, and a
	// spinner over it would be turning for something that is not coming.
	if !strings.Contains(page, `id="handoff-status" class="handoff-status" hidden`) {
		t.Error("the progress line does not start hidden")
	}
	// The words live in their own element because the spinner shares the
	// line: writing to the line itself would take the spinner with it.
	if !strings.Contains(page, `id="handoff-status-text"`) {
		t.Error("the progress line has nowhere to write the words")
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

// TestHandoffTakesNothingItCannotPrice pins what a reader without the
// Upload grant is shown, and what is not on the page for them.
//
// The form is the part that matters. Gathering a list is minutes of
// somebody's afternoon on the storefronts this is built for, and a page
// that took one only to have /upload refuse it at the far end would spend
// all of that before saying no.
func TestHandoffTakesNothingItCannotPrice(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:        &NavElem{Short: "b"},
		HandoffOrigins: HandoffOrigins,
		InfoMessage:    ErrMsg,
	})

	for _, gone := range []string{`name="textArea"`, `action="/upload"`, `id="handoff-status"`} {
		if strings.Contains(page, gone) {
			t.Errorf("a reader who cannot upload was still given %s", gone)
		}
	}
	if !strings.Contains(page, ErrMsg) {
		t.Error("the page does not say why it is not taking the list")
	}
	// The script reads this to decide whether to announce itself at all,
	// which is what keeps an extension from handing rows to a page that
	// cannot do anything with them.
	if !strings.Contains(page, `data-can-upload="false"`) {
		t.Error("the page does not tell its own script to stay quiet")
	}
}

// The invitation is the point of serving this page signed out at all: it is
// where somebody arrives who has only ever seen the extension.
func TestHandoffInvitesAReaderWithNoSignature(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:      &NavElem{Short: "b"},
		InfoMessage:  ErrMsg,
		PatreonLogin: true,
		PatreonIDs:   map[string]string{"patreon": "12345"},
		PatreonURL:   "https://mtgban.com/auth",
	})

	for _, want := range []string{"getPatreonURL", "12345", "Log in"} {
		if !strings.Contains(page, want) {
			t.Errorf("the invitation is missing %s", want)
		}
	}
}

// A reader who is signed in and whose tier simply does not reach this far
// is not asked to log in again.
func TestHandoffDoesNotAskASignedInReaderToLogIn(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:      &NavElem{Short: "b"},
		InfoMessage:  ErrMsgPlus,
		PatreonLogin: false,
	})

	if strings.Contains(page, "Log in") {
		t.Error("a signed-in reader was offered a login button")
	}
	if !strings.Contains(page, ErrMsgPlus) {
		t.Error("the page does not say the tier is what is missing")
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

// The page is served without the signing middleware in front of it, so
// these are the checks. A grant travels in a cookie the reader holds, and
// the only thing separating "my tier includes this" from "I typed it into
// my own cookie" is whether this host signed it.
func TestHandoffHandlerAsksBeforeItReceives(t *testing.T) {
	signingEnabled(t, true)

	page := func(t *testing.T, sig string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/upload/handoff", nil)
		if sig != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		}
		rec := httptest.NewRecorder()
		UploadHandoff(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		return rec.Body.String()
	}

	granted := signedAs(t, url.Values{"Upload": {"true"}, "UserTier": {"Pro"}}, time.Now().Add(time.Hour))

	t.Run("a tier that carries Upload", func(t *testing.T) {
		body := page(t, granted)
		if !strings.Contains(body, `data-can-upload="true"`) {
			t.Error("a granted reader was not allowed to receive a list")
		}
		if !strings.Contains(body, `name="textArea"`) {
			t.Error("the form the rows are posted with is missing")
		}
	})

	t.Run("a tier that does not", func(t *testing.T) {
		body := page(t, signedAs(t, url.Values{"UserTier": {"Free"}}, time.Now().Add(time.Hour)))
		if strings.Contains(body, `name="textArea"`) {
			t.Error("a reader without the grant was given the form anyway")
		}
		if !strings.Contains(body, ErrMsgPlus) {
			t.Error("a signed-in reader was not told it is the tier that is missing")
		}
	})

	t.Run("nobody at all", func(t *testing.T) {
		body := page(t, "")
		if strings.Contains(body, `name="textArea"`) {
			t.Error("a reader with no signature was given the form")
		}
		if !strings.Contains(body, ErrMsg) {
			t.Error("a reader with no signature was not invited in")
		}
	})

	t.Run("the grant written in by hand", func(t *testing.T) {
		// The whole reason the HMAC is checked here rather than the grant
		// being read straight off the cookie.
		raw, _ := base64.StdEncoding.DecodeString(granted)
		v, _ := url.ParseQuery(string(raw))
		v.Set("UserTier", "Free")
		forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		body := page(t, forged)
		if strings.Contains(body, `data-can-upload="true"`) {
			t.Error("a rewritten signature was believed")
		}
		if strings.Contains(body, `name="textArea"`) {
			t.Error("a rewritten signature was given the form")
		}
	})
}

// TestHandoffDocumentsItself pins that the page says what reaches it and in
// what shape, for both readers who see it: somebody who opened the URL
// themselves, and somebody being turned away.
//
// This page is the only documentation of the handoff there is. The column
// vocabulary it prints is internal/docparse's, so the risk is the two
// drifting - a spelling documented here that the parser stopped reading
// is worse than none at all.
func TestHandoffDocumentsItself(t *testing.T) {
	// Both readers: the one who was handed nothing, and the one being
	// turned away. The message is what tells them apart.
	for _, told := range []string{"", ErrMsg} {
		page := renderPage(t, "upload_handoff.html", false, PageVars{
			BetaNav:        &NavElem{Short: "b"},
			HandoffOrigins: HandoffOrigins,
			InfoMessage:    told,
		})

		if !strings.Contains(page, `id="handoff-guide"`) {
			t.Fatalf("InfoMessage=%q: the page carries no guide", told)
		}
		// Where a list may come from is a fact about this deployment, so it
		// is printed rather than described.
		for _, origin := range HandoffOrigins {
			if !strings.Contains(page, origin) {
				t.Errorf("InfoMessage=%q: the guide does not name %s", told, origin)
			}
		}
		// One spelling per field docparse's ParseHeader actually matches.
		for _, column := range []string{
			"card", "edition", "variant", "foil", "condition", "quantity",
			"price", "notes", "uuid", "tcgplayer id", "cardmarket",
		} {
			if !strings.Contains(page, column) {
				t.Errorf("InfoMessage=%q: the guide does not mention %q", told, column)
			}
		}
		// And the limits, read off the handler's own constants.
		if !strings.Contains(page, fmt.Sprint(MaxUploadEntries)) {
			t.Errorf("InfoMessage=%q: the guide does not say how many rows fit", told)
		}
	}
}

// Every header spelling the guide prints is one docparse still reads.
//
// The spellings are taken off the rendered page rather than listed here,
// because a list here would be a third copy: the parser has its own, the
// guide prints its own, and only the page is what somebody follows. Each
// one is then handed to the parser, which answers for itself - it is a
// switch of substring tests, and reading it by eye is how a documented
// column comes to be one nothing matches.
func TestHandoffGuideNamesColumnsTheParserReads(t *testing.T) {
	page := renderPage(t, "upload_handoff.html", false, PageVars{
		BetaNav:        &NavElem{Short: "b"},
		HandoffOrigins: HandoffOrigins,
	})

	tables := regexp.MustCompile(`(?s)<table class="handoff-cols">(.*?)</table>`).FindAllStringSubmatch(page, -1)
	if len(tables) == 0 {
		t.Fatal("the guide prints no column table")
	}

	spelt := regexp.MustCompile(`<code>([^<]+)</code>`)
	var parser docparse.Parser
	var checked int

	for _, table := range tables {
		for _, found := range spelt.FindAllStringSubmatch(table[1], -1) {
			spelling := found[1]
			checked++

			// Paired with a card name, since a lone column is read as a
			// decklist and a header anchored on nothing is handed back to
			// be re-read as data.
			indexMap, err := parser.ParseHeader([]string{spelling, "card name"})
			if err != nil {
				t.Errorf("%q: ParseHeader refused it: %v", spelling, err)
				continue
			}
			var reached bool
			for _, at := range indexMap {
				if at == 0 {
					reached = true
					break
				}
			}
			if !reached {
				t.Errorf("%q is printed on the handoff page and reaches no field", spelling)
			}
		}
	}

	if checked < 20 {
		t.Errorf("only %d spellings were checked; the tables are probably not being read", checked)
	}
}

// The progress line starts hidden and is revealed by the script, which
// works only while nothing in our own stylesheet has given it a display.
//
// [hidden] is a display:none in the browser's stylesheet, and any author
// rule beats that - so `.handoff-status { display: flex }` alone puts the
// line and its spinner above the guide on every page nobody handed
// anything to. Neither suite can see it: the Go side reads the attribute
// out of the markup and the bun stubs set `hidden` as a property, so this
// asks the stylesheet instead.
func TestHiddenStillHidesTheProgressLine(t *testing.T) {
	sheet, err := os.ReadFile("css/handoff.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}

	block := regexp.MustCompile(`(?s)\.handoff-status \{(.*?)\}`).FindStringSubmatch(string(sheet))
	if block == nil {
		t.Skip("the progress line has no rule of its own")
	}
	if !strings.Contains(block[1], "display:") {
		return
	}
	if !strings.Contains(string(sheet), ".handoff-status[hidden]") {
		t.Error(".handoff-status sets a display and nothing puts [hidden] back")
	}
}
