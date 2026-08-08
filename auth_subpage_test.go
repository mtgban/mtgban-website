package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/ratelimit"
)

// navWithHiddenSubPage installs a nav whose subpage hides itself, and
// returns a handler whose body carries the marker, so a test can tell
// whether the gated page was rendered.
func navWithHiddenSubPage(t *testing.T, parentLink, subLink, marker string) http.Handler {
	t.Helper()

	savedNavs, savedOrder := ExtraNavs, OrderNav
	savedDev, savedSig := DevMode, SigCheck
	savedLimiter := UserRateLimiter
	t.Cleanup(func() {
		ExtraNavs, OrderNav = savedNavs, savedOrder
		DevMode, SigCheck = savedDev, savedSig
		UserRateLimiter = savedLimiter
	})

	// Unsigned requests all share the one empty-email bucket, so without a
	// limiter of its own a test gets the rate limit notice instead of the page
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, 1)
	DevMode, SigCheck = true, false
	ExtraNavs = map[string]*NavElem{
		"Testing": {
			Name: "Testing",
			Link: parentLink,
			Page: "home.html",
			SubPages: []NavElem{
				{
					Name:       "Hidden",
					Link:       subLink,
					ShouldHide: func() bool { return true },
				},
			},
		},
	}
	OrderNav = []string{"Testing"}

	return enforceSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(marker))
	}))
}

// A hidden subpage answers with the notice and nothing else: rendering it
// and carrying on into the gated handler used to glue both documents into
// one response, serving the very page the subpage was hiding.
func TestEnforceSigningHiddenSubPageStopsAtNotice(t *testing.T) {
	const marker = "PAGE-BODY-MARKER"
	handler := navWithHiddenSubPage(t, "/newspaper", "/newspaper?page=syp", marker)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/newspaper?page=syp", nil))

	body := recorder.Body.String()
	if strings.Contains(body, marker) {
		t.Error("gated handler ran after the notice was rendered")
	}
	if count := strings.Count(body, "</html>"); count != 1 {
		t.Errorf("response holds %d documents, want exactly 1", count)
	}
}

// Hiding a subpage must not hide the page it hangs off. The subpage is
// picked by a query parameter, so matching on the path alone made every
// plain request to the parent look like a request for the subpage.
func TestEnforceSigningHiddenSubPageLeavesParentAlone(t *testing.T) {
	const marker = "PAGE-BODY-MARKER"
	handler := navWithHiddenSubPage(t, "/newspaper", "/newspaper?page=syp", marker)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/newspaper", nil))

	if !strings.Contains(recorder.Body.String(), marker) {
		t.Error("parent page was withheld because one of its subpages is hidden")
	}
}

// A subpage on a path of its own keeps working the same way.
func TestEnforceSigningHiddenSubPageOwnPath(t *testing.T) {
	const marker = "PAGE-BODY-MARKER"
	handler := navWithHiddenSubPage(t, "/search", "/sealed", marker)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/search", nil))

	if !strings.Contains(recorder.Body.String(), marker) {
		t.Error("parent page was withheld because a sibling subpage is hidden")
	}
}
