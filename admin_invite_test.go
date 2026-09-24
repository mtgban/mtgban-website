package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// inviteSig runs the admin tool and hands back the signature it minted, read
// out of the link the redirect carries - which is the whole of what the tool
// produces.
func inviteSig(t *testing.T, query string) url.Values {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/admin?reboot=invite&"+query, nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	Admin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("the tool answered %d, want a redirect carrying the link", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	link, err := url.Parse(location.Query().Get("msg"))
	if err != nil {
		t.Fatalf("parsing the minted link: %v", err)
	}
	sig := link.Query().Get("sig")
	if sig == "" {
		t.Fatal("the link carries no signature")
	}
	v := parseSig(sig)
	if v == nil {
		t.Fatal("the signature does not decode")
	}
	return v
}

// expiresIn is how long the link has left, rounded to the day it was cut for.
func expiresIn(t *testing.T, v url.Values) time.Duration {
	t.Helper()

	seconds, err := strconv.ParseInt(v.Get("Expires"), 10, 64)
	if err != nil {
		t.Fatalf("Expires = %q, which the verifier cannot parse either: %v", v.Get("Expires"), err)
	}
	return time.Until(time.Unix(seconds, 0))
}

// The point of the dropdown: the link is good for as long as it was cut for.
func TestInviteLinkExpiresWhenAsked(t *testing.T) {
	for _, days := range []int{1, 7, 15, 30, 60} {
		got := expiresIn(t, inviteSig(t, "tier=Pioneer&duration="+strconv.Itoa(days)))
		want := time.Duration(days) * 24 * time.Hour

		// Minted a moment ago, so the remaining time is the full span bar the
		// test's own runtime.
		if got > want || want-got > time.Minute {
			t.Errorf("a %d-day link has %v left, want about %v", days, got, want)
		}
	}
}

// A request that names no duration is the shape this tool had before it could
// be asked for one, and it still mints what a login would get.
func TestInviteLinkWithoutADurationKeepsTheLoginLength(t *testing.T) {
	got := expiresIn(t, inviteSig(t, "tier=Pioneer"))
	if got > DefaultSignatureDuration || DefaultSignatureDuration-got > time.Minute {
		t.Errorf("a link with no duration asked for has %v left, want about %v",
			got, DefaultSignatureDuration)
	}
}

// Nothing the field can say may mint a link that is already dead: an expiry at
// or before now reads to the verifier exactly like an expired signature, so a
// zero, a negative or a word falls back to the default rather than handing
// over something that cannot be used.
func TestInviteLinkIsNeverBornExpired(t *testing.T) {
	for _, duration := range []string{"0", "-3", "later", "", "106752"} {
		got := expiresIn(t, inviteSig(t, "tier=Pioneer&duration="+url.QueryEscape(duration)))
		if got <= 0 {
			t.Errorf("duration=%q minted a link that expired %v ago", duration, -got)
		}
	}
}

// The select stops at two months, and so does a hand-written URL.
func TestInviteLinkLastsTwoMonthsAtMost(t *testing.T) {
	got := expiresIn(t, inviteSig(t, "tier=Pioneer&duration=36500"))
	if got > 60*24*time.Hour {
		t.Errorf("a 100-year link has %v left, want two months at most", got)
	}
}

// The link is only worth handing out if the site will take it, which is the
// one thing reading Expires out of the blob does not prove.
func TestInviteLinkIsOneTheSiteAccepts(t *testing.T) {
	signingEnabled(t, false)

	req := httptest.NewRequest(http.MethodGet, "/admin?reboot=invite&tier=Pioneer&duration=7", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	Admin(rec, req)

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	link, err := url.Parse(location.Query().Get("msg"))
	if err != nil {
		t.Fatalf("parsing the minted link: %v", err)
	}

	if _, ok := signatureIsValid(link.Query().Get("sig")); !ok {
		t.Error("the site refused a link the admin tool had just minted")
	}
}

// What the tool offers, on both the desktop and the mobile admin: a tier, a
// length, and no way to ask for one without the other.
func TestAdminOffersAnInviteLinkWithAnExpiry(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "admin.html", mobile, PageVars{
			BetaNav: &NavElem{Short: "b"},
			Tiers:   []string{"Pioneer", "Modern"},
		})

		if !strings.Contains(out, "Create Invite Link") {
			t.Errorf("mobile=%v: the tool is not offered", mobile)
		}
		if !strings.Contains(out, `name="reboot" value="invite"`) {
			t.Errorf("mobile=%v: the form asks for something else", mobile)
		}
		if !strings.Contains(out, `name="duration"`) {
			t.Errorf("mobile=%v: the tool takes no expiry", mobile)
		}
		if strings.Contains(out, "Spoof") {
			t.Errorf("mobile=%v: the tool is still named after what it used to be", mobile)
		}

		// Two months on both this tool's dropdown and the API key's.
		if got := strings.Count(out, `<option value="60">Two months</option>`); got != 2 {
			t.Errorf("mobile=%v: Two months appears in %d dropdowns, want both", mobile, got)
		}
	}
}

// Every admin action runs off the query string, so a crafted link could cut
// an invite, grant a tier or rewrite the ACL in an admin's session. Only a
// request the admin page made runs anything; one from another site, from an
// app such as Discord (none), or from a sibling mtgban.com site lands on the
// bare page having done nothing.
func TestAdminRunsNothingItDidNotAskFor(t *testing.T) {
	for _, tc := range []struct {
		method, fetchSite, referer string
		runs                       bool
	}{
		{http.MethodGet, "cross-site", "", false},
		{http.MethodPost, "cross-site", "", false},
		{http.MethodGet, "none", "", false},
		{http.MethodGet, "same-site", "https://beta.mtgban.com/", false},
		{http.MethodGet, "", "", false},
		{http.MethodGet, "", "https://evil.example/admin", false},
		// A browser too old to say, on the admin page's own link.
		{http.MethodGet, "", "http://example.com/admin", true},
		{http.MethodGet, "same-origin", "", true},
	} {
		req := httptest.NewRequest(tc.method, "/admin?reboot=invite&tier=Pioneer", nil)
		if tc.fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
		}
		if tc.referer != "" {
			req.Header.Set("Referer", tc.referer)
		}
		rec := httptest.NewRecorder()
		Admin(rec, req)

		ran := strings.Contains(rec.Header().Get("Location"), "html=invite")
		if ran != tc.runs {
			t.Errorf("%s from %q (referer %q): ran=%v, want %v", tc.method, tc.fetchSite, tc.referer, ran, tc.runs)
		}
	}
}
