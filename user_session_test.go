package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/userstate"
)

// account posts the Account page's form with action, the way a browser holding
// cookies does, through the wrapper the route has.
func (rig *renewalRig) account(action string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	rig.t.Helper()
	return rig.accountFrom(rig.form("/user", url.Values{"action": {action}}, cookies...))
}

func (rig *renewalRig) accountFrom(req *http.Request) *httptest.ResponseRecorder {
	rig.t.Helper()
	rec := httptest.NewRecorder()
	noSigning(http.HandlerFunc(rig.site.User)).ServeHTTP(rec, req)
	return rec
}

// wantRedirect fails unless rec sent the reader on to where, which a POST to
// the Account page always does.
func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, where string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != where || rec.Body.Len() != 0 {
		t.Errorf("status %d to %q with %d bytes, want a bare 303 to %s", rec.Code, rec.Header().Get("Location"), rec.Body.Len(), where)
	}
}

// Refresh now renews the signature the browser holds without waiting for its
// age, from the session the browser's own cookie names: the reader gets the
// tier Patreon reports now, a new signature and the session for another 31
// days, and is sent back to the page, which says it renewed.
func TestRefreshNowRenewsTheBrowsersOwnSession(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.title = "VINTAGE"
	session := rig.session("")
	rig.session("")
	young := rig.sig("Pioneer", 1*day)

	rec := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, rec, "/user?refreshed=yes")
	set := setCookies(rec)
	if len(rec.Result().Cookies()) != 2 || set[signatureCookie] == nil || set[sessionCookie] == nil {
		t.Fatalf("Set-Cookie %q, want %s and %s", rec.Header().Values("Set-Cookie"), signatureCookie, sessionCookie)
	}
	values, valid := signatureIsValid(set[signatureCookie].Value)
	if !valid || values.Get("UserTier") != "Vintage" || values.Get("UserEmail") != rig.user.Email {
		t.Errorf("new signature valid %v for %q at %q, want the reader's own at Vintage", valid, values.Get("UserEmail"), values.Get("UserTier"))
	}
	if set[sessionCookie].Value != session || set[sessionCookie].MaxAge != int(31*day/time.Second) {
		t.Errorf("session cookie %+v, want the same id for 31 days", set[sessionCookie])
	}
	rows := rig.rows()
	if len(rows) != 2 || rig.stub.calls() != 1 {
		t.Fatalf("rows %+v after %d refreshes, want both sessions after one", rows, rig.stub.calls())
	}
	for _, row := range rows {
		if row.token != rig.stub.liveToken() {
			t.Errorf("session %s holds %q, want the rotated token", row.id, row.token)
		}
	}
}

// Pressed twice at once, it asks Patreon once: the lease holds the second off.
func TestRefreshNowTwiceAtOnceAsksPatreonOnce(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.delay = 300 * time.Millisecond
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	recs := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range recs {
		wg.Go(func() { recs[i] = rig.account("refresh", browser(young, session)...) })
	}
	wg.Wait()

	renewed := 0
	for _, rec := range recs {
		if len(rec.Result().Cookies()) == 2 {
			renewed++
			wantRedirect(t, rec, "/user?refreshed=yes")
		} else {
			wantRedirect(t, rec, "/user?refreshed=no")
		}
	}
	if renewed != 1 || rig.stub.calls() != 1 {
		t.Errorf("%d presses renewed after %d refreshes, want one each", renewed, rig.stub.calls())
	}
}

// Refresh now renews only the reader the browser's signature cookie names,
// from the session its own cookie names: a ?sig=, a form field or someone
// else's session picks nobody.
// A second press of Refresh now inside the rest the first left behind asks
// Patreon nothing: the sessions are resting, so the lease refuses it, and the
// reader is sent back to the page as they are, which says so.
func TestRefreshNowTwiceInARowAsksPatreonOnce(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	first := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, first, "/user?refreshed=yes")
	if len(first.Result().Cookies()) != 2 {
		t.Fatalf("first press set %v, want the new signature and session", first.Header()["Set-Cookie"])
	}
	renewed := setCookies(first)[signatureCookie].Value

	second := rig.account("refresh", browser(renewed, session)...)
	wantRedirect(t, second, "/user?refreshed=no")
	if len(second.Result().Cookies()) != 0 || rig.stub.calls() != 1 {
		t.Errorf("second press set %v after %d refreshes, want nothing and one refresh", second.Header()["Set-Cookie"], rig.stub.calls())
	}
	rest := rig.restingFor(session)
	if rest < 290 || rest > 300 {
		t.Errorf("sessions rest %.0fs after Refresh now, want about five minutes", rest)
	}
}

func TestRefreshNowActsOnlyOnTheBrowsersOwnCookies(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	stranger := sessionReader(t, rig.db, "stranger")
	strangerSession, err := rig.db.CreatePatreonSession(t.Context(), loginOf(stranger, "refresh-stranger"), 0, 90*day)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a ?sig= with no cookie", func(t *testing.T) {
		req := rig.form("/user?sig="+url.QueryEscape(young), url.Values{"action": {"refresh"}}, browser("", session)...)
		wantRedirect(t, rig.accountFrom(req), "/user?refreshed=no")
		if rig.stub.calls() != 0 {
			t.Errorf("%d refreshes for a ?sig=, want none", rig.stub.calls())
		}
	})
	t.Run("a form field naming a session or a reader", func(t *testing.T) {
		fields := url.Values{"action": {"refresh"}, "session": {strangerSession}, "session_id": {strangerSession}, "email": {stranger.Email}, "email_hash": {userstate.HashEmail(stranger.Email)}}
		rec := rig.accountFrom(rig.form("/user", fields, browser(young, session)...))
		wantRedirect(t, rec, "/user?refreshed=yes")
		for _, row := range sessionRowsOf(t, rig.db, userstate.HashEmail(stranger.Email)) {
			if row.token != "refresh-stranger" {
				t.Errorf("the stranger's session was renewed: %+v", row)
			}
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == signatureCookie && GetParamFromSig(c.Value, "UserEmail") != rig.user.Email {
				t.Errorf("the response signs %q in", GetParamFromSig(c.Value, "UserEmail"))
			}
		}
	})
	t.Run("a session that is not the signature's", func(t *testing.T) {
		before := rig.stub.calls()
		wantRedirect(t, rig.account("refresh", browser(young, strangerSession)...), "/user?refreshed=no")
		if rig.stub.calls() != before {
			t.Error("a session of another reader was renewed behind this reader's signature")
		}
	})
	t.Run("a GET", func(t *testing.T) {
		before := rig.stub.calls()
		rec := httptest.NewRecorder()
		noSigning(http.HandlerFunc(rig.site.User)).ServeHTTP(rec, rig.request(http.MethodGet, "/user?action=refresh", browser(young, session)...))
		if rig.stub.calls() != before || len(rec.Result().Cookies()) != 0 {
			t.Error("a GET renewed the signature")
		}
	})
	t.Run("a signature that does not check out", func(t *testing.T) {
		before := rig.stub.calls()
		forged := tampered(young)
		wantRedirect(t, rig.account("refresh", browser(forged, session)...), "/user?refreshed=no")
		if rig.stub.calls() != before {
			t.Error("a forged signature was renewed")
		}
	})
}

// Refresh now from a session that can never renew again, its refresh token
// refused by Patreon for good or its row gone, says to log in again rather
// than to try again.
func TestRefreshNowSaysWhenTheSessionEnded(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.token = &stubAnswer{http.StatusUnauthorized, `{"error":"invalid_grant"}`}
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	rec := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, rec, "/user?refreshed=ended")
	if rows := rig.rows(); len(rows) != 0 {
		t.Errorf("rows %+v, want the session gone", rows)
	}
	// The browser still holding the cookie of the row that went
	wantRedirect(t, rig.account("refresh", browser(young, session)...), "/user?refreshed=ended")
	if rig.stub.calls() != 1 {
		t.Errorf("%d refreshes, want the one Patreon refused", rig.stub.calls())
	}
	page := httptest.NewRecorder()
	noSigning(http.HandlerFunc(rig.site.User)).ServeHTTP(page, rig.request(http.MethodGet, "/user?refreshed=ended", browser(young, "")...))
	if !strings.Contains(page.Body.String(), refreshNotes["ended"]) {
		t.Error("the page does not say the sign-in ended")
	}
}

// Where the site does not renew, the button is not on the page and a POST
// that presses it changes nothing.
func TestRefreshNowIsAbsentWhereRenewalIsOff(t *testing.T) {
	rig := newRenewalRig(t, infrastructure.PatreonRenewal{GraceDays: 3})
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	rec := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, rec, "/user?refreshed=no")
	if len(rec.Result().Cookies()) != 0 || rig.stub.calls() != 0 {
		t.Errorf("Set-Cookie %q after %d refreshes, want none", rec.Header().Values("Set-Cookie"), rig.stub.calls())
	}
	user := &UserVars{SignedIn: true, Email: "a@b.com", CanEndSessions: true, Tiers: tierSummaries(newSite(), fixtureACL(), "")}
	if out := renderUserPage(t, pageVarsFor(user)); strings.Contains(out, `value="refresh"`) || !strings.Contains(out, `value="logout-everywhere"`) {
		t.Error("the page offers Refresh now, or withholds Log out everywhere, without renewal")
	}
	user.CanRefresh = true
	if out := renderUserPage(t, pageVarsFor(user)); !strings.Contains(out, `value="refresh"`) || !strings.Contains(out, `method="post"`) {
		t.Error("the page withholds Refresh now where renewal is on")
	}
}

// The page offers Refresh now and Log out everywhere to a signed-in browser
// that holds a session, where the site renews, and not otherwise; and says
// what the last Refresh now did.
func TestAccountPageOffersRefreshNowToABrowserWithASession(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	for name, tc := range map[string]struct {
		cookies []*http.Cookie
		want    bool
	}{
		"signed in with a session": {browser(young, session), true},
		"signed in, no session":    {browser(young, ""), false},
		"signed out":               {browser("", session), false},
	} {
		rec := httptest.NewRecorder()
		noSigning(http.HandlerFunc(rig.site.User)).ServeHTTP(rec, rig.request(http.MethodGet, "/user", tc.cookies...))
		if offered := strings.Contains(rec.Body.String(), `value="refresh"`); offered != tc.want || rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, Refresh now offered %v, want %v", name, rec.Code, offered, tc.want)
		}
		if offered := strings.Contains(rec.Body.String(), `value="logout-everywhere"`); offered != tc.want {
			t.Errorf("%s: Log out everywhere offered %v, want %v", name, offered, tc.want)
		}
	}

	for query, want := range map[string]string{
		"?refreshed=yes":   refreshNotes["yes"],
		"?refreshed=no":    refreshNotes["no"],
		"?refreshed=ended": refreshNotes["ended"],
		"":                 "",
		"?refreshed=x":     "",
	} {
		rec := httptest.NewRecorder()
		noSigning(http.HandlerFunc(rig.site.User)).ServeHTTP(rec, rig.request(http.MethodGet, "/user"+query, browser(young, session)...))
		shown := strings.Contains(rec.Body.String(), `role="status"`)
		if shown != (want != "") || (want != "" && !strings.Contains(rec.Body.String(), want)) {
			t.Errorf("/user%s: note shown %v, want %q", query, shown, want)
		}
	}
}

// Log out everywhere deletes every session of the reader's email, none
// of anyone else's, and clears this browser's cookies. The signatures already
// issued elsewhere run to their own end and cannot renew.
func TestLogOutEverywhereEndsEverySessionOfTheEmail(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	here := rig.session("")
	rig.session("")
	young := rig.sig("Legacy", 1*day)

	stranger := sessionReader(t, rig.db, "stranger")
	strangerHash := userstate.HashEmail(stranger.Email)
	_, err := rig.db.CreatePatreonSession(t.Context(), loginOf(stranger, "refresh-stranger"), 0, 90*day)
	if err != nil {
		t.Fatal(err)
	}

	req := rig.form("/user", url.Values{"action": {"logout-everywhere"}, "email": {stranger.Email}, "email_hash": {strangerHash}}, browser(young, here)...)
	rec := rig.accountFrom(req)
	wantRedirect(t, rec, "/")
	checkLogoutClears(t, rec, map[string]*http.Cookie{
		signatureCookie: signatureCookieFor(req, signatureCookie, "x", time.Now()),
		sessionCookie:   sessionCookieFor(req, "x", 1),
	})
	if rows := rig.rows(); len(rows) != 0 {
		t.Errorf("rows %+v, want every session of the reader gone", rows)
	}
	if rows := sessionRowsOf(t, rig.db, strangerHash); len(rows) != 1 {
		t.Errorf("the stranger holds %d sessions, want their one", len(rows))
	}

	// Another device carries on to its own end, and cannot renew: its
	// session cookie names nothing now and goes, and without it the
	// device asks nothing more
	old := rig.sig("Legacy", 9*day)
	req = rig.request(http.MethodGet, "/limited", browser(old, "the-other-devices-session")...)
	rig.wantSessionDropped(rig.serve(req, false), req, old)
	rig.wantUntouched(rig.page(browser(old, "")...), old)
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes after Log out everywhere, want none", rig.stub.calls())
	}
}

// Log out everywhere deletes the rows of the reader the browser's signature
// names and no other: not one a ?sig= names, and nothing at all for a
// signature that does not check out, or one that comes without a session of
// its reader, as a signature leaked through a link or a log would.
func TestLogOutEverywhereNamesTheReaderBySignatureCookieAlone(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	t.Run("a ?sig= with no cookie", func(t *testing.T) {
		req := rig.form("/user?sig="+url.QueryEscape(young), url.Values{"action": {"logout-everywhere"}})
		rec := rig.accountFrom(req)
		wantRedirect(t, rec, "/")
		if rows := rig.rows(); len(rows) != 1 {
			t.Errorf("rows %+v, want the reader's session kept", rows)
		}
	})
	t.Run("a signature that does not check out", func(t *testing.T) {
		forged := tampered(young)
		rec := rig.account("logout-everywhere", browser(forged, session)...)
		wantRedirect(t, rec, "/")
		if rows := rig.rows(); len(rows) != 1 {
			t.Errorf("rows %+v, want the reader's session kept", rows)
		}
		if len(rec.Result().Cookies()) != 3 {
			t.Errorf("Set-Cookie %q, want this browser's cookies cleared all the same", rec.Header().Values("Set-Cookie"))
		}
	})
	stranger := sessionReader(t, rig.db, "stranger")
	strangerSession, err := rig.db.CreatePatreonSession(t.Context(), loginOf(stranger, "refresh-stranger"), 0, 90*day)
	if err != nil {
		t.Fatal(err)
	}
	for name, cookies := range map[string][]*http.Cookie{
		"a signature with no session":        browser(young, ""),
		"a signature with a stranger's":      browser(young, strangerSession),
		"a signature with a session unknown": browser(young, "not-a-session-id"),
	} {
		rec := rig.account("logout-everywhere", cookies...)
		wantRedirect(t, rec, "/")
		if rows := rig.rows(); len(rows) != 1 {
			t.Errorf("%s: rows %+v, want the reader's session kept", name, rows)
		}
		if rows := sessionRowsOf(t, rig.db, userstate.HashEmail(stranger.Email)); len(rows) != 1 {
			t.Errorf("%s: the stranger holds %d sessions, want their one", name, len(rows))
		}
		if len(rec.Result().Cookies()) != 3 {
			t.Errorf("%s: Set-Cookie %q, want this browser's cookies cleared all the same", name, rec.Header().Values("Set-Cookie"))
		}
	}
}

// With the database down the browser is logged out all the same, and the
// failure is logged; the sessions wait for the prune or the next press.
func TestLogOutEverywhereWithTheDatabaseDown(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	spare := openUserStateClient(t)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	rig.db.Close()

	req := rig.form("/user", url.Values{"action": {"logout-everywhere"}}, browser(young, session)...)
	rec := rig.accountFrom(req)
	wantRedirect(t, rec, "/")
	checkLogoutClears(t, rec, map[string]*http.Cookie{
		signatureCookie: signatureCookieFor(req, signatureCookie, "x", time.Now()),
		sessionCookie:   sessionCookieFor(req, "x", 1),
	})
	if !strings.Contains(rig.logged.String(), "DeletePatreonSessions") {
		t.Errorf("admin log %q does not name the failure", rig.logged.String())
	}
	if rows := sessionRowsOf(t, spare, rig.hash); len(rows) != 1 {
		t.Errorf("rows %+v, want the session left for the prune", rows)
	}
}

// A form posted from another site's page is refused before it is read, and a
// POST that names no action, or one the page does not have, does nothing.
func TestAccountPostRefusesCrossSiteAndUnknownActions(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	for _, action := range []string{"refresh", "logout-everywhere"} {
		req := rig.form("/user", url.Values{"action": {action}}, browser(young, session)...)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := rig.accountFrom(req)
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s from another site: status %d, Set-Cookie %q; want 403 and none", action, rec.Code, rec.Header().Values("Set-Cookie"))
		}

		req = rig.form("/user", url.Values{"action": {action}}, browser(young, session)...)
		req.Header.Del("Sec-Fetch-Site")
		req.Header.Set("Origin", "https://evil.example")
		if rec = rig.accountFrom(req); rec.Code != http.StatusForbidden {
			t.Errorf("%s with a foreign Origin: status %d, want 403", action, rec.Code)
		}
	}
	for _, action := range []string{"", "unknown", "REFRESH"} {
		rec := rig.account(action, browser(young, session)...)
		wantRedirect(t, rec, "/user")
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("action %q set %q", action, rec.Header().Values("Set-Cookie"))
		}
	}
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes, want none", rig.stub.calls())
	}
	if rows := rig.rows(); len(rows) != 1 || rows[0].token != "refresh-0" {
		t.Errorf("rows %+v, want the session untouched", rows)
	}
}
