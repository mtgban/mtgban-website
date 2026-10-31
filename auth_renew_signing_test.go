package main

import (
	"context"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

// A signature old enough, in the cookie beside its session, is renewed in the
// request that finds it: the response sets the new signature and the same
// session for another 31 days, the sessions hold the token Patreon rotated
// to, and the handler already reads the new signature. The new signature has
// the keys a login's has, and no database connection is held while Patreon is
// asked.
func TestSigningRenewsADueSignature(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	other := rig.session("")
	old := rig.sig("Legacy", 9*day)

	got := rig.page(browser(old, session)...)
	fresh := rig.wantRenewed(got, old, session)

	values := parseSig(fresh)
	if values.Get("UserEmail") != rig.user.Email || values.Get("UserTier") != "Legacy" || values.Get("UserName") != rig.user.FullName {
		t.Errorf("renewed signature names %q %q %q, want the reader's own", values.Get("UserEmail"), values.Get("UserTier"), values.Get("UserName"))
	}
	login := parseSig(sign("Legacy", rig.user, nil, DefaultSignatureDuration))
	if !slices.Equal(slices.Sorted(maps.Keys(values)), slices.Sorted(maps.Keys(login))) {
		t.Errorf("renewed signature has keys %v, a login's has %v", slices.Sorted(maps.Keys(values)), slices.Sorted(maps.Keys(login)))
	}

	rotated := rig.stub.liveToken()
	if rotated == "refresh-0" || rig.stub.calls() != 1 {
		t.Errorf("Patreon honours %q after %d refreshes, want a rotated token after one", rotated, rig.stub.calls())
	}
	rows := rig.rows()
	if len(rows) != 2 || rows[0].token != rotated || rows[1].token != rotated {
		t.Errorf("rows %+v, want both holding %q", rows, rotated)
	}
	if rig.restingFor(other) > 0 {
		t.Error("a renewed session is still resting")
	}
	if rig.stub.inUse != 0 {
		t.Errorf("%d database connections were held while Patreon was asked", rig.stub.inUse)
	}
	if !strings.Contains(rig.logged.String(), "verdict=entitled tier=Legacy->Legacy err=<nil>") {
		t.Errorf("admin log %q does not tell the renewal", rig.logged.String())
	}
	rig.wantNoTokens()
}

// A renewal gives the tier Patreon reports now, higher or lower.
func TestSigningRenewalFollowsThePledge(t *testing.T) {
	for _, tc := range []struct{ name, before, title, want string }{
		{"up", "Pioneer", "VINTAGE", "Vintage"},
		{"down", "Vintage", "PIONEER", "Pioneer"},
		{"same", "Legacy", "LEGACY (Early Adopters)", "Legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			rig.stub.title = tc.title
			session := rig.session("")
			old := rig.sig(tc.before, 9*day)

			got := rig.page(browser(old, session)...)
			fresh := rig.wantRenewed(got, old, session)
			tier := GetParamFromSig(fresh, "UserTier")
			if tier != tc.want || GetParamFromSig(got.sig, "UserTier") != tc.want {
				t.Errorf("renewed tier %q, want %q", tier, tc.want)
			}
		})
	}
}

// An edit to the access table reaches a reader at their next renewal.
func TestSigningRenewalReadsTheCurrentAccessTable(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	installAccess(t, `{"Legacy":{"Search":{}}}`, `[]`)
	old := rig.sig("Legacy", 9*day)
	installAccess(t, `{"Legacy":{"Search":{},"Upload":{}}}`, `[]`)
	session := rig.session("")

	fresh := rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	if GetParamFromSig(old, "Upload") != "" || GetParamFromSig(fresh, "Upload") != "true" {
		t.Errorf("Upload was %q before and %q after, want it granted by the renewal", GetParamFromSig(old, "Upload"), GetParamFromSig(fresh, "Upload"))
	}
}

// A grant decides the tier before Patreon's membership answer, so a reader
// with a grant and no pledge renews; take the grant away and the pledge
// decides, or nothing does.
func TestSigningRenewalGrantBeforePledge(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.membership = false
	grant := fmt.Sprintf(`[{"email":%q,"name":"Granted","category":"friend","tier":"Vintage"}]`, rig.user.Email)
	installAccess(t, `{}`, grant)
	session := rig.session("")

	old := rig.sig("Vintage", 9*day)
	fresh := rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	tier := GetParamFromSig(fresh, "UserTier")
	if tier != "Vintage" || rig.stub.memberCalls != 0 {
		t.Errorf("a grant renewed to %q after %d membership calls, want Vintage with none", tier, rig.stub.memberCalls)
	}

	installAccess(t, `{}`, `[]`)
	rig.stub.membership = true
	old = rig.sig("Vintage", 10*day)
	fresh = rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	tier = GetParamFromSig(fresh, "UserTier")
	if tier != "Legacy" {
		t.Errorf("without the grant the renewal gave %q, want the pledge's Legacy", tier)
	}

	rig.stub.membership = false
	old = rig.sig("Legacy", 9*day)
	got := rig.page(browser(old, session)...)
	if got.reached || !strings.Contains(got.rec.Body.String(), html.EscapeString(ErrMsgExpired)) {
		t.Errorf("a reader with neither grant nor pledge reached %v, want the logged-out page", got.reached)
	}
}

// A reader whose email changed on Patreon is signed under the new one, and
// every session follows, so the next renewal finds them there.
func TestSigningRenewalFollowsAChangedEmail(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.email = fmt.Sprintf("moved-%d@example.com", time.Now().UnixNano())
	newHash := userstate.HashEmail(rig.stub.email)
	t.Cleanup(func() {
		// t.Context() is already canceled when a cleanup runs
		_, err := rig.db.DeletePatreonSessions(context.Background(), newHash)
		if err != nil {
			t.Error(err)
		}
	})
	session := rig.session("")
	other := rig.session("")
	old := rig.sig("Legacy", 9*day)

	fresh := rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	email := GetParamFromSig(fresh, "UserEmail")
	if email != rig.stub.email {
		t.Errorf("renewed signature names %q, want %q", email, rig.stub.email)
	}
	if len(rig.rows()) != 0 {
		t.Errorf("rows %+v are still under the old email", rig.rows())
	}
	moved := sessionRowsOf(t, rig.db, newHash)
	if len(moved) != 2 || moved[0].token != rig.stub.liveToken() || moved[1].token != rig.stub.liveToken() {
		t.Errorf("rows %+v under the new email, want both with the rotated token", moved)
	}
	if !strings.Contains(rig.logged.String(), fmt.Sprintf("email changed from %q to %q", rig.user.Email, rig.stub.email)) {
		t.Errorf("admin log %q does not say the email changed", rig.logged.String())
	}

	// The other device finds its session under the new email, and renews
	rig.user.Email = rig.stub.email
	rig.hash = newHash
	again := rig.sig("Legacy", 9*day)
	rig.wantRenewed(rig.page(browser(again, other)...), again, other)
	if rig.stub.calls() != 2 {
		t.Errorf("%d refreshes, want one per renewal", rig.stub.calls())
	}
}

// An email Patreon has not confirmed is flagged in the renewed signature, as
// a login flags it.
func TestSigningRenewalFlagsAnUnconfirmedEmail(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.verified = false
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	fresh := rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	if GetParamFromSig(fresh, "UserEmailUnverified") != "true" {
		t.Error("the renewed signature does not flag the unconfirmed email")
	}
}

// A renewal records what Patreon says about the reader for alerts the way a
// login does: the tier, or none for a grant, and the Discord account.
func TestSigningRenewalRecordsTheAlertContact(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	store, err := alerts.New(rig.db.DB())
	if err != nil {
		t.Fatal(err)
	}
	s := newSite()
	s.alerts.SetStore(store)
	rig.site = s
	t.Cleanup(func() {
		_, err := rig.db.DB().Exec(`DELETE FROM alert_contacts WHERE user_hash = $1`, rig.hash)
		if err != nil {
			t.Error(err)
		}
	})
	rig.stub.discord = "123456789012345678"
	session := rig.session("")

	old := rig.sig("Legacy", 9*day)
	rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	contact, found, err := store.Contact(t.Context(), rig.hash)
	if err != nil || !found || contact.Tier != "Legacy" || contact.DiscordUserID != "123456789012345678" {
		t.Errorf("contact %+v (found %v, err %v), want the Legacy tier and the Discord account", contact, found, err)
	}

	installAccess(t, `{}`, fmt.Sprintf(`[{"email":%q,"name":"Granted","category":"friend","tier":"Vintage"}]`, rig.user.Email))
	rig.stub.discord = ""
	old = rig.sig("Vintage", 9*day)
	rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	contact, _, err = store.Contact(t.Context(), rig.hash)
	if err != nil || contact.Tier != "" || contact.DiscordUserID != "" {
		t.Errorf("contact %+v (err %v) after a grant renewal, want no tier and no Discord account", contact, err)
	}
}

// When nothing is pledged and clear_on_negative is on, the reader is logged
// out: this browser's session is deleted and every cookie of the login is
// cleared, with the login button shown and the handler not reached. The other
// devices keep a live token, to find out for themselves.
func TestSigningRenewalLogsOutAReaderWhoPledgesNothing(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.title = ""
	here := rig.session("")
	elsewhere := rig.session("")
	old := rig.sig("Legacy", 9*day)

	req := rig.request(http.MethodGet, "/limited", browser(old, here)...)
	got := rig.serve(req, false)
	body := got.rec.Body.String()
	if got.reached || !strings.Contains(body, html.EscapeString(ErrMsgExpired)) || !strings.Contains(body, "Log in") || strings.Contains(body, "Logout") {
		t.Errorf("reached %v, page offers the logged-out message and the login: %v", got.reached, strings.Contains(body, html.EscapeString(ErrMsgExpired)))
	}
	checkLogoutClears(t, got.rec, map[string]*http.Cookie{
		signatureCookie: signatureCookieFor(req, signatureCookie, "x", time.Now()),
		sessionCookie:   sessionCookieFor(req, "x", 1),
	})
	rows := rig.rows()
	if len(rows) != 1 || rows[0].id != elsewhere || rows[0].token != rig.stub.liveToken() {
		t.Errorf("rows %+v, want only the other device's, with the rotated token", rows)
	}
	if !strings.Contains(rig.logged.String(), "verdict=not entitled") {
		t.Errorf("admin log %q does not tell the verdict", rig.logged.String())
	}
	rig.wantNoTokens()
}

// Without clear_on_negative the same answer changes nothing: the signature
// stays, the sessions rest an hour, and the token Patreon rotated to is kept.
func TestSigningRenewalWithoutClearOnNegativeKeepsTheReader(t *testing.T) {
	rig := newRenewalRig(t, infrastructure.PatreonRenewal{AfterDays: 8, GraceDays: 3})
	rig.stub.title = ""
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	rows := rig.rows()
	if len(rows) != 1 || rows[0].token != rig.stub.liveToken() || rig.restingFor(session) < 59*60 {
		t.Errorf("rows %+v resting %.0fs, want the rotated token and an hour", rows, rig.restingFor(session))
	}
	if !strings.Contains(rig.logged.String(), "verdict=not entitled") {
		t.Errorf("admin log %q does not tell the verdict", rig.logged.String())
	}

	// The hour is the backoff: asking again costs Patreon nothing
	rig.wantUntouched(rig.page(browser(old, session)...), old)
	if rig.stub.calls() != 1 {
		t.Errorf("%d refreshes inside the backoff, want 1", rig.stub.calls())
	}
}

// Whatever goes wrong with Patreon's answer, short of a refresh token it
// refuses for good, the reader keeps their signature and their sessions,
// nothing is set or cleared, and the sessions rest an hour: one wait per
// outage, not per request. A refresh that went through before the answer
// failed leaves the rotated token in the sessions, never a dead one.
func TestSigningRenewalNeverActsOnAnAnswerThatSettlesNothing(t *testing.T) {
	const wrongTier = `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}}}`
	for _, tc := range []struct {
		name                    string
		token, identity, member *stubAnswer
		title                   string
		closed                  bool
		slowIdentity            bool
	}{
		{name: "refresh 500", token: &stubAnswer{500, `{"errors":[{"title":"boom"}]}`}},
		{name: "refresh 429", token: &stubAnswer{429, `{"errors":[{"code_name":"RequestThrottled"}]}`}},
		{name: "refresh 502 from the edge", token: &stubAnswer{502, `<html>Bad Gateway</html>`}},
		{name: "refresh unreadable", token: &stubAnswer{200, `{"access_token": "cut`}},
		{name: "refresh without an access token", token: &stubAnswer{200, `{"access_token":"","refresh_token":"r","token_type":"Bearer"}`}},
		{name: "refresh without a refresh token", token: &stubAnswer{200, `{"access_token":"a","token_type":"Bearer"}`}},
		{name: "refresh refused for another reason", token: &stubAnswer{401, `{"error":"invalid_client"}`}},
		{name: "refresh unreachable", closed: true},
		{name: "identity too slow", slowIdentity: true},
		{name: "identity 401", identity: &stubAnswer{401, `{"errors":[{"title":"Unauthorized"}]}`}},
		{name: "identity 403", identity: &stubAnswer{403, `{}`}},
		{name: "identity 500", identity: &stubAnswer{500, ``}},
		{name: "identity with an errors array", identity: &stubAnswer{200, `{"errors":[{"title":"Unauthorized"}]}`}},
		{name: "identity unreadable", identity: &stubAnswer{200, `<html>`}},
		{name: "membership 404", member: &stubAnswer{404, `{"errors":[{"title":"Not Found"}]}`}},
		{name: "membership 403", member: &stubAnswer{403, `{}`}},
		{name: "membership 429", member: &stubAnswer{429, `{}`}},
		{name: "membership with an errors array", member: &stubAnswer{200, `{"errors":[{"title":"x","code_name":"y"}]}`}},
		{name: "membership unreadable", member: &stubAnswer{200, `{"data":`}},
		{name: "a tier with no title", member: &stubAnswer{200, wrongTier}},
		{name: "a tier title the site does not know", title: "SOMETHING NEW"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := renewalBlock
			if tc.slowIdentity {
				block.RenewTimeoutSeconds = 1
			}
			rig := newRenewalRig(t, block)
			rig.stub.token, rig.stub.identity, rig.stub.member = tc.token, tc.identity, tc.member
			if tc.title != "" {
				rig.stub.title = tc.title
			}
			if tc.slowIdentity {
				rig.stub.identityDelay = 1500 * time.Millisecond
			}
			session := rig.session("")
			elsewhere := rig.session("")
			old := rig.sig("Legacy", 9*day)
			if tc.closed {
				rig.stub.server.Close()
			}

			rig.wantUntouched(rig.page(browser(old, session)...), old)
			rows := rig.rows()
			if len(rows) != 2 {
				t.Fatalf("rows %+v, want both kept", rows)
			}
			for _, row := range rows {
				if row.token != rig.stub.liveToken() {
					t.Errorf("session %s holds %q, but Patreon honours %q", row.id, row.token, rig.stub.liveToken())
				}
			}
			wait := rig.restingFor(elsewhere)
			if wait < 59*60 || wait > 61*60 {
				t.Errorf("sessions rest %.0fs, want an hour", wait)
			}
			if !strings.Contains(rig.logged.String(), "verdict=unknown") {
				t.Errorf("admin log %q does not tell the verdict", rig.logged.String())
			}
			rig.wantNoTokens()

			// Inside the hour, asking again costs Patreon nothing
			before := rig.stub.calls()
			rig.wantUntouched(rig.page(browser(old, session)...), old)
			after := rig.stub.calls()
			if after != before {
				t.Errorf("%d refreshes inside the backoff, want %d", after, before)
			}
		})
	}
}

// A refresh token Patreon refuses for good is dead for every device, so every
// session of the email goes and the browser's session cookie is cleared; the
// signature stays, and the reader is served as before.
func TestSigningRenewalDropsSessionsWhoseTokenIsDead(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{"as Patreon answers it", http.StatusUnauthorized},
		{"as the OAuth standard has it", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			here := rig.session("")
			rig.session("")
			rig.stub.token = &stubAnswer{tc.code, `{"error":"invalid_grant"}`}
			old := rig.sig("Legacy", 9*day)

			req := rig.request(http.MethodGet, "/limited", browser(old, here)...)
			got := rig.serve(req, false)
			if !got.reached || got.sig != old {
				t.Errorf("handler reached %v and read the old signature: %v", got.reached, got.sig == old)
			}
			set := setCookies(got.rec)
			cleared := set[sessionCookie]
			want := sessionCookieFor(req, "", -1)
			if len(got.rec.Result().Cookies()) != 1 || cleared == nil || cleared.MaxAge >= 0 || cleared.Value != "" ||
				cleared.Domain != want.Domain || cleared.Path != want.Path || !cleared.HttpOnly || !cleared.Secure || cleared.SameSite != want.SameSite {
				t.Errorf("Set-Cookie %q, want the session cookie cleared and nothing else", got.rec.Header().Values("Set-Cookie"))
			}
			rows := rig.rows()
			if len(rows) != 0 {
				t.Errorf("rows %+v, want every session of the email gone", rows)
			}
			if !strings.Contains(rig.logged.String(), "verdict=invalid_grant") {
				t.Errorf("admin log %q does not tell the verdict", rig.logged.String())
			}

			// The browser dropped its session cookie, and the signature
			// carries on to its own end
			rig.wantUntouched(rig.page(browser(old, "")...), old)
			if rig.stub.calls() != 1 {
				t.Errorf("%d refreshes, want the one that found the token dead", rig.stub.calls())
			}
		})
	}
}

// A token another device already spent is dead the same way.
func TestSigningRenewalWithATokenAnotherDeviceSpent(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	rig.stub.spend("refresh-elsewhere")
	old := rig.sig("Legacy", 9*day)

	got := rig.page(browser(old, session)...)
	if !got.reached || got.sig != old || len(got.rec.Result().Cookies()) != 1 {
		t.Errorf("reached %v, Set-Cookie %q; want the old signature and the session cleared", got.reached, got.rec.Header().Values("Set-Cookie"))
	}
	rows := rig.rows()
	if len(rows) != 0 {
		t.Errorf("rows %+v, want none", rows)
	}
}

// A signature that ran out within grace_days is renewed from its cookie and
// session, and the reader never sees the expiry.
func TestSigningRenewsASignatureThatRanOutWithinGrace(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	old := rig.sig("Legacy", 11*day+2*time.Hour)

	got := rig.page(browser(old, session)...)
	rig.wantRenewed(got, old, session)

	// So does a script's fetch
	again := rig.sig("Legacy", 11*day+3*time.Hour)
	data := rig.serve(rig.request(http.MethodGet, "/data/prices/x", browser(again, session)...), true)
	rig.wantRenewed(data, again, session)
}

// Where grace cannot renew, the reader meets the page they would have met
// without it: the plain logged-out page, with nothing set or cleared, and no
// call to Patreon unless a renewal was possible.
func TestSigningGraceLeavesTodaysBehaviourWhereItCannotRenew(t *testing.T) {
	loggedOut := func(got *served) bool {
		body := got.rec.Body.String()
		return !got.reached && strings.Contains(body, html.EscapeString(ErrMsg)) && !strings.Contains(body, html.EscapeString(ErrMsgExpired)) && len(got.rec.Header().Values("Set-Cookie")) == 0
	}
	expired := 11*day + time.Hour

	t.Run("Patreon gives no answer", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		rig.stub.identity = &stubAnswer{500, ``}
		session := rig.session("")
		got := rig.page(browser(rig.sig("Legacy", expired), session)...)
		if !loggedOut(got) || rig.restingFor(session) < 59*60 {
			t.Errorf("reached %v, today's page %v, resting %.0fs; want today's page and an hour's rest", got.reached, loggedOut(got), rig.restingFor(session))
		}
	})
	t.Run("no session cookie", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		rig.session("")
		got := rig.page(browser(rig.sig("Legacy", expired), "")...)
		if !loggedOut(got) || rig.stub.calls() != 0 {
			t.Errorf("today's page %v after %d refreshes, want it with none", loggedOut(got), rig.stub.calls())
		}
	})
	t.Run("past grace_days", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		session := rig.session("")
		got := rig.page(browser(rig.sig("Legacy", 14*day+time.Hour), session)...)
		if !loggedOut(got) || rig.stub.calls() != 0 {
			t.Errorf("today's page %v after %d refreshes, want it with none", loggedOut(got), rig.stub.calls())
		}
	})
	t.Run("no signature cookie", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		session := rig.session("")
		got := rig.page(browser("", session)...)
		if !loggedOut(got) || rig.stub.calls() != 0 {
			t.Errorf("today's page %v after %d refreshes, want it with none", loggedOut(got), rig.stub.calls())
		}
	})
	t.Run("grace_days 0", func(t *testing.T) {
		rig := newRenewalRig(t, infrastructure.PatreonRenewal{AfterDays: 8})
		session := rig.session("")
		got := rig.page(browser(rig.sig("Legacy", expired), session)...)
		if !loggedOut(got) || rig.stub.calls() != 0 {
			t.Errorf("today's page %v after %d refreshes, want it with none", loggedOut(got), rig.stub.calls())
		}
	})
	t.Run("a session past max_session_days", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		id, err := rig.db.CreatePatreonSession(t.Context(), loginOf(rig.user, "refresh-0"), 0, -time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// The cookie of a session past its cap names nothing, and goes
		req := rig.request(http.MethodGet, "/limited", browser(rig.sig("Legacy", expired), id)...)
		got := rig.serve(req, false)
		cookies := got.rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].MaxAge >= 0 {
			t.Errorf("Set-Cookie %q, want the session cookie cleared and nothing else", got.rec.Header().Values("Set-Cookie"))
		}
		got.rec.Header().Del("Set-Cookie")
		if !loggedOut(got) || rig.stub.calls() != 0 {
			t.Errorf("today's page %v after %d refreshes, want it with none", loggedOut(got), rig.stub.calls())
		}
	})
	t.Run("a POST", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		session := rig.session("")
		got := rig.serve(rig.request(http.MethodPost, "/upload", browser(rig.sig("Legacy", expired), session)...), false)
		if got.rec.Code != http.StatusMethodNotAllowed || got.reached || rig.stub.calls() != 0 {
			t.Errorf("status %d after %d refreshes, want 405 and none", got.rec.Code, rig.stub.calls())
		}
	})
	t.Run("a reader who pledges nothing is logged out", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		rig.stub.title = ""
		session := rig.session("")
		req := rig.request(http.MethodGet, "/limited", browser(rig.sig("Legacy", expired), session)...)
		got := rig.serve(req, false)
		if got.reached || !strings.Contains(got.rec.Body.String(), html.EscapeString(ErrMsgExpired)) {
			t.Errorf("reached %v, want the logged-out page", got.reached)
		}
		checkLogoutClears(t, got.rec, map[string]*http.Cookie{
			signatureCookie: signatureCookieFor(req, signatureCookie, "x", time.Now()),
			sessionCookie:   sessionCookieFor(req, "x", 1),
		})
		rows := rig.rows()
		if len(rows) != 0 {
			t.Errorf("rows %+v, want the session gone", rows)
		}
	})
}

// A signature that ran out is counted against the reader it names while
// grace is on, not against everyone else with an expired cookie.
func TestSigningGraceCountsAnExpiredSignatureByItsReader(t *testing.T) {
	for _, tc := range []struct {
		name           string
		block          infrastructure.PatreonRenewal
		anonymousSpent bool
	}{
		{"with grace_days", renewalBlock, false},
		{"without", infrastructure.PatreonRenewal{AfterDays: 8}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, tc.block)
			UserRateLimiter = ratelimit.NewLimiter(1, 2)
			expired := browser(rig.sig("Legacy", 11*day+time.Hour), "")

			for range 2 {
				rig.page(expired...)
			}
			limited := func(got *served) bool { return strings.Contains(got.rec.Body.String(), "Too Many Requests") }
			anonymous := rig.page()
			if limited(anonymous) != tc.anonymousSpent {
				t.Errorf("a reader with no cookie was limited: %v, want %v", limited(anonymous), tc.anonymousSpent)
			}
			again := rig.page(expired...)
			if !limited(again) && !tc.anonymousSpent {
				t.Error("the reader with the expired signature was not limited by their own count")
			}
		})
	}
}

// unverifiedSignature still drops a signature that ran out, grace or not:
// the raw cookie is read in signing alone.
func TestUnverifiedSignatureStillDropsAnExpiredCookie(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	expired := rig.sig("Legacy", 11*day+time.Hour)
	got := unverifiedSignature(rig.request(http.MethodGet, "/limited", browser(expired, "x")...))
	if got != "" {
		t.Errorf("unverifiedSignature = %q for an expired cookie, want none", got)
	}
}

// What arrives as ?sig= never renews, expired or not, whatever session cookie
// comes with it: an invite link, or a reader's signature pasted into one.
func TestSigningNeverRenewsAQuerySignature(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	for name, age := range map[string]time.Duration{"due": 9 * day, "expired": 11*day + time.Hour} {
		sig := rig.sig("Legacy", age)
		got := rig.serve(rig.request(http.MethodGet, "/limited?sig="+url.QueryEscape(sig), browser("", session)...), false)
		set := setCookies(got.rec)
		if rig.stub.calls() != 0 {
			t.Errorf("%s: %d refreshes for a ?sig=, want none", name, rig.stub.calls())
		}
		if age < 11*day && (!got.reached || got.sig != sig || set[sessionCookie] != nil || set[signatureCookie] == nil || set[signatureCookie].Value != sig) {
			t.Errorf("%s: reached %v, Set-Cookie %q; want the signature kept as the cookie, as ever", name, got.reached, got.rec.Header().Values("Set-Cookie"))
		}
		if age > 11*day && (got.reached || !strings.Contains(got.rec.Body.String(), html.EscapeString(ErrMsgExpired))) {
			t.Errorf("%s: reached %v, want the logged-out page", name, got.reached)
		}
	}
	rows := rig.rows()
	if len(rows) != 1 || rows[0].token != "refresh-0" {
		t.Errorf("rows %+v, want the session untouched", rows)
	}
}

// An invite link names nobody: kept as the cookie, it grants its pages until
// its own end and is never renewed, even beside a session left by an earlier
// login, and it gets no grace.
func TestSigningInviteLinkIsNeverRenewed(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")

	// Two days left, which is the age a signature due for renewal has
	invite := sign("Legacy", nil, nil, 2*day)
	first := rig.serve(rig.request(http.MethodGet, "/limited?sig="+url.QueryEscape(invite)), false)
	kept := setCookies(first.rec)[signatureCookie]
	if !first.reached || kept == nil || kept.Value != invite || !kept.HttpOnly {
		t.Fatalf("reached %v, Set-Cookie %q; want the invite kept as an HttpOnly cookie", first.reached, first.rec.Header().Values("Set-Cookie"))
	}
	later := rig.page(browser(invite, session)...)
	rig.wantUntouched(later, invite)

	ended := sign("Legacy", nil, nil, -time.Hour)
	gone := rig.page(browser(ended, session)...)
	if gone.reached || !strings.Contains(gone.rec.Body.String(), html.EscapeString(ErrMsg)) || len(gone.rec.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("an ended invite reached %v, want the login page", gone.reached)
	}
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes for an invite, want none", rig.stub.calls())
	}
}

// A signature that is not bound to the session beside it, by the email it
// names, the way it was written, or the session itself, never renews.
func TestSigningRenewalNeedsTheSessionToBeTheSignatures(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	stranger := sessionReader(t, rig.db, "stranger")
	due := rig.sig("Legacy", 9*day)

	for _, tc := range []struct {
		name    string
		sig     string
		session string
		refused bool
	}{
		{"another reader's signature", sign("Legacy", stranger, nil, DefaultSignatureDuration-9*day), session, false},
		{"no session cookie, the old shape of login", due, "", false},
		{"a signature that does not check out", tampered(due), session, true},
	} {
		got := rig.page(browser(tc.sig, tc.session)...)
		if rig.stub.calls() != 0 {
			t.Errorf("%s: %d refreshes, want none", tc.name, rig.stub.calls())
		}
		if tc.refused {
			if got.reached || len(got.rec.Header().Values("Set-Cookie")) != 0 {
				t.Errorf("%s: reached %v, Set-Cookie %q; want it refused as before", tc.name, got.reached, got.rec.Header().Values("Set-Cookie"))
			}
			continue
		}
		rig.wantUntouched(got, tc.sig)
	}

	// A session nobody holds cannot renew, and its cookie goes
	req := rig.request(http.MethodGet, "/limited", browser(due, "not-a-session-id")...)
	rig.wantSessionDropped(rig.serve(req, false), req, due)
	if rig.stub.calls() != 0 {
		t.Errorf("a session nobody holds: %d refreshes, want none", rig.stub.calls())
	}

	// A signature written under another secret
	t.Setenv("BAN_SECRET", "another-secret")
	got := rig.page(browser(due, session)...)
	if got.reached || rig.stub.calls() != 0 {
		t.Errorf("a signature from another secret reached %v after %d refreshes", got.reached, rig.stub.calls())
	}
	rows := rig.rows()
	if len(rows) != 1 || rows[0].token != "refresh-0" {
		t.Errorf("rows %+v, want the session untouched", rows)
	}
}

// A POST in the window renews, and so does a script's fetch of /data/.
func TestSigningRenewsOnAPostAndOnADataRoute(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	installAccess(t, `{"Legacy":{"Upload":{}}}`, `[]`)
	session := rig.session("")

	old := rig.sig("Legacy", 9*day)
	post := rig.serve(rig.request(http.MethodPost, "/upload", browser(old, session)...), false)
	rig.wantRenewed(post, old, session)

	old = rig.sig("Legacy", 10*day)
	data := rig.serve(rig.request(http.MethodGet, "/data/prices/x", browser(old, session)...), true)
	rig.wantRenewed(data, old, session)
}

// Of every request at once that finds the signature due, from one device or
// several, one asks Patreon; the others are served on the old signature, and
// every session ends on the new token.
func TestSigningRenewalIsSingleFlightAcrossDevices(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.delay = 300 * time.Millisecond
	devices := []string{rig.session(""), rig.session("")}
	old := rig.sig("Legacy", 9*day)

	const requests = 6
	results := make([]*served, requests)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			results[i] = rig.serve(rig.request(http.MethodGet, "/limited", browser(old, devices[i%len(devices)])...), false)
		})
	}
	wg.Wait()

	renewed := 0
	for _, got := range results {
		if !got.reached {
			t.Error("a request was not served")
		}
		if len(got.rec.Result().Cookies()) == 2 {
			renewed++
		} else if len(got.rec.Header().Values("Set-Cookie")) != 0 || got.sig != old {
			t.Errorf("a request that lost the lease set %q and read a new signature: %v", got.rec.Header().Values("Set-Cookie"), got.sig != old)
		}
	}
	if renewed != 1 || rig.stub.calls() != 1 {
		t.Errorf("%d requests renewed after %d refreshes, want one each", renewed, rig.stub.calls())
	}
	for _, row := range rig.rows() {
		if row.token != rig.stub.liveToken() {
			t.Errorf("session %s holds %q, but Patreon honours %q", row.id, row.token, rig.stub.liveToken())
		}
	}
}

// A lease whose holder died, as it runs out, is taken over by the next
// request; one still running holds the others off.
func TestSigningRenewalLeaseOutlivesItsHolderForAMinute(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	_, _, leased, err := rig.db.LeasePatreonSessions(t.Context(), session, rig.hash, "client-id", time.Minute)
	if err != nil || !leased {
		t.Fatalf("lease: %v %v", leased, err)
	}
	rig.wantUntouched(rig.page(browser(old, session)...), old)
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes while another request held the lease, want none", rig.stub.calls())
	}

	// The holder is gone and its minute is up, here as on the site that
	// remembered the refusal
	_, err = rig.db.DB().ExecContext(t.Context(), `UPDATE patreon_sessions SET renew_after = now() - interval '1 second' WHERE session_id = $1`, session)
	if err != nil {
		t.Fatal(err)
	}
	forgetRests(t)
	rig.wantRenewed(rig.page(browser(old, session)...), old, session)
}

// A reader logged out everywhere while their renewal waited on Patreon is
// not signed in again: the commit finds the sessions gone and nothing is set.
func TestSigningRenewalStopsWhenTheSessionsAreGone(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)
	rig.stub.beforeToken = func() {
		_, err := rig.db.DeletePatreonSessions(t.Context(), rig.hash)
		if err != nil {
			t.Error(err)
		}
	}

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	rows := rig.rows()
	if len(rows) != 0 {
		t.Errorf("rows %+v, want none", rows)
	}
	if !strings.Contains(rig.logged.String(), "verdict=sessions gone") {
		t.Errorf("admin log %q does not say the sessions were gone", rig.logged.String())
	}
}

// A reader who logs out here while their renewal waits on Patreon is not
// signed in again, though another device's session still holds the lease,
// nor re-signed for an access table or grant edit the signature predates;
// the other session takes the token Patreon rotated to.
func TestSigningRenewalStopsWhenItsOwnSessionIsGone(t *testing.T) {
	for _, edit := range []string{"none", "acl", "grant"} {
		t.Run(edit, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			switch edit {
			case "acl":
				pokes.StampACL(time.Now())
			case "grant":
				pokes.StampGrant(rig.hash, time.Now(), DefaultSignatureDuration)
			}
			session := rig.session("")
			other := rig.session("")
			old := rig.sig("Legacy", 9*day)
			rig.stub.beforeToken = func() {
				logout := httptest.NewRecorder()
				rig.site.Home(logout, rig.request(http.MethodGet, "/?errmsg=logout", browser(old, session)...))
			}

			rig.wantUntouched(rig.page(browser(old, session)...), old)
			rows := rig.rows()
			if len(rows) != 1 || rows[0].id != other || rows[0].token != rig.stub.liveToken() {
				t.Errorf("rows %+v, want only the other device's, holding %s", rows, rig.stub.liveToken())
			}
			if !strings.Contains(rig.logged.String(), "verdict=session gone") {
				t.Errorf("admin log %q does not say this browser's session was gone", rig.logged.String())
			}
		})
	}
}

// A logout that lands before the renewal leases the session is not undone
// either: the request clears the session cookie and sets no signature.
func TestSigningRenewalStopsWhenItsSessionIsGoneBeforeTheLease(t *testing.T) {
	for _, edit := range []string{"none", "acl", "grant"} {
		t.Run(edit, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			switch edit {
			case "acl":
				pokes.StampACL(time.Now())
			case "grant":
				pokes.StampGrant(rig.hash, time.Now(), DefaultSignatureDuration)
			}
			session := rig.session("")
			old := rig.sig("Legacy", 9*day)
			logout := httptest.NewRecorder()
			rig.site.Home(logout, rig.request(http.MethodGet, "/?errmsg=logout", browser(old, session)...))

			req := rig.request(http.MethodGet, "/limited", browser(old, session)...)
			rig.wantSessionDropped(rig.serve(req, false), req, old)
			if rig.stub.calls() != 0 {
				t.Errorf("%d refreshes for a session that is gone, want none", rig.stub.calls())
			}
		})
	}
}

// A logout is not undone by the re-sign a young signature gets for an edit
// either: a request still holding the session it ended clears that cookie and
// sets no signature.
func TestSigningReSignStopsWhenItsSessionIsGone(t *testing.T) {
	for _, edit := range []string{"acl", "grant"} {
		t.Run(edit, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			session := rig.session("")
			young := rig.sig("Legacy", 1*day)
			switch edit {
			case "acl":
				pokes.StampACL(time.Now())
			case "grant":
				pokes.StampGrant(rig.hash, time.Now(), DefaultSignatureDuration)
			}
			logout := httptest.NewRecorder()
			rig.site.Home(logout, rig.request(http.MethodGet, "/?errmsg=logout", browser(young, session)...))

			req := rig.request(http.MethodGet, "/limited", browser(young, session)...)
			rig.wantSessionDropped(rig.serve(req, false), req, young)
			if !strings.Contains(rig.logged.String(), "cause="+edit+" verdict=session gone") {
				t.Errorf("admin log %q does not say the session was gone", rig.logged.String())
			}
		})
	}
}

// A database that cannot say whether the session stands costs the reader the
// edit no more than at the lease: the young signature is re-signed.
func TestSigningReSignsWithTheDatabaseDown(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.StampACL(time.Now())
	rig.db.Close()

	rig.wantReminted(rig.page(browser(young, session)...), young)
	if !strings.Contains(rig.logged.String(), "standing") {
		t.Errorf("admin log %q does not name the failure", rig.logged.String())
	}
}

// A reader who navigates away while their signature renews does not cost the
// session its token: Patreon rotated it, so the renewal finishes and stores it.
func TestSigningRenewalFinishesWhenTheReaderLeaves(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	req := rig.request(http.MethodGet, "/limited", browser(old, session)...)
	ctx, leave := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	rig.stub.beforeToken = leave
	rig.serve(req, false)

	rows := rig.rows()
	if len(rows) != 1 || rows[0].token != rig.stub.liveToken() || rig.stub.liveToken() == "refresh-0" {
		t.Errorf("rows %+v with Patreon honouring %q, want the session holding the rotated token", rows, rig.stub.liveToken())
	}
}

// A database that cannot be reached costs the reader nothing: they are served
// on the signature they have, with no cookie changed, and the log names the
// failure without a token.
func TestSigningRenewalWithTheDatabaseDown(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	spare := openUserStateClient(t)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)
	rig.db.Close()

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes without a database, want none", rig.stub.calls())
	}
	if !strings.Contains(rig.logged.String(), "lease") {
		t.Errorf("admin log %q does not name the failure", rig.logged.String())
	}
	rows := sessionRowsOf(t, spare, rig.hash)
	if len(rows) != 1 || rows[0].token != "refresh-0" {
		t.Errorf("rows %+v, want the session untouched", rows)
	}
	rig.wantNoTokens()
}

// A database that fails after Patreon rotated the token cannot store it: the
// signature is not re-issued, the reader is served on the one they have, and
// the session keeps the token that is dead now, so it renews no more.
func TestSigningRenewalWhenTheRotatedTokenCannotBeStored(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	spare := openUserStateClient(t)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)
	rig.stub.beforeToken = func() { rig.db.Close() }

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	rows := sessionRowsOf(t, spare, rig.hash)
	if len(rows) != 1 || rows[0].token != "refresh-0" || rig.stub.liveToken() == "refresh-0" {
		t.Errorf("rows %+v with Patreon honouring %q, want the session left with the dead token", rows, rig.stub.liveToken())
	}
	if !strings.Contains(rig.logged.String(), "commit") {
		t.Errorf("admin log %q does not name the failure", rig.logged.String())
	}
	rig.wantNoTokens()
}

// Each thing the renewal needs, missing alone, leaves it off: the reader is
// served as ever and Patreon is not asked.
func TestSigningRenewalNeedsEveryPiece(t *testing.T) {
	for _, tc := range []struct {
		name string
		turn string
	}{
		{"after_days 0", "block"},
		{"no database", "database"},
		{"signatures unchecked", "sigcheck"},
		{"no Patreon client id", "client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			session := rig.session("")
			old := rig.sig("Legacy", 9*day)
			switch tc.turn {
			case "block":
				renewalConfig(t, infrastructure.PatreonRenewal{GraceDays: 3, ClearOnNegative: true}, "client-id")
			case "database":
				UserStateDB = nil
			case "sigcheck":
				SigCheck = false
			case "client":
				renewalConfig(t, renewalBlock, "")
			}

			rig.wantUntouched(rig.page(browser(old, session)...), old)
			if rig.stub.calls() != 0 {
				t.Errorf("%d refreshes, want none", rig.stub.calls())
			}
			rows := rig.rows()
			if len(rows) != 1 || rows[0].token != "refresh-0" || rig.restingFor(session) > 0 {
				t.Errorf("rows %+v, want the session untouched", rows)
			}
		})
	}
}

// A signature younger than after_days costs the database nothing: not a
// lease, not a read.
func TestSigningLeavesAYoungSignatureAlone(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	old := rig.sig("Legacy", 7*day)

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	if rig.stub.calls() != 0 || rig.restingFor(session) > 0 {
		t.Errorf("%d refreshes, session resting %.0fs; want none and a session left alone", rig.stub.calls(), rig.restingFor(session))
	}
}

// The refresh waits longer than renew_timeout_seconds gives the lookups: an
// answer given up on after Patreon rotated the token would leave the
// sessions holding a dead one.
func TestSigningRenewalWaitsOutASlowRefresh(t *testing.T) {
	block := renewalBlock
	block.RenewTimeoutSeconds = 1
	rig := newRenewalRig(t, block)
	rig.stub.delay = 1500 * time.Millisecond
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	rig.wantRenewed(rig.page(browser(old, session)...), old, session)
	rows := rig.rows()
	if len(rows) != 1 || rows[0].token != rig.stub.liveToken() || rig.stub.liveToken() == "refresh-0" {
		t.Errorf("rows %+v with Patreon honouring %q, want the session holding the rotated token", rows, rig.stub.liveToken())
	}
}

// A request already on its way with the signature just renewed, due or run
// out within grace, is served on the signature that renewal minted, and does
// not ask Patreon again.
func TestSigningRenewalServesARequestInFlightTheNewSignature(t *testing.T) {
	for name, age := range map[string]time.Duration{"due": 9 * day, "within grace": 11*day + 2*time.Hour} {
		t.Run(name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			session := rig.session("")
			old := rig.sig("Legacy", age)

			fresh := rig.wantRenewed(rig.page(browser(old, session)...), old, session)
			sibling := rig.page(browser(old, session)...)
			cookie := setCookies(sibling.rec)[signatureCookie]
			if !sibling.reached || sibling.sig != fresh || cookie == nil || cookie.Value != fresh {
				t.Errorf("the request in flight reached %v on the new signature %v, cookie %v; want it served and set the new one", sibling.reached, sibling.sig == fresh, cookie != nil && cookie.Value == fresh)
			}
			if rig.stub.calls() != 1 {
				t.Errorf("%d refreshes, want the one", rig.stub.calls())
			}
		})
	}
}

// A request that arrives while its signature's renewal is still running loses
// the lease and is served as such a request is: a due signature on itself, one
// run out within grace logged out. Only one arriving after the renewal answered
// is served the new signature.
func TestSigningRenewalServesARequestDuringItAsALostLease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		age    time.Duration
		served bool
	}{
		{"due", 9 * day, true},
		{"within grace", 11*day + 2*time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			session := rig.session("")
			old := rig.sig("Legacy", tc.age)
			var during *served
			rig.stub.beforeToken = func() { during = rig.page(browser(old, session)...) }

			rig.wantRenewed(rig.page(browser(old, session)...), old, session)
			if during == nil || during.reached != tc.served || len(during.rec.Result().Cookies()) != 0 {
				t.Fatalf("the request during the renewal: %+v, want reached %v with no cookie set", during, tc.served)
			}
			if tc.served && during.sig != old {
				t.Error("a due request during the renewal was not served on its own signature")
			}
			if rig.stub.calls() != 1 {
				t.Errorf("%d refreshes, want the one", rig.stub.calls())
			}
		})
	}
}

// After a renewal files the sessions under a changed email, the reader's other
// devices, whose signatures name the old one, cannot renew: they are served on
// what they have, and are not asked about again for an hour.
func TestSigningRenewalLeavesTheOtherDevicesOfAChangedEmail(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	spare := openUserStateClient(t)
	rig.stub.email = fmt.Sprintf("moved-%d@example.com", time.Now().UnixNano())
	newHash := userstate.HashEmail(rig.stub.email)
	t.Cleanup(func() {
		// t.Context() is already canceled when a cleanup runs
		_, err := spare.DeletePatreonSessions(context.Background(), newHash)
		if err != nil {
			t.Error(err)
		}
	})
	laptop, phone := rig.session(""), rig.session("")
	onLaptop, onPhone := rig.sig("Legacy", 9*day), rig.sig("Legacy", 10*day)

	rig.wantRenewed(rig.page(browser(onLaptop, laptop)...), onLaptop, laptop)
	rig.wantUntouched(rig.page(browser(onPhone, phone)...), onPhone)
	rig.db.Close()
	before := rig.logged.String()
	rig.wantUntouched(rig.page(browser(onPhone, phone)...), onPhone)
	if rig.logged.String() != before || rig.stub.calls() != 1 {
		t.Errorf("the phone asked again after %d refreshes: %q", rig.stub.calls(), strings.TrimPrefix(rig.logged.String(), before))
	}
}

// A device refused while another renewal holds the lease is not kept from
// asking again: once that renewal commits, it renews at its next request.
func TestSigningRenewalAsksAgainOnceAnotherRenewalCommits(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	laptop, phone := rig.session(""), rig.session("")
	onPhone := rig.sig("Legacy", 9*day)

	_, fence, leased, err := rig.db.LeasePatreonSessions(t.Context(), laptop, rig.hash, "client-id", time.Minute)
	if err != nil || !leased {
		t.Fatalf("lease: %v %v", leased, err)
	}
	rig.wantUntouched(rig.page(browser(onPhone, phone)...), onPhone)

	// The laptop's renewal commits the token Patreon rotated to
	rig.stub.spend("refresh-laptop")
	_, err = rig.db.CommitPatreonSessions(t.Context(), fence, rig.hash, "refresh-laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	rig.wantRenewed(rig.page(browser(onPhone, phone)...), onPhone, phone)
}

// A session whose account rests is not asked about again until the rest is
// over: a due reader costs the database one lease and one look per rest,
// not one per request.
func TestSigningRenewalRemembersASessionThatRests(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	spare := openUserStateClient(t)
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)
	_, err := rig.db.DB().ExecContext(t.Context(), `UPDATE patreon_sessions SET renew_after = now() + interval '1 hour' WHERE session_id = $1`, session)
	if err != nil {
		t.Fatal(err)
	}

	rig.wantUntouched(rig.page(browser(old, session)...), old)
	// The database is gone: a request that asked it would log the failure
	rig.db.Close()
	before := rig.logged.String()
	rig.wantUntouched(rig.page(browser(old, session)...), old)
	if rig.logged.String() != before {
		t.Errorf("a resting session asked the database again: %q", strings.TrimPrefix(rig.logged.String(), before))
	}
	if rows := sessionRowsOf(t, spare, rig.hash); len(rows) != 1 {
		t.Errorf("rows %+v, want the session kept", rows)
	}
}

// A refresh token Patreon refused ends only the sessions that hold it: one
// that another renewal left holding a live token stays, and renews.
func TestSigningRenewalRevokesOnlyTheDeadToken(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	live := rig.session("")
	dead := rig.session("refresh-dead")
	old := rig.sig("Legacy", 9*day)

	req := rig.request(http.MethodGet, "/limited", browser(old, dead)...)
	rig.wantSessionDropped(rig.serve(req, false), req, old)
	rows := rig.rows()
	if len(rows) != 1 || rows[0].id != live {
		t.Fatalf("rows %+v, want only the session holding the live token", rows)
	}

	// The lease the refusal took runs out, and the other device renews
	_, err := rig.db.DB().ExecContext(t.Context(), `UPDATE patreon_sessions SET renew_after = now() WHERE session_id = $1`, live)
	if err != nil {
		t.Fatal(err)
	}
	rig.wantRenewed(rig.page(browser(old, live)...), old, live)
}
