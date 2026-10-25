package main

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/userstate"
)

// A signature too young to renew is renewed in the request that follows its
// reader's poke, on the tier Patreon reports then, and the new signature, issued
// after the poke, is left alone: the next request on it leaves Patreon alone.
func TestSigningRenewsAPokedReaderOnTheNextRequest(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.title = "VINTAGE"
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)

	// Nobody poked: a young signature is left alone
	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 {
		t.Fatalf("%d refreshes for a signature nobody poked, want none", rig.stub.calls())
	}

	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
	got := rig.page(browser(young, session)...)
	fresh := rig.wantRenewed(got, young, session)
	tier := GetParamFromSig(got.sig, "UserTier")
	if tier != "Vintage" || GetParamFromSig(fresh, "UserTier") != "Vintage" {
		t.Errorf("the page was served at %q, want the new tier Vintage", tier)
	}
	if rig.stub.calls() != 1 {
		t.Errorf("%d refreshes, want 1", rig.stub.calls())
	}

	rig.wantUntouched(rig.page(browser(fresh, session)...), fresh)
	if rig.stub.calls() != 1 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes for the renewed signature, poked %v; want still 1 and the poke kept for the other devices", rig.stub.calls(), pokes.Poked(rig.hash, time.Now(), pokeWindow()))
	}
}

// A poke is per reader, and a reader has several devices: each signature issued
// before the poke renews once, at its own next request, whichever renewed first.
func TestSigningPokeRenewsEveryDeviceOnce(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.title = "VINTAGE"
	laptop, phone := rig.session(""), rig.session("")
	onLaptop, onPhone := rig.sig("Legacy", 1*day), rig.sig("Legacy", 2*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	freshLaptop := rig.wantRenewed(rig.page(browser(onLaptop, laptop)...), onLaptop, laptop)
	freshPhone := rig.wantRenewed(rig.page(browser(onPhone, phone)...), onPhone, phone)
	if rig.stub.calls() != 2 || GetParamFromSig(freshPhone, "UserTier") != "Vintage" {
		t.Errorf("%d refreshes, phone renewed at %q; want one per device at the new tier", rig.stub.calls(), GetParamFromSig(freshPhone, "UserTier"))
	}

	rig.wantUntouched(rig.page(browser(freshLaptop, laptop)...), freshLaptop)
	rig.wantUntouched(rig.page(browser(freshPhone, phone)...), freshPhone)
	if rig.stub.calls() != 2 {
		t.Errorf("%d refreshes after both devices renewed, want still 2", rig.stub.calls())
	}
	rig.wantNoTokens()
}

// A poke is only for the reader it names.
func TestSigningPokeOfAnotherReaderRenewsNobodyElse(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	stranger := sessionReader(t, rig.db, "stranger")

	pokes.Poke(userstate.HashEmail(stranger.Email), time.Now(), pokeWindow())
	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 || !pokes.Poked(userstate.HashEmail(stranger.Email), time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes, stranger poked %v; want none and the stranger's poke kept", rig.stub.calls(), pokes.Poked(userstate.HashEmail(stranger.Email), time.Now(), pokeWindow()))
	}
}

// A poke renews whatever the reader's signature has left, a script's fetch of
// /data/ and a POST included, and one that ran out within grace_days by the
// grace path it is.
func TestSigningPokeRenewsWhateverTheSignatureHasLeft(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	installAccess(t, `{"Legacy":{"Upload":{}}}`, `[]`)
	session := rig.session("")

	for _, age := range map[string]time.Duration{
		"minted a moment ago": time.Minute,
		"a week old":          7 * day,
		"about to run out":    11*day - time.Minute,
		"ran out an hour ago": 11*day + time.Hour,
	} {
		pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
		old := rig.sig("Legacy", age)
		got := rig.page(browser(old, session)...)
		rig.wantRenewed(got, old, session)
	}

	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
	old := rig.sig("Legacy", 1*day)
	rig.wantRenewed(rig.serve(rig.request(http.MethodPost, "/upload", browser(old, session)...), false), old, session)

	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
	old = rig.sig("Legacy", 2*day)
	rig.wantRenewed(rig.serve(rig.request(http.MethodGet, "/data/prices/x", browser(old, session)...), true), old, session)
}

// A poke or a stamp lifts the age check and nothing else: where the signature
// or its session could not renew on age, they cannot on either, nothing is set,
// and a poke waits for a request that can.
func TestSigningPokeAndStampCannotRenewWhatAgeCannot(t *testing.T) {
	young := 1 * day
	readers := func(rig *renewalRig, age time.Duration) string { return rig.sig("Legacy", age) }
	invite := func(_ *renewalRig, age time.Duration) string {
		return sign("Legacy", nil, nil, DefaultSignatureDuration-age)
	}
	for _, tc := range []struct {
		name    string
		age     time.Duration
		sig     func(rig *renewalRig, age time.Duration) string
		session bool
		query   bool
	}{
		{"no session cookie", young, readers, false, false},
		{"a ?sig=", young, readers, true, true},
		{"a signature past the end of grace_days", 14*day + time.Hour, readers, true, false},
		{"an invite, which names nobody", young, invite, true, false},
	} {
		for _, lift := range []string{"a poke", "a stamp"} {
			t.Run(lift+", "+tc.name, func(t *testing.T) {
				rig := newRenewalRig(t, renewalBlock)
				pokes := freshPokes(t)
				session := rig.session("")
				if lift == "a poke" {
					pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
					// A hash of no email is what an invite would be poked by; nothing
					// legitimate pokes it
					pokes.Poke(userstate.HashEmail(""), time.Now(), pokeWindow())
				} else {
					pokes.StampACL(time.Now())
				}
				sig := tc.sig(rig, tc.age)

				cookies := browser(sig, "")
				if tc.session {
					cookies = browser(sig, session)
				}
				target := "/limited"
				if tc.query {
					target += "?sig=" + url.QueryEscape(sig)
					cookies = browser("", session)
				}
				got := rig.serve(rig.request(http.MethodGet, target, cookies...), false)

				if rig.stub.calls() != 0 {
					t.Errorf("%d refreshes, want none", rig.stub.calls())
				}
				if setCookies(got.rec)[sessionCookie] != nil {
					t.Errorf("Set-Cookie %q, want the session cookie left alone", got.rec.Header().Values("Set-Cookie"))
				}
				if lift == "a poke" && !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
					t.Error("the poke was spent on a request that renewed nothing")
				}
				rows := rig.rows()
				if len(rows) != 1 || rows[0].token != "refresh-0" || rig.restingFor(session) > 0 {
					t.Errorf("rows %+v, want the session untouched", rows)
				}
			})
		}
	}
}

// A signature that does not check out is refused as it ever was, poked or not.
func TestSigningPokeDoesNotRenewASignatureThatDoesNotCheckOut(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	got := rig.page(browser(tampered(rig.sig("Legacy", 1*day)), session)...)
	if got.reached || len(got.rec.Header().Values("Set-Cookie")) != 0 || rig.stub.calls() != 0 {
		t.Errorf("reached %v, Set-Cookie %q after %d refreshes; want it refused as before", got.reached, got.rec.Header().Values("Set-Cookie"), rig.stub.calls())
	}
}

// Each thing the renewal needs, missing alone, leaves a poke without effect.
func TestSigningPokeNeedsEveryPieceOfRenewal(t *testing.T) {
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
			pokes := freshPokes(t)
			session := rig.session("")
			pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
			young := rig.sig("Legacy", 1*day)
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

			rig.wantUntouched(rig.page(browser(young, session)...), young)
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

// A poke the age window has outlived renews nothing: the window would have
// caught the reader by then.
func TestSigningPokeThatLapsedRenewsNothing(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	pokes.Poke(rig.hash, time.Now().Add(-8*day-time.Minute), pokeWindow())
	young := rig.sig("Legacy", 1*day)

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 {
		t.Errorf("%d refreshes for a lapsed poke, want none", rig.stub.calls())
	}
}

// While Patreon gives no answer the poke stays: the sessions rest an hour, a
// request inside it costs Patreon nothing, and the first request after it
// renews once Patreon is back.
func TestSigningPokeSurvivesPatreonBeingDown(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.token = &stubAnswer{http.StatusInternalServerError, `{"errors":[{"title":"boom"}]}`}
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Fatal("the poke went while Patreon was down")
	}
	wait := rig.restingFor(session)
	if wait < 59*60 || wait > 61*60 {
		t.Errorf("sessions rest %.0fs, want an hour", wait)
	}

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 1 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes inside the backoff, poked %v; want 1 and the poke kept", rig.stub.calls(), pokes.Poked(rig.hash, time.Now(), pokeWindow()))
	}

	// The hour is up and Patreon is back
	rig.stub.token = nil
	_, err := rig.db.DB().ExecContext(t.Context(), `UPDATE patreon_sessions SET renew_after = now() WHERE session_id = $1`, session)
	if err != nil {
		t.Fatal(err)
	}
	forgetRests(t)
	fresh := rig.wantRenewed(rig.page(browser(young, session)...), young, session)
	rig.wantUntouched(rig.page(browser(fresh, session)...), fresh)
	if rig.stub.calls() != 2 {
		t.Errorf("%d refreshes once Patreon was back, want 2 in all", rig.stub.calls())
	}
}

// A request that loses the lease leaves the poke for the one that holds it, or
// the next.
func TestSigningPokeSurvivesALostLease(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	_, _, leased, err := rig.db.LeasePatreonSessions(t.Context(), session, rig.hash, "client-id", time.Minute)
	if err != nil || !leased {
		t.Fatalf("lease: %v %v", leased, err)
	}
	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes, poked %v; want none and the poke kept", rig.stub.calls(), pokes.Poked(rig.hash, time.Now(), pokeWindow()))
	}
}

// pledge:delete is the same poke: with clear_on_negative on, the reader's next
// request on each device finds nothing pledged and logs that device out.
// Without it the answer is treated as none, and the poke waits.
func TestSigningPokeAfterAPledgeDeleteLogsTheReaderOut(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.title = ""
	here := rig.session("")
	elsewhere := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	req := rig.request(http.MethodGet, "/limited", browser(young, here)...)
	got := rig.serve(req, false)
	body := got.rec.Body.String()
	if got.reached || !strings.Contains(body, html.EscapeString(ErrMsgExpired)) || !strings.Contains(body, "Log in") {
		t.Errorf("reached %v, page offers the logged-out message and the login: %v", got.reached, strings.Contains(body, html.EscapeString(ErrMsgExpired)))
	}
	checkLogoutClears(t, got.rec, map[string]*http.Cookie{
		signatureCookie: signatureCookieFor(req, signatureCookie, "x", time.Now()),
		sessionCookie:   sessionCookieFor(req, "x", 1),
	})
	rows := rig.rows()
	if len(rows) != 1 || rows[0].id != elsewhere {
		t.Errorf("rows %+v, want only the other device's", rows)
	}

	// The other device is logged out at its own next request
	got = rig.serve(rig.request(http.MethodGet, "/limited", browser(young, elsewhere)...), false)
	if got.reached || !strings.Contains(got.rec.Body.String(), html.EscapeString(ErrMsgExpired)) || len(rig.rows()) != 0 {
		t.Errorf("the other device: reached %v, logged out %v, rows %+v; want it logged out too", got.reached, strings.Contains(got.rec.Body.String(), html.EscapeString(ErrMsgExpired)), rig.rows())
	}
	if rig.stub.calls() != 2 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes, poked %v; want one per device and the poke kept", rig.stub.calls(), pokes.Poked(rig.hash, time.Now(), pokeWindow()))
	}
	rig.wantNoTokens()
}

// Without clear_on_negative a delete changes nothing the reader sees, and the
// poke waits for the hour to be up.
func TestSigningPokeAfterAPledgeDeleteWithoutClearOnNegativeKeepsTheReader(t *testing.T) {
	rig := newRenewalRig(t, infrastructure.PatreonRenewal{AfterDays: 8, GraceDays: 3})
	pokes := freshPokes(t)
	rig.stub.title = ""
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if !pokes.Poked(rig.hash, time.Now(), pokeWindow()) || rig.restingFor(session) < 59*60 {
		t.Errorf("poked %v, resting %.0fs; want the poke kept and an hour's rest", pokes.Poked(rig.hash, time.Now(), pokeWindow()), rig.restingFor(session))
	}
}

// Refresh now answers a poke too: the signature it mints is issued after the
// poke, so this browser's next request leaves Patreon alone, while the poke
// stays for the reader's other devices.
func TestRefreshNowAnswersAPoke(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	rec := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, rec, "/user?refreshed=yes")
	fresh := setCookies(rec)[signatureCookie]
	if fresh == nil || fresh.Value == young || rig.stub.calls() != 1 {
		t.Fatalf("Refresh now set %v after %d refreshes, want a new signature from one", fresh, rig.stub.calls())
	}

	rig.wantUntouched(rig.page(browser(fresh.Value, session)...), fresh.Value)
	if rig.stub.calls() != 1 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
		t.Errorf("%d refreshes for the refreshed signature, poked %v; want still 1 and the poke kept", rig.stub.calls(), pokes.Poked(rig.hash, time.Now(), pokeWindow()))
	}
}

// wantReminted fails unless the request was served on a signature re-signed
// from old under the access table now: the same reader, tier and Expires, set
// alone in the cookie, with Patreon not asked; the same signature, where the
// table gives the same flags. It returns the new signature.
func (rig *renewalRig) wantReminted(got *served, old string) string {
	rig.t.Helper()
	set := setCookies(got.rec)
	fresh := set[signatureCookie]
	if len(got.rec.Result().Cookies()) != 1 || fresh == nil {
		rig.t.Fatalf("Set-Cookie %q, want %s alone", got.rec.Header().Values("Set-Cookie"), signatureCookie)
	}
	_, valid := signatureIsValid(fresh.Value)
	if !valid || !got.reached || got.sig != fresh.Value {
		rig.t.Errorf("cookie valid %v, handler reached %v on it %v; want a valid signature served", valid, got.reached, got.sig == fresh.Value)
	}
	for _, key := range []string{"Expires", "UserEmail", "UserName", "UserTier"} {
		if GetParamFromSig(fresh.Value, key) != GetParamFromSig(old, key) {
			rig.t.Errorf("%s %q, want the old signature's %q", key, GetParamFromSig(fresh.Value, key), GetParamFromSig(old, key))
		}
	}
	if rig.stub.calls() != 0 {
		rig.t.Errorf("%d refreshes, want Patreon left alone", rig.stub.calls())
	}
	return fresh.Value
}

// An edit of the access table reaches a reader on their next request: the
// signature, young as it is, is re-signed under the table as it is now, the
// page flag the edit turned on comes with it, nothing else changes, and the
// re-signed signature is left alone. A browser with no session is reached
// too, since nothing is asked of Patreon.
func TestSigningReSignsAfterAnACLEdit(t *testing.T) {
	for name, withSession := range map[string]bool{"with a session": true, "without one": false} {
		t.Run(name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			freshPokes(t)
			files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)
			session := ""
			if withSession {
				session = rig.session("")
			}
			young := rig.sig("Legacy", 1*day)
			if GetParamFromSig(young, "Upload") != "" {
				t.Fatal("the signature was minted with the flag the edit is to turn on")
			}

			// Nothing edited
			rig.wantUntouched(rig.page(browser(young, session)...), young)

			files.set("acl", `{"Legacy":{"Search":{},"Upload":{}}}`)
			err := reloadACL(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			got := rig.page(browser(young, session)...)
			fresh := rig.wantReminted(got, young)
			if GetParamFromSig(fresh, "Upload") != "true" {
				t.Errorf("the page was served with Upload %q, want the flag the edit turned on", GetParamFromSig(fresh, "Upload"))
			}
			if !strings.Contains(rig.logged.String(), "cause=acl verdict=reminted") {
				t.Errorf("admin log %q does not tell the cause", rig.logged.String())
			}
			rig.wantUntouched(rig.page(browser(fresh, session)...), fresh)
		})
	}
}

// The stamp asks for the signatures issued before it and no others, however
// young or old they are, and an age that is due renews for its age.
func TestSigningStampReSignsOnlyWhatWasIssuedBeforeIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		cause string // none when the signature is left alone
	}{
		{"issued after the edit", 1 * day, ""},
		{"issued a minute after the edit", 2*day - time.Minute, ""},
		{"issued a minute before the edit", 2*day + time.Minute, "acl"},
		{"issued a week before the edit", 7 * day, "acl"},
		{"due for its age as well", 9 * day, "due"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			session := rig.session("")
			old := rig.sig("Legacy", tc.age)
			pokes.StampACL(time.Now().Add(-2 * day))

			got := rig.page(browser(old, session)...)
			switch tc.cause {
			case "":
				rig.wantUntouched(got, old)
				if rig.stub.calls() != 0 || rig.restingFor(session) > 0 {
					t.Errorf("%d refreshes, session resting %.0fs; want none and a session left alone", rig.stub.calls(), rig.restingFor(session))
				}
			case "acl":
				rig.wantReminted(got, old)
			default:
				rig.wantRenewed(got, old, session)
				if !strings.Contains(rig.logged.String(), "cause="+tc.cause+" verdict=entitled") {
					t.Errorf("admin log %q, want cause=%s", rig.logged.String(), tc.cause)
				}
			}
		})
	}
}

// An edit of the access table asks Patreon nothing, so Patreon being down
// neither keeps the edit from the reader nor rests their sessions.
func TestSigningStampReSignsWithPatreonDown(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.token = &stubAnswer{http.StatusInternalServerError, `{"errors":[{"title":"boom"}]}`}
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	pokes.StampACL(time.Now())

	fresh := rig.wantReminted(rig.page(browser(young, session)...), young)
	if rig.restingFor(session) > 0 {
		t.Errorf("sessions rest %.0fs, want them left alone", rig.restingFor(session))
	}
	rig.wantUntouched(rig.page(browser(fresh, session)...), fresh)
}

// A reader both poked and behind an edit of the access table, in a browser
// with no session to renew from, is re-signed for the edit all the same.
func TestSigningStampReSignsAPokedReaderWithoutASession(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)
	young := rig.sig("Legacy", 1*day)
	pokes.Poke(rig.hash, time.Now().Add(-time.Hour), pokeWindow())
	files.set("acl", `{"Legacy":{"Search":{},"Upload":{}}}`)
	err := reloadACL(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	fresh := rig.wantReminted(rig.page(browser(young, "")...), young)
	if GetParamFromSig(fresh, "Upload") != "true" {
		t.Errorf("re-signed with Upload %q, want the flag the edit turned on", GetParamFromSig(fresh, "Upload"))
	}
}

// A grant edit reaches the grantee on their next request, whichever way the
// site came to know of it, and their neighbours are left alone: the tier and
// the flags come from the grant as it is now.
func TestSigningRenewsAGrantedReaderWhoseGrantChanged(t *testing.T) {
	for _, via := range []string{"a reload", "a save"} {
		t.Run(via, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			rig.stub.membership = false
			grants := func(tier string) string {
				return `[` + grantFor(rig.user.Email, tier) + `,` + grantFor("neighbour@example.com", "Legacy") + `]`
			}
			files := loadAccessFiles(t, `{"Legacy":{"Search":{}},"Vintage":{"Search":{},"Upload":{}}}`, grants("Legacy"))
			session := rig.session("")
			young := rig.sig("Legacy", 1*day)
			rig.wantUntouched(rig.page(browser(young, session)...), young)

			var err error
			if via == "a reload" {
				files.set("grants", grants("Vintage"))
				err = reloadGrants(t.Context())
			} else {
				edited := slices.Clone(PatreonGrants())
				edited[0].Tier = "Vintage"
				err = saveGrants(t.Context(), edited)
			}
			if err != nil {
				t.Fatal(err)
			}
			if pokes.Len() != 1 || !pokes.Poked(rig.hash, time.Now(), pokeWindow()) {
				t.Fatalf("%d poked, want only the grantee", pokes.Len())
			}

			got := rig.page(browser(young, session)...)
			fresh := rig.wantRenewed(got, young, session)
			if GetParamFromSig(fresh, "UserTier") != "Vintage" || GetParamFromSig(fresh, "Upload") != "true" || GetParamFromSig(got.sig, "UserTier") != "Vintage" {
				t.Errorf("renewed at %q with Upload %q, want the grant's Vintage tier and its flags", GetParamFromSig(fresh, "UserTier"), GetParamFromSig(fresh, "Upload"))
			}
			if !strings.Contains(rig.logged.String(), "cause=poke verdict=entitled") {
				t.Errorf("admin log %q does not tell the cause", rig.logged.String())
			}
			if rig.stub.memberCalls != 0 {
				t.Errorf("%d membership calls for a grant, want none", rig.stub.memberCalls)
			}
		})
	}
}

// Each renewal says in its line what asked for it, whatever Patreon answered.
func TestRenewalLogsWhatAskedForIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		age     time.Duration
		poke    bool
		stamp   bool
		refresh bool
		stub    func(*patreonStub)
		want    string // cause=… verdict=…
	}{
		{"an age that is due", 9 * day, false, false, false, nil, "cause=due verdict=entitled"},
		{"a signature that ran out within grace", 11*day + 2*time.Hour, false, false, false, nil, "cause=grace verdict=entitled"},
		{"a poke", 1 * day, true, false, false, nil, "cause=poke verdict=entitled"},
		{"an edit of the access table", 3 * day, false, true, false, nil, "cause=acl verdict=reminted"},
		{"a poke and an edit", 3 * day, true, true, false, nil, "cause=poke verdict=entitled"},
		{"a poke and an age that is due", 9 * day, true, false, false, nil, "cause=due verdict=entitled"},
		{"Refresh now", 1 * day, false, false, true, nil, "cause=refresh verdict=entitled"},
		{"a poke Patreon does not answer", 1 * day, true, false, false, func(p *patreonStub) { p.token = &stubAnswer{500, `{}`} }, "cause=poke verdict=unknown"},
		{"an edit, whatever Patreon would say", 3 * day, false, true, false, func(p *patreonStub) { p.title = "" }, "cause=acl verdict=reminted"},
		{"a poke with a refresh token Patreon refuses", 1 * day, true, false, false, func(p *patreonStub) { p.token = &stubAnswer{401, `{"error":"invalid_grant"}`} }, "cause=poke verdict=invalid_grant"},
		{"Refresh now when nothing is pledged", 1 * day, false, false, true, func(p *patreonStub) { p.title = "" }, "cause=refresh verdict=not entitled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			if tc.stub != nil {
				tc.stub(rig.stub)
			}
			session := rig.session("")
			old := rig.sig("Legacy", tc.age)
			if tc.poke {
				pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())
			}
			if tc.stamp {
				pokes.StampACL(time.Now().Add(-2 * day))
			}

			if tc.refresh {
				rig.account("refresh", browser(old, session)...)
			} else {
				rig.page(browser(old, session)...)
			}
			var renewals []string
			for _, line := range strings.Split(rig.logged.String(), "\n") {
				if strings.HasPrefix(line, "renew: ") {
					renewals = append(renewals, line)
				}
			}
			if len(renewals) != 1 || !strings.Contains(renewals[0], tc.want) {
				t.Errorf("admin log %q, want one renew line with %q", rig.logged.String(), tc.want)
			}
		})
	}
}

// The line that says a reader's email moved carries the cause as well, so
// every line of a renewal does.
func TestRenewalLogsWhatAskedForItWhenTheEmailMoved(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	rig.stub.email = fmt.Sprintf("moved-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() {
		// t.Context() is already canceled when a cleanup runs
		_, err := rig.db.DeletePatreonSessions(context.Background(), userstate.HashEmail(rig.stub.email))
		if err != nil {
			t.Error(err)
		}
	})
	session := rig.session("")
	pokes.Poke(rig.hash, aSecondAgo(), pokeWindow())

	rig.page(browser(rig.sig("Legacy", 1*day), session)...)
	var renewals []string
	for _, line := range strings.Split(rig.logged.String(), "\n") {
		if strings.HasPrefix(line, "renew: ") {
			renewals = append(renewals, line)
		}
	}
	if len(renewals) != 2 || !strings.Contains(renewals[0], "cause=poke email changed from") || !strings.Contains(renewals[1], "cause=poke verdict=entitled") {
		t.Errorf("renew lines %q, want the move and the verdict each with cause=poke", renewals)
	}
}

// A signature minted under the old state in the same second as the edit or
// the poke that made it stale, which its Expires cannot tell from one minted
// after, is renewed all the same rather than kept for after_days.
func TestSigningStaleInTheEditsOwnSecond(t *testing.T) {
	t.Run("an edit", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		pokes := freshPokes(t)
		session := rig.session("")
		minted := rig.sig("Legacy", 0)
		pokes.StampACL(time.Now())
		rig.wantReminted(rig.page(browser(minted, session)...), minted)
	})
	t.Run("a poke", func(t *testing.T) {
		rig := newRenewalRig(t, renewalBlock)
		pokes := freshPokes(t)
		rig.stub.title = "VINTAGE"
		session := rig.session("")
		minted := rig.sig("Legacy", 0)
		pokes.Poke(rig.hash, time.Now(), pokeWindow())
		fresh := rig.wantRenewed(rig.page(browser(minted, session)...), minted, session)
		if GetParamFromSig(fresh, "UserTier") != "Vintage" {
			t.Errorf("renewed at %q, want the tier the poke was for", GetParamFromSig(fresh, "UserTier"))
		}
	})
}
