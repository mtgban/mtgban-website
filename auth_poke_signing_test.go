package main

import (
	"html"
	"net/http"
	"net/url"
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

	pokes.poke(rig.hash)
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
	if rig.stub.calls() != 1 || !pokes.poked(rig.hash) {
		t.Errorf("%d refreshes for the renewed signature, poked %v; want still 1 and the poke kept for the other devices", rig.stub.calls(), pokes.poked(rig.hash))
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
	pokes.poke(rig.hash)

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

	pokes.poke(userstate.HashEmail(stranger.Email))
	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 || !pokes.poked(userstate.HashEmail(stranger.Email)) {
		t.Errorf("%d refreshes, stranger poked %v; want none and the stranger's poke kept", rig.stub.calls(), pokes.poked(userstate.HashEmail(stranger.Email)))
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
		pokes.poke(rig.hash)
		old := rig.sig("Legacy", age)
		got := rig.page(browser(old, session)...)
		rig.wantRenewed(got, old, session)
	}

	pokes.poke(rig.hash)
	old := rig.sig("Legacy", 1*day)
	rig.wantRenewed(rig.serve(rig.request(http.MethodPost, "/upload", browser(old, session)...), false), old, session)

	pokes.poke(rig.hash)
	old = rig.sig("Legacy", 1*day)
	rig.wantRenewed(rig.serve(rig.request(http.MethodGet, "/data/prices/x", browser(old, session)...), true), old, session)
}

// A poke lifts the age check and nothing else: where the signature or its
// session could not renew on age, they cannot on a poke, nothing is set, and
// the poke waits for a request that can.
func TestSigningPokeCannotRenewWhatAgeCannot(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			rig := newRenewalRig(t, renewalBlock)
			pokes := freshPokes(t)
			session := rig.session("")
			pokes.poke(rig.hash)
			// An invite names no reader, so nothing legitimate pokes it; this is
			// what a hash of no email would be
			pokes.poke(userstate.HashEmail(""))
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
			if !pokes.poked(rig.hash) {
				t.Error("the poke was spent on a request that renewed nothing")
			}
			rows := rig.rows()
			if len(rows) != 1 || rows[0].token != "refresh-0" || rig.restingFor(session) > 0 {
				t.Errorf("rows %+v, want the session untouched", rows)
			}
		})
	}
}

// A signature that does not check out is refused as it ever was, poked or not.
func TestSigningPokeDoesNotRenewASignatureThatDoesNotCheckOut(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	pokes := freshPokes(t)
	session := rig.session("")
	pokes.poke(rig.hash)

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
			pokes.poke(rig.hash)
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
	pokes.at[rig.hash] = time.Now().Add(-8*day - time.Minute)
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
	pokes.poke(rig.hash)

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if !pokes.poked(rig.hash) {
		t.Fatal("the poke went while Patreon was down")
	}
	wait := rig.restingFor(session)
	if wait < 59*60 || wait > 61*60 {
		t.Errorf("sessions rest %.0fs, want an hour", wait)
	}

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 1 || !pokes.poked(rig.hash) {
		t.Errorf("%d refreshes inside the backoff, poked %v; want 1 and the poke kept", rig.stub.calls(), pokes.poked(rig.hash))
	}

	// The hour is up and Patreon is back
	rig.stub.token = nil
	_, err := rig.db.DB().ExecContext(t.Context(), `UPDATE patreon_sessions SET renew_after = now() WHERE session_id = $1`, session)
	if err != nil {
		t.Fatal(err)
	}
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
	pokes.poke(rig.hash)

	_, _, leased, err := rig.db.LeasePatreonSessions(t.Context(), session, rig.hash, time.Minute)
	if err != nil || !leased {
		t.Fatalf("lease: %v %v", leased, err)
	}
	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if rig.stub.calls() != 0 || !pokes.poked(rig.hash) {
		t.Errorf("%d refreshes, poked %v; want none and the poke kept", rig.stub.calls(), pokes.poked(rig.hash))
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
	pokes.poke(rig.hash)

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
	if rig.stub.calls() != 2 || !pokes.poked(rig.hash) {
		t.Errorf("%d refreshes, poked %v; want one per device and the poke kept", rig.stub.calls(), pokes.poked(rig.hash))
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
	pokes.poke(rig.hash)

	rig.wantUntouched(rig.page(browser(young, session)...), young)
	if !pokes.poked(rig.hash) || rig.restingFor(session) < 59*60 {
		t.Errorf("poked %v, resting %.0fs; want the poke kept and an hour's rest", pokes.poked(rig.hash), rig.restingFor(session))
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
	pokes.poke(rig.hash)

	rec := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, rec, "/user")
	fresh := setCookies(rec)[signatureCookie]
	if fresh == nil || fresh.Value == young || rig.stub.calls() != 1 {
		t.Fatalf("Refresh now set %v after %d refreshes, want a new signature from one", fresh, rig.stub.calls())
	}

	rig.wantUntouched(rig.page(browser(fresh.Value, session)...), fresh.Value)
	if rig.stub.calls() != 1 || !pokes.poked(rig.hash) {
		t.Errorf("%d refreshes for the refreshed signature, poked %v; want still 1 and the poke kept", rig.stub.calls(), pokes.poked(rig.hash))
	}
}
