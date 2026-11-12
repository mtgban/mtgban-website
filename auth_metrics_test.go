package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mtgban/mtgban-website/apihandoff"
	"github.com/mtgban/mtgban-website/observability"
)

func TestRenewalValue(t *testing.T) {
	for o, want := range map[renewalOutcome]string{
		renewalNotRenewed: "not_renewed", renewalRenewed: "renewed", renewalEnded: "ended",
		renewalRefused: "refused", renewalGone: "gone", renewalSessionGone: "session_gone",
	} {
		if got := renewalValue(o); got != want {
			t.Errorf("renewalValue(%d) = %q, want %q", o, got, want)
		}
	}
	entry, _ := observability.Lookup("auth.renew")
	if len(entry.Enum) != 6 {
		t.Errorf("auth.renew has %d values for 6 outcomes", len(entry.Enum))
	}
}

func TestHandoffPurpose(t *testing.T) {
	for p, want := range map[string]string{
		apihandoff.PurposeTrial: "trial", apihandoff.PurposeLogin: "login", "": "unknown", "x": "unknown",
	} {
		if got := handoffPurpose(p); got != want {
			t.Errorf("handoffPurpose(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestACallbackWithNoCodeIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.Host = "mtgban.com"
	testSite.Auth(httptest.NewRecorder(), r)
	wantRow(t, rows.rows(), "", "auth.login", "no_code", 1)
}

// A code Patreon will not exchange is a failed login; a handoff's is not one.
func TestACallbackPatreonFailedIsCounted(t *testing.T) {
	setGatewaySecret(t, "handoff-secret")
	handoffSetup(t)
	rows := withFeatureCounter(t)
	state := handoffStatePrefix + url.Values{"p": {apihandoff.PurposeTrial}, "n": {"n1"}}.Encode()
	for _, q := range []string{"code=x", url.Values{"code": {"x"}, "state": {state}}.Encode()} {
		r := httptest.NewRequest(http.MethodGet, "/auth?"+q, nil)
		r.Host = "mtgban.com"
		testSite.Auth(httptest.NewRecorder(), r)
	}
	got := rows.rows()
	wantRow(t, got, "", "auth.login", "fail_patreon", 1)
	wantRow(t, got, "refused", "apiplans.handoff", "trial", 1)
	if n := len(find(got, "auth.login")); n != 1 {
		t.Errorf("auth.login rows = %d, want the site login's only", n)
	}
}

func TestLogoutIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	testSite.Home(httptest.NewRecorder(), siteRequest("/?errmsg=logout"))
	testSite.User(httptest.NewRecorder(), accountPost("logout-everywhere"))
	got := rows.rows()
	wantRow(t, got, "", "auth.logout", "here", 1)
	wantRow(t, got, "", "auth.logout", "everywhere", 1)
}

func TestRefreshIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	testSite.User(httptest.NewRecorder(), accountPost("refresh"))
	got := rows.rows()
	wantRow(t, got, "", "account.refresh", "", 1)
	wantNoRow(t, got, "auth.renew")
}

// A cross-site post is refused before it is read, and counts nothing.
func TestARefusedAccountPostIsNotCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	r := accountPost("refresh")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	testSite.User(httptest.NewRecorder(), r)
	wantNoRow(t, rows.rows(), "account.refresh")
}

// accountPost is a same-origin press of action on the Account page.
func accountPost(action string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/user", strings.NewReader(url.Values{"action": {action}}.Encode()))
	r.Host = "mtgban.com"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func TestAPIPlansViewIsCounted(t *testing.T) {
	shown := ""
	for _, p := range apiProducts.Packages {
		if !p.IsHistory() {
			shown = p.Key
		}
	}
	rows := withFeatureCounter(t)
	for _, target := range []string{"/api-plans", "/api-plans?invite=x", "/api-plans?change=1", "/api-plans?package=" + shown, "/api-plans?package=bogus"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Sec-Fetch-Dest", "document")
		testSite.APIPlans(httptest.NewRecorder(), r)
	}
	r := httptest.NewRequest(http.MethodGet, "/api-plans", nil)
	r.Header.Set("Sec-Fetch-Dest", "empty")
	testSite.APIPlans(httptest.NewRecorder(), r)
	got := rows.rows()
	wantRow(t, got, "", "apiplans.view", "plain", 2)
	wantRow(t, got, "", "apiplans.view", "prefilled", 3)
}

func TestHandoffStepsAreCounted(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		setGatewaySecret(t, "handoff-secret")
		handoffSetup(t)
		rows := withFeatureCounter(t)
		patreonRedirect(t, handoffStart(t, testSite.APILogin, "/api-login", ""))
		wantRow(t, rows.rows(), "start", "apiplans.handoff", "login", 1)
	})
	t.Run("off", func(t *testing.T) {
		setGatewaySecret(t, "")
		handoffSetup(t)
		rows := withFeatureCounter(t)
		handoffStart(t, testSite.APILogin, "/api-login", "")
		got := rows.rows()
		wantRow(t, got, "refused", "apiplans.handoff", "login", 1)
		if n := len(find(got, "apiplans.handoff")); n != 1 {
			t.Errorf("apiplans.handoff rows = %d, want the refusal only", n)
		}
	})
	t.Run("finish", func(t *testing.T) {
		setGatewaySecret(t, "handoff-secret")
		handoffSetup(t)
		rows := withFeatureCounter(t)
		handoffFinish(t, handoffState{purpose: apihandoff.PurposeLogin, nonce: "n1"}, "", ann, "Legacy", nil)
		handoffFinish(t, handoffState{purpose: apihandoff.PurposeTrial, nonce: "n1"}, "n1", ann, "Legacy", nil)
		handoffFinish(t, handoffState{purpose: "x", nonce: "n1"}, "n1", ann, "Legacy", nil)
		got := rows.rows()
		wantRow(t, got, "refused", "apiplans.handoff", "login", 1)
		wantRow(t, got, "ok", "apiplans.handoff", "trial", 1)
		wantRow(t, got, "refused", "apiplans.handoff", "unknown", 1)
	})
}

// Two presses of Refresh now: the first calls Patreon and renews, the second
// finds the sessions resting and counts no renewal.
func TestRenewalIsCountedAsItsOutcome(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	rows := withFeatureCounter(t)

	first := rig.account("refresh", browser(young, session)...)
	wantRedirect(t, first, "/user?refreshed=yes")
	renewed := setCookies(first)[signatureCookie].Value
	second := rig.account("refresh", browser(renewed, session)...)
	wantRedirect(t, second, "/user?refreshed=no")

	got := rows.rows()
	wantRow(t, got, "", "auth.renew", "renewed", 1)
	if n := len(find(got, "auth.renew")); n != 1 {
		t.Errorf("auth.renew rows = %d, want the one call to Patreon", n)
	}
	wantRow(t, got, "", "account.refresh", "", 2)
}

// Two presses at once: the one turned away by the held lease counts nothing.
func TestARenewalTurnedAwayAtTheLeaseIsNotCounted(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	session := rig.session("")
	young := rig.sig("Legacy", 1*day)
	rows := withFeatureCounter(t)

	other := make(chan struct{})
	rig.stub.beforeToken = func() { holdUntil(t, other) }
	var finished atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			rig.account("refresh", browser(young, session)...)
			if finished.Add(1) == 1 {
				close(other)
			}
		})
	}
	wg.Wait()

	got := rows.rows()
	if rig.stub.calls() != 1 {
		t.Fatalf("%d refreshes, want one", rig.stub.calls())
	}
	wantRow(t, got, "", "auth.renew", "renewed", 1)
	if n := len(find(got, "auth.renew")); n != 1 {
		t.Errorf("auth.renew rows = %d, want the one call to Patreon", n)
	}
}

// A login Patreon names a pledged reader for is ok; one with no pledge is fail_tier;
// one whose tier lookup Patreon fails is fail_patreon.
func TestALoginIsCountedByItsEnd(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	rig.stub.token = &stubAnswer{http.StatusOK, `{"access_token":"access-x","refresh_token":"refresh-x","expires_in":100,"scope":"identity","token_type":"Bearer"}`}
	rows := withFeatureCounter(t)

	testSite.Auth(httptest.NewRecorder(), rig.request(http.MethodGet, "/auth?code=x&state=%2F"))
	rig.stub.member = &stubAnswer{http.StatusBadGateway, ""}
	failed := httptest.NewRecorder()
	testSite.Auth(failed, rig.request(http.MethodGet, "/auth?code=x&state=%2F"))
	if where := failed.Header().Get("Location"); where != "/?errmsg=TierNotFound" {
		t.Errorf("a failed tier lookup went to %q", where)
	}
	rig.stub.member = nil
	rig.stub.membership = false
	testSite.Auth(httptest.NewRecorder(), rig.request(http.MethodGet, "/auth?code=x&state=%2F"))

	got := rows.rows()
	wantRow(t, got, "", "auth.login", "ok", 1)
	wantRow(t, got, "", "auth.login", "fail_patreon", 1)
	wantRow(t, got, "", "auth.login", "fail_tier", 1)
}
