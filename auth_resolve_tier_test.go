package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/patreon"
)

// tierPatreon is a transport Patreon answers membership lookups through, with
// one canned answer, counting how many it was asked.
type tierPatreon struct {
	status int
	body   string
	err    error
	calls  atomic.Int32
}

func (p *tierPatreon) RoundTrip(req *http.Request) (*http.Response, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	return &http.Response{StatusCode: p.status, Body: io.NopCloser(strings.NewReader(p.body)), Request: req}, nil
}

// entitledTo is the membership answer of a pledge entitling one tier, named
// title in the answer's included resources.
func entitledTo(title string) string {
	return fmt.Sprintf(`{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}},"included":[{"id":"t1","type":"tier","attributes":{"title":%q}}]}`, title)
}

// resolveTierSetup serves grants (none when empty) to the grant lookup, and
// the admin log to a builder.
func resolveTierSetup(t *testing.T, grants string) *strings.Builder {
	t.Helper()
	if grants == "" {
		grants = "[]"
	}
	savedAccess := Access
	t.Cleanup(func() { Access = savedAccess })
	files := map[string]string{"acl": `{}`, "grants": grants}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}

	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	var logged strings.Builder
	LogPages["Admin"] = log.New(&logged, "", 0)
	return &logged
}

const (
	grantWithTier      = `[{"email":"ann@example.com","name":"Ann","category":"friend","tier":"Vintage","overrides":{"Alerts":{"AlertsMax":"5"}}}]`
	grantWithoutTier   = `[{"email":"ann@example.com","name":"Ann","category":"friend","overrides":{"Alerts":{"AlertsMax":"5"}}}]`
	grantOfSomeoneElse = `[{"email":"bob@example.com","name":"Bob","category":"friend","tier":"Vintage"}]`
	grantWithoutEmail  = `[{"email":"","name":"Nobody","category":"friend","tier":"Vintage"}]`
)

var annOverrides = map[string]map[string]string{"Alerts": {"AlertsMax": "5"}}

// Patreon's membership answer sorts a reader into entitled, not entitled and
// unknown, and the last never reads as a cancellation: a tier the answer does
// not name, a title the site does not know, an error in the answer, a refusal
// or a failure all leave the reader's pledge in doubt.
func TestResolveTier(t *testing.T) {
	type tierTest struct {
		name       string
		grants     string
		membership string // the identity's membership id
		noUserID   bool   // the identity names no user id
		noEmail    bool   // the identity names no email
		status     int
		body       string
		netErr     error
		calls      int32 // membership lookups made
		tier       string
		overrides  map[string]map[string]string
		granted    bool // a grant named the tier
		verdict    tierVerdict
		noAnswer   bool   // patreonDidNotAnswer of the error
		logged     string // a line the admin log must carry once
	}
	tests := []tierTest{
		{name: "a grant decides without a lookup", grants: grantWithTier, membership: "m1",
			tier: "Vintage", overrides: annOverrides, granted: true, verdict: tierEntitled},
		{name: "a grant needs no membership", grants: grantWithTier,
			tier: "Vintage", overrides: annOverrides, granted: true, verdict: tierEntitled},
		{name: "a grant without a tier takes the pledge's", grants: grantWithoutTier, membership: "m1",
			status: 200, body: entitledTo("MODERN"), calls: 1, tier: "Modern", overrides: annOverrides, verdict: tierEntitled},
		{name: "a grant without a tier or a pledge", grants: grantWithoutTier, verdict: tierNotEntitled},
		{name: "another reader's grant", grants: grantOfSomeoneElse, status: 200, body: entitledTo("LEGACY"),
			membership: "m1", calls: 1, tier: "Legacy", verdict: tierEntitled},
		{name: "no membership", verdict: tierNotEntitled},
		{name: "no user id", grants: grantWithTier, membership: "m1", noUserID: true, verdict: tierUnknown},
		{name: "no email", membership: "m1", noEmail: true, verdict: tierUnknown},
		{name: "no email beside a grant with none", grants: grantWithoutEmail, membership: "m1", noEmail: true, verdict: tierUnknown},
		{name: "no entitled tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[]}}}}`,
			calls: 1, verdict: tierNotEntitled},
		{name: "an entitled tier that is no tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"reward"}]}}}}`,
			calls: 1, verdict: tierUnknown},
		{name: "an untitled tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}}}`,
			calls: 1, verdict: tierUnknown},
		{name: "a tier titled as another", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}},"included":[{"id":"t2","type":"tier","attributes":{"title":"LEGACY"}}]}`,
			calls: 1, verdict: tierUnknown},
		{name: "a tier with an empty title", membership: "m1", status: 200, body: entitledTo(""),
			calls: 1, verdict: tierUnknown},
		{name: "a title the site does not know", membership: "m1", status: 200, body: entitledTo("TYPE TWO"),
			calls: 1, verdict: tierUnknown, logged: `unexpected tier title "TYPE TWO"`},
		{name: "an error in the answer", membership: "m1", status: 200,
			body:  `{"errors":[{"code_name":"refused"}]}`,
			calls: 1, verdict: tierUnknown},
		{name: "an error beside a tier", membership: "m1", status: 200,
			body:  strings.Replace(entitledTo("LEGACY"), `{"data"`, `{"errors":[{"code_name":"refused"}],"data"`, 1),
			calls: 1, verdict: tierUnknown},
		{name: "no such member", membership: "m1", status: http.StatusNotFound, body: `{"errors":[{}]}`,
			calls: 1, verdict: tierUnknown},
		{name: "a bad request", membership: "m1", status: http.StatusBadRequest, body: `{}`,
			calls: 1, verdict: tierUnknown},
		{name: "a refused token", membership: "m1", status: http.StatusUnauthorized, body: `{}`,
			calls: 1, verdict: tierUnknown, noAnswer: true},
		{name: "a forbidden token", membership: "m1", status: http.StatusForbidden, body: `{}`,
			calls: 1, verdict: tierUnknown, noAnswer: true},
		{name: "too many requests", membership: "m1", status: http.StatusTooManyRequests, body: `{}`,
			calls: 1, verdict: tierUnknown, noAnswer: true},
		{name: "an edge's 503", membership: "m1", status: http.StatusServiceUnavailable, body: `<html>`,
			calls: 1, verdict: tierUnknown, noAnswer: true},
		{name: "no connection", membership: "m1", netErr: errors.New("connection refused"),
			calls: 1, verdict: tierUnknown, noAnswer: true},
		{name: "an answer cut short", membership: "m1", status: 200, body: `{"data":`,
			calls: 1, verdict: tierUnknown, noAnswer: true},
	}
	for title, tier := range map[string]string{
		"PIONEER":                  "Pioneer",
		"PIONEER (Early Adopters)": "Pioneer",
		"STANDARD":                 "Pioneer",
		"MODERN":                   "Modern",
		"MODERN (Early Adopters)":  "Modern",
		"LEGACY":                   "Legacy",
		"LEGACY (Early Adopters)":  "Legacy",
		"VINTAGE":                  "Vintage",
		"VINTAGE (Early Adopters)": "Vintage",
		"TYPE ONE":                 "Vintage",
	} {
		tests = append(tests, tierTest{name: "the title " + title, membership: "m1", status: 200,
			body: entitledTo(title), calls: 1, tier: tier, verdict: tierEntitled})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logged := resolveTierSetup(t, tc.grants)
			transport := &tierPatreon{status: tc.status, body: tc.body, err: tc.netErr}
			client := &patreon.Client{Client: &http.Client{Transport: transport}}
			user := &PatreonUserData{UserID: "u1", MembershipID: tc.membership, FullName: "Ann Example", Email: "ann@example.com", EmailVerified: true}
			if tc.noUserID {
				user.UserID = ""
			}
			if tc.noEmail {
				user.Email = ""
			}

			ctx := context.Background()
			tier, overrides, granted, verdict, err := resolveTier(ctx, client, user)

			calls := transport.calls.Load()
			if calls != tc.calls {
				t.Errorf("made %d membership lookups, want %d", calls, tc.calls)
			}
			if granted != tc.granted {
				t.Errorf("granted %v, want %v", granted, tc.granted)
			}
			if verdict != tc.verdict {
				t.Errorf("verdict %d, want %d (tier %q, error %v)", verdict, tc.verdict, tier, err)
			}
			if tier != tc.tier {
				t.Errorf("tier %q, want %q", tier, tc.tier)
			}
			if !maps.EqualFunc(overrides, tc.overrides, maps.Equal) {
				t.Errorf("overrides %v, want %v", overrides, tc.overrides)
			}
			if (err != nil) != (tc.verdict == tierUnknown) {
				t.Errorf("error %v with verdict %d, want one only for an unknown verdict", err, verdict)
			}
			if tc.verdict == tierUnknown && patreonDidNotAnswer(ctx, err) != tc.noAnswer {
				t.Errorf("patreonDidNotAnswer(%v) is %v, want %v", err, !tc.noAnswer, tc.noAnswer)
			}
			if tc.logged != "" && strings.Count(logged.String(), tc.logged) != 1 {
				t.Errorf("admin log %q, want %q on one line", logged.String(), tc.logged)
			}
			if tc.logged == "" && strings.Contains(logged.String(), "unexpected tier title") {
				t.Errorf("admin log %q names an unexpected title", logged.String())
			}
		})
	}
}
