package pledge

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

// resolverSetup returns a Resolver that serves grants (none when empty) to
// the grant lookup, and the admin log it writes to as a builder.
func resolverSetup(t *testing.T, grants string) (*Resolver, *strings.Builder) {
	t.Helper()
	if grants == "" {
		grants = "[]"
	}
	files := map[string]string{"acl": `{}`, "grants": grants}
	list := access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := list.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}

	var logged strings.Builder
	adminLog := log.New(&logged, "", 0)
	return New(Hooks{
		Log: func() *log.Logger { return adminLog },
		GrantFor: func(email string) (access.Grant, bool) {
			for _, grant := range list.Grants() {
				if strings.EqualFold(grant.Email, email) {
					return grant, true
				}
			}
			return access.Grant{}, false
		},
	}), &logged
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
func TestResolve(t *testing.T) {
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
		verdict    Verdict
		noAnswer   bool   // DidNotAnswer of the error
		logged     string // a line the admin log must carry once
	}
	tests := []tierTest{
		{name: "a grant decides without a lookup", grants: grantWithTier, membership: "m1",
			tier: "Vintage", overrides: annOverrides, granted: true, verdict: Entitled},
		{name: "a grant needs no membership", grants: grantWithTier,
			tier: "Vintage", overrides: annOverrides, granted: true, verdict: Entitled},
		{name: "a grant without a tier takes the pledge's", grants: grantWithoutTier, membership: "m1",
			status: 200, body: entitledTo("MODERN"), calls: 1, tier: "Modern", overrides: annOverrides, verdict: Entitled},
		{name: "a grant without a tier or a pledge", grants: grantWithoutTier, verdict: NotEntitled},
		{name: "another reader's grant", grants: grantOfSomeoneElse, status: 200, body: entitledTo("LEGACY"),
			membership: "m1", calls: 1, tier: "Legacy", verdict: Entitled},
		{name: "no membership", verdict: NotEntitled},
		{name: "no user id", grants: grantWithTier, membership: "m1", noUserID: true, verdict: Unknown},
		{name: "no email", membership: "m1", noEmail: true, verdict: Unknown},
		{name: "no email beside a grant with none", grants: grantWithoutEmail, membership: "m1", noEmail: true, verdict: Unknown},
		{name: "no entitled tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[]}}}}`,
			calls: 1, verdict: NotEntitled},
		{name: "only the free tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t0","type":"tier"}]}}},"included":[{"id":"t0","type":"tier","attributes":{"title":"Free","amount_cents":0}}]}`,
			calls: 1, verdict: NotEntitled},
		{name: "the free tier beside a paid one", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t0","type":"tier"},{"id":"t1","type":"tier"}]}}},"included":[{"id":"t0","type":"tier","attributes":{"title":"Free","amount_cents":0}},{"id":"t1","type":"tier","attributes":{"title":"LEGACY","amount_cents":1000}}]}`,
			calls: 1, tier: "Legacy", verdict: Entitled},
		{name: "the free tier beside a paid one the site does not know", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t0","type":"tier"},{"id":"t1","type":"tier"}]}}},"included":[{"id":"t0","type":"tier","attributes":{"title":"Free","amount_cents":0}},{"id":"t1","type":"tier","attributes":{"title":"TYPE TWO","amount_cents":2500}}]}`,
			calls: 1, verdict: Unknown, logged: `unexpected tier title "TYPE TWO"`},
		{name: "a paid tier with its cost", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}},"included":[{"id":"t1","type":"tier","attributes":{"title":"MODERN","amount_cents":500}}]}`,
			calls: 1, tier: "Modern", verdict: Entitled},
		{name: "a free tier the site does not know by title", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t0","type":"tier"}]}}},"included":[{"id":"t0","type":"tier","attributes":{"title":"TYPE TWO","amount_cents":0}}]}`,
			calls: 1, verdict: NotEntitled},
		{name: "an entitled tier that is no tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"reward"}]}}}}`,
			calls: 1, verdict: Unknown},
		{name: "an untitled tier", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}}}`,
			calls: 1, verdict: Unknown},
		{name: "a tier titled as another", membership: "m1", status: 200,
			body:  `{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}},"included":[{"id":"t2","type":"tier","attributes":{"title":"LEGACY"}}]}`,
			calls: 1, verdict: Unknown},
		{name: "a tier with an empty title", membership: "m1", status: 200, body: entitledTo(""),
			calls: 1, verdict: Unknown},
		{name: "a title the site does not know", membership: "m1", status: 200, body: entitledTo("TYPE TWO"),
			calls: 1, verdict: Unknown, logged: `unexpected tier title "TYPE TWO"`},
		{name: "an error in the answer", membership: "m1", status: 200,
			body:  `{"errors":[{"code_name":"refused"}]}`,
			calls: 1, verdict: Unknown},
		{name: "an error beside a tier", membership: "m1", status: 200,
			body:  strings.Replace(entitledTo("LEGACY"), `{"data"`, `{"errors":[{"code_name":"refused"}],"data"`, 1),
			calls: 1, verdict: Unknown},
		{name: "no such member", membership: "m1", status: http.StatusNotFound, body: `{"errors":[{}]}`,
			calls: 1, verdict: Unknown},
		{name: "a bad request", membership: "m1", status: http.StatusBadRequest, body: `{}`,
			calls: 1, verdict: Unknown},
		{name: "a refused token", membership: "m1", status: http.StatusUnauthorized, body: `{}`,
			calls: 1, verdict: Unknown, noAnswer: true},
		{name: "a forbidden token", membership: "m1", status: http.StatusForbidden, body: `{}`,
			calls: 1, verdict: Unknown, noAnswer: true},
		{name: "too many requests", membership: "m1", status: http.StatusTooManyRequests, body: `{}`,
			calls: 1, verdict: Unknown, noAnswer: true},
		{name: "an edge's 503", membership: "m1", status: http.StatusServiceUnavailable, body: `<html>`,
			calls: 1, verdict: Unknown, noAnswer: true},
		{name: "no connection", membership: "m1", netErr: errors.New("connection refused"),
			calls: 1, verdict: Unknown, noAnswer: true},
		{name: "an answer cut short", membership: "m1", status: 200, body: `{"data":`,
			calls: 1, verdict: Unknown, noAnswer: true},
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
			body: entitledTo(title), calls: 1, tier: tier, verdict: Entitled})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, logged := resolverSetup(t, tc.grants)
			transport := &tierPatreon{status: tc.status, body: tc.body, err: tc.netErr}
			client := &patreon.Client{Client: &http.Client{Transport: transport}}
			user := &User{UserID: "u1", MembershipID: tc.membership, FullName: "Ann Example", Email: "ann@example.com", EmailVerified: true}
			if tc.noUserID {
				user.UserID = ""
			}
			if tc.noEmail {
				user.Email = ""
			}

			ctx := context.Background()
			tier, overrides, granted, verdict, err := res.Resolve(ctx, client, user)

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
			if (err != nil) != (tc.verdict == Unknown) {
				t.Errorf("error %v with verdict %d, want one only for an unknown verdict", err, verdict)
			}
			if tc.verdict == Unknown && DidNotAnswer(ctx, err) != tc.noAnswer {
				t.Errorf("DidNotAnswer(%v) is %v, want %v", err, !tc.noAnswer, tc.noAnswer)
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
