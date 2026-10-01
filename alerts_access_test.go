package main

import (
	"net/url"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/userstate"
)

func TestAllowanceFromValues(t *testing.T) {
	cases := []struct {
		v    url.Values
		want int
	}{
		{url.Values{"AlertsMax": {"10"}}, 0},
		{url.Values{"Alerts": {"true"}, "AlertsMax": {"10"}}, 10},
		{url.Values{"Alerts": {"true"}}, 0},
		{url.Values{"Alerts": {"true"}, "AlertsMax": {"ten"}}, 0},
		{url.Values{"Alerts": {"true"}, "AlertsMax": {"-1"}}, 0},
		{nil, 0},
	}
	for _, tc := range cases {
		got := allowanceFromValues(tc.v)
		if got != tc.want {
			t.Errorf("allowance(%v) = %d, want %d", tc.v, got, tc.want)
		}
	}
}

func TestUserACLValuesLayersGrantOverrides(t *testing.T) {
	table := access.Table{
		"Legacy":  {"Search": {}},
		"Pioneer": {"Alerts": {"AlertsMax": "20"}},
	}
	grants := []access.Grant{
		{Email: "Granted@Example.com", Tier: "Legacy", Overrides: map[string]map[string]string{"Alerts": {"AlertsMax": "5"}}},
	}

	plain := aclValuesWith(table, indexGrants(grants), userstate.HashEmail("nobody@example.com"), "Legacy")
	if plain.Get("Alerts") != "" || plain.Get("AlertsMax") != "" {
		t.Fatalf("tier alone granted alerts: %v", plain)
	}

	granted := aclValuesWith(table, indexGrants(grants), userstate.HashEmail("granted@example.com"), "Legacy")
	if granted.Get("Alerts") != "true" || granted.Get("AlertsMax") != "5" {
		t.Fatalf("grant overrides dropped: %v", granted)
	}

	// A grant's own Tier now wins over the contact's stored tier passed in:
	// an admin moving a grant to a new tier reaches the evaluator without a
	// fresh login, rather than staying stuck on the tier last logged in with.
	movedGrants := []access.Grant{
		{Email: "granted@example.com", Tier: "Pioneer"},
	}
	moved := aclValuesWith(table, indexGrants(movedGrants), userstate.HashEmail("granted@example.com"), "Legacy")
	if moved.Get("Alerts") != "true" || moved.Get("AlertsMax") != "20" {
		t.Fatalf("grant tier should win over the passed-in stored tier: %v", moved)
	}

	// A grant with no Tier of its own still applies its overrides on top of
	// the stored tier, same as Auth does: an empty Tier must not drop them.
	overrideOnlyGrants := []access.Grant{
		{Email: "granted@example.com", Overrides: map[string]map[string]string{"Alerts": {"AlertsMax": "9"}}},
	}
	overrideOnly := aclValuesWith(table, indexGrants(overrideOnlyGrants), userstate.HashEmail("granted@example.com"), "Legacy")
	if overrideOnly.Get("Alerts") != "true" || overrideOnly.Get("AlertsMax") != "9" {
		t.Fatalf("empty-Tier grant should still apply its overrides: %v", overrideOnly)
	}
}

// TestIndexGrantsFirstDuplicateWins matches the old linear scan's tie-break:
// a repeated email keeps the first grant's Tier, not the last.
func TestIndexGrantsFirstDuplicateWins(t *testing.T) {
	grants := []access.Grant{{Email: "dup@example.com", Tier: "First"}, {Email: "dup@example.com", Tier: "Second"}}
	grant, found := indexGrants(grants).find(userstate.HashEmail("dup@example.com"))
	if !found || grant.Tier != "First" {
		t.Fatalf("grant = %+v found=%v, want Tier=First", grant, found)
	}
}

func TestAlertContactAllowedIn(t *testing.T) {
	table := access.Table{
		"Vintage": {"Alerts": {"AlertsMax": "10"}},
		// AlertsMax lives under a page other than Alerts: OptionalFields is
		// read off whichever page's options carry it, not just Alerts'.
		"Modern": {"Search": {"AlertsMax": "7"}},
	}
	cases := []struct {
		name      string
		tier      string
		overrides map[string]map[string]string
		want      bool
	}{
		{"tier grants Alerts and AlertsMax", "Vintage", nil, true},
		{"tier has nothing, override grants Alerts", "Legacy", map[string]map[string]string{"Alerts": {"AlertsMax": "3"}}, true},
		{"AlertsMax under another page, no Alerts", "Modern", nil, false},
		{"nothing", "Nobody", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := alertContactAllowedIn(table, tc.tier, tc.overrides)
			if got != tc.want {
				t.Errorf("alertContactAllowedIn(%s) = %v, want %v", tc.tier, got, tc.want)
			}
		})
	}
}
