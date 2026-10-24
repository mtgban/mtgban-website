package main

import (
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/userstate"
)

// Whether a signature renews comes down to how old it is against after_days
// and, once it ran out, how long ago against grace_days; the other four
// inputs each end it on their own.
func TestDecideRenewal(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	const day = 24 * time.Hour
	block := infrastructure.PatreonRenewal{AfterDays: 8, GraceDays: 3}

	for _, tc := range []struct {
		name    string
		expires time.Duration // from now
		signed  bool
		cookie  bool
		session bool
		cfg     infrastructure.PatreonRenewal
		want    renewalDecision
	}{
		{"just minted", 11 * day, true, true, true, block, renewalSkip},
		{"a week old", 4 * day, true, true, true, block, renewalSkip},
		{"a second short of after_days", 3*day + time.Second, true, true, true, block, renewalSkip},
		{"exactly after_days old", 3 * day, true, true, true, block, renewalDue},
		{"a day from running out", day, true, true, true, block, renewalDue},
		{"a second from running out", time.Second, true, true, true, block, renewalDue},
		{"running out now", 0, true, true, true, block, renewalDue},
		{"a second past", -time.Second, true, true, true, block, renewalGrace},
		{"a day past", -day, true, true, true, block, renewalGrace},
		{"exactly grace_days past", -3 * day, true, true, true, block, renewalGrace},
		{"a second beyond grace_days", -3*day - time.Second, true, true, true, block, renewalSkip},
		{"long gone", -30 * day, true, true, true, block, renewalSkip},

		{"not written by this host, due", day, false, true, true, block, renewalSkip},
		{"not written by this host, in grace", -day, false, true, true, block, renewalSkip},
		{"from ?sig=, due", day, true, false, true, block, renewalSkip},
		{"from ?sig=, in grace", -day, true, false, true, block, renewalSkip},
		{"no session cookie, due", day, true, true, false, block, renewalSkip},
		{"no session cookie, in grace", -day, true, true, false, block, renewalSkip},

		{"after_days 0, due", day, true, true, true, infrastructure.PatreonRenewal{GraceDays: 3}, renewalSkip},
		{"after_days 0, in grace", -day, true, true, true, infrastructure.PatreonRenewal{GraceDays: 3}, renewalSkip},
		{"an empty block", day, true, true, true, infrastructure.PatreonRenewal{}, renewalSkip},
		{"grace_days 0, due", day, true, true, true, infrastructure.PatreonRenewal{AfterDays: 8}, renewalDue},
		{"grace_days 0, a second past", -time.Second, true, true, true, infrastructure.PatreonRenewal{AfterDays: 8}, renewalSkip},

		{"daily, a day old", 10 * day, true, true, true, infrastructure.PatreonRenewal{AfterDays: 1}, renewalDue},
		{"daily, a second short", 10*day + time.Second, true, true, true, infrastructure.PatreonRenewal{AfterDays: 1}, renewalSkip},
		{"after_days past the signature's life, running out", time.Second, true, true, true, infrastructure.PatreonRenewal{AfterDays: 12, GraceDays: 3}, renewalSkip},
		{"after_days past the signature's life, a day past", -day, true, true, true, infrastructure.PatreonRenewal{AfterDays: 12, GraceDays: 3}, renewalGrace},
	} {
		got := decideRenewal(tc.signed, now.Add(tc.expires), now, tc.cookie, tc.session, tc.cfg)
		if got != tc.want {
			t.Errorf("%s: decided %d, want %d", tc.name, got, tc.want)
		}
	}
}

// renewalConfig installs the renewal block and a Patreon client id for the
// test, and puts back what it found.
func renewalConfig(t *testing.T, block infrastructure.PatreonRenewal, clientID string) {
	t.Helper()
	savedBlock, savedPatreon := Config().Config.PatreonRenewal, Config().Config.Patreon
	t.Cleanup(func() { Config().Config.PatreonRenewal, Config().Config.Patreon = savedBlock, savedPatreon })
	Config().Config.PatreonRenewal = block
	Config().Config.Patreon = infrastructure.Patreon{
		Source: "main",
		Client: map[string]string{"main": clientID},
		Secret: map[string]string{"main": "client-secret"},
	}
}

// Each of the four things besides the block turns renewal off alone, and so
// does the block when it names no after_days or is not there.
func TestRenewalEnabledNeedsEveryPiece(t *testing.T) {
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })

	on := infrastructure.PatreonRenewal{AfterDays: 8, GraceDays: 3}
	signingEnabled(t, false)
	for _, tc := range []struct {
		name     string
		block    infrastructure.PatreonRenewal
		database bool
		sigCheck bool
		clientID string
		want     bool
	}{
		{"everything there", on, true, true, "client-id", true},
		{"only after_days", infrastructure.PatreonRenewal{AfterDays: 1}, true, true, "client-id", true},
		{"no block", infrastructure.PatreonRenewal{}, true, true, "client-id", false},
		{"after_days 0", infrastructure.PatreonRenewal{GraceDays: 3, MaxSessionDays: 30, ClearOnNegative: true}, true, true, "client-id", false},
		{"no database", on, false, true, "client-id", false},
		{"signatures unchecked", on, true, false, "client-id", false},
		{"no Patreon client id", on, true, true, "", false},
	} {
		SigCheck = tc.sigCheck
		renewalConfig(t, tc.block, tc.clientID)
		UserStateDB = nil
		if tc.database {
			UserStateDB = &userstate.Client{}
		}
		got := renewalEnabled()
		if got != tc.want {
			t.Errorf("%s: renewal enabled %v, want %v", tc.name, got, tc.want)
		}
	}

	// A source the client map has no id for is no client at all
	SigCheck = true
	renewalConfig(t, on, "client-id")
	Config().Config.Patreon.Source = "elsewhere"
	UserStateDB = &userstate.Client{}
	if renewalEnabled() {
		t.Error("renewal enabled with no client id for the Patreon source")
	}
}
