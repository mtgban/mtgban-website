package main

import (
	"testing"

	"github.com/lib/pq"

	"github.com/mtgban/mtgban-website/userstate"
)

func TestSkipAccessNotification(t *testing.T) {
	notification := func(payload string) *pq.Notification {
		return &pq.Notification{Channel: grantsReloadChannel, Extra: payload}
	}
	for _, tt := range []struct {
		name         string
		n            *pq.Notification
		instanceName string
		skip         bool
	}{
		// A reconnect may have missed notifications, reload no matter what.
		{"reconnect", nil, "magic", false},
		{"own save", notification("magic"), "magic", true},
		{"peer save", notification("lorcana"), "magic", false},
		// Unnamed instances cannot be told apart, so never skip on them:
		// treating empty-equals-empty as "own" would drop peer saves.
		{"unnamed sender", notification(""), "magic", false},
		{"unnamed everywhere", notification(""), "", false},
	} {
		skip := skipAccessNotification(tt.n, tt.instanceName)
		if skip != tt.skip {
			t.Errorf("%s: skip = %v, want %v", tt.name, skip, tt.skip)
		}
	}
}

// A patreon_poke notification pokes the reader its payload names, whoever
// sent it, and is not a reload: the listener has nothing else to do with it.
func TestTakePoke(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	savedName := Config().InstanceName
	t.Cleanup(func() { Config().InstanceName = savedName })
	Config().InstanceName = "magic"
	hash := userstate.HashEmail("reader@example.com")

	for _, tc := range []struct {
		name    string
		n       *pq.Notification
		taken   bool
		pokedBy string
	}{
		{"a poke", &pq.Notification{Channel: patreonPokeChannel, Extra: hash}, true, hash},
		// The payload is a hash, so the skip of a reload's own sender does not apply
		{"a poke whose payload is this instance's name", &pq.Notification{Channel: patreonPokeChannel, Extra: "magic"}, true, "magic"},
		{"a poke naming nobody", &pq.Notification{Channel: patreonPokeChannel}, true, ""},
		{"a reload carrying the same payload", &pq.Notification{Channel: grantsReloadChannel, Extra: hash}, false, ""},
		{"a reconnect", nil, false, ""},
	} {
		pokes := freshPokes(t)
		taken := takePoke(tc.n)
		if taken != tc.taken {
			t.Errorf("%s: taken %v, want %v", tc.name, taken, tc.taken)
		}
		want := 0
		if tc.pokedBy != "" {
			want = 1
		}
		if len(pokes.at) != want || (want == 1 && !pokes.poked(tc.pokedBy)) {
			t.Errorf("%s: set %v, want %d entry for %q", tc.name, pokes.at, want, tc.pokedBy)
		}
	}
}
