package main

import (
	"testing"

	"github.com/lib/pq"
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
