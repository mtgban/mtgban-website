package main

import (
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

// Discord sends GuildCreate on every connect for each guild the bot is
// already in, so only a guild joined moments ago is a new install.
func TestJoinedRecently(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		joinedAt time.Time
		want     bool
	}{
		{"joined seconds ago", now.Add(-5 * time.Second), true},
		{"joined months ago", now.AddDate(0, -6, 0), false},
		{"joined two minutes ago", now.Add(-2 * time.Minute), false},
		{"no join time", time.Time{}, false},
	} {
		got := joinedRecently(&discordgo.Guild{JoinedAt: tc.joinedAt}, now)
		if got != tc.want {
			t.Errorf("%s: joinedRecently = %v, want %v", tc.name, got, tc.want)
		}
	}
}
