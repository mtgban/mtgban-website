package main

import (
	"errors"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

func resetChangelogCache() {
	changelogCacheMu.Lock()
	defer changelogCacheMu.Unlock()
	cachedChangelog = changelogCache{}
}

func TestGetChangelogEntriesUsesCache(t *testing.T) {
	resetChangelogCache()
	defer resetChangelogCache()

	oldFetch := fetchChangelogEntriesFunc
	defer func() { fetchChangelogEntriesFunc = oldFetch }()

	calls := 0
	fetchChangelogEntriesFunc = func() ([]changelogEntry, error) {
		calls++
		return []changelogEntry{{Content: "cached"}}, nil
	}

	for range 2 {
		entries, err := getChangelogEntries()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Content != "cached" {
			t.Fatalf("unexpected entries: %#v", entries)
		}
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1", calls)
	}
}

func TestGetChangelogEntriesUsesStaleCacheAndBacksOff(t *testing.T) {
	resetChangelogCache()
	defer resetChangelogCache()

	oldFetch := fetchChangelogEntriesFunc
	defer func() { fetchChangelogEntriesFunc = oldFetch }()

	calls := 0
	fetchChangelogEntriesFunc = func() ([]changelogEntry, error) {
		calls++
		if calls == 1 {
			return []changelogEntry{{Content: "stale"}}, nil
		}
		return nil, errors.New("discord unavailable")
	}

	entries, err := getChangelogEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("initial fetch = %#v, %v", entries, err)
	}

	changelogCacheMu.Lock()
	cachedChangelog.refreshed = time.Now().Add(-changelogCacheTTL - time.Second)
	changelogCacheMu.Unlock()

	entries, err = getChangelogEntries()
	if err != nil || len(entries) != 1 || entries[0].Content != "stale" {
		t.Fatalf("stale fetch = %#v, %v", entries, err)
	}
	if _, err = getChangelogEntries(); err != nil {
		t.Fatalf("backoff should serve stale entries: %v", err)
	}
	if calls != 2 {
		t.Fatalf("fetch called %d times, want 2", calls)
	}
}

func TestGetChangelogEntriesBacksOffColdFailures(t *testing.T) {
	resetChangelogCache()
	defer resetChangelogCache()

	oldFetch := fetchChangelogEntriesFunc
	defer func() { fetchChangelogEntriesFunc = oldFetch }()

	calls := 0
	fetchChangelogEntriesFunc = func() ([]changelogEntry, error) {
		calls++
		return nil, errors.New("discord unavailable")
	}

	if _, err := getChangelogEntries(); err == nil {
		t.Fatal("cold failure returned nil error")
	}
	if _, err := getChangelogEntries(); err == nil {
		t.Fatal("backoff failure returned nil error")
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1", calls)
	}
}

func TestGetChangelogChannelIDRequiresDiscord(t *testing.T) {
	oldID := Config.DiscordChangelogChannelID
	oldSession := dg
	defer func() {
		Config.DiscordChangelogChannelID = oldID
		dg = oldSession
	}()

	Config.DiscordChangelogChannelID = ""
	dg = nil
	if _, err := getChangelogChannelID(); err == nil {
		t.Fatal("missing Discord session returned nil error")
	}
}

func TestGetChangelogChannelIDReportsMissingChannel(t *testing.T) {
	oldID := Config.DiscordChangelogChannelID
	oldList := listChangelogChannelsFunc
	defer func() {
		Config.DiscordChangelogChannelID = oldID
		listChangelogChannelsFunc = oldList
	}()

	Config.DiscordChangelogChannelID = ""
	listChangelogChannelsFunc = func() ([]*discordgo.Channel, error) {
		return []*discordgo.Channel{{Name: "general"}}, nil
	}
	if _, err := getChangelogChannelID(); err == nil {
		t.Fatal("missing channel returned nil error")
	}
}

func TestChangelogEntryFromMessage(t *testing.T) {
	message := &discordgo.Message{
		ID:        "123",
		GuildID:   "guild",
		ChannelID: "channel",
		Content:   "Prices are now easier to compare.",
		Timestamp: time.Date(2026, time.September, 17, 12, 0, 0, 0, time.UTC),
		Embeds: []*discordgo.MessageEmbed{{
			Title:       "A smaller search page",
			Description: "The new layout is live.",
			URL:         "https://mtgban.com/search",
		}},
		Attachments: []*discordgo.MessageAttachment{{
			Filename: "preview.png",
			URL:      "https://cdn.discordapp.com/preview.png",
		}},
	}

	entry, ok := changelogEntryFromMessage(message, "channel")
	if !ok {
		t.Fatal("changelogEntryFromMessage returned ok=false")
	}
	if entry.Published != "Sep 17, 2026" {
		t.Fatalf("Published = %q, want %q", entry.Published, "Sep 17, 2026")
	}
	if entry.SourceURL != "https://discord.com/channels/guild/channel/123" {
		t.Fatalf("SourceURL = %q", entry.SourceURL)
	}
	if len(entry.Embeds) != 1 || entry.Embeds[0].Title != "A smaller search page" {
		t.Fatalf("unexpected embeds: %#v", entry.Embeds)
	}
	if len(entry.Attachments) != 1 || entry.Attachments[0].Name != "preview.png" {
		t.Fatalf("unexpected attachments: %#v", entry.Attachments)
	}
}

func TestChangelogEntryFromMessageSkipsEmptyMessages(t *testing.T) {
	if _, ok := changelogEntryFromMessage(&discordgo.Message{}, "channel"); ok {
		t.Fatal("empty message should not become a changelog entry")
	}
}
