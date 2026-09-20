package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

func resetChangelogCache() {
	changelogCacheMu.Lock()
	defer changelogCacheMu.Unlock()
	cachedChangelog = changelogCache{}
}

func TestDiscordConfigSupportsNestedAndLegacyKeys(t *testing.T) {
	var nested ConfigType
	if err := json.Unmarshal([]byte(`{"discord":{"bot_token":"token","guild_id":"guild","invite_url":"https://discord.gg/ban","changelog_channel_id":"announcements","development_channel_id":"dev","recap_channel_id":"recap","chat_channel_id":"chat","user_webhook_url":"user","server_webhook_url":"server","api_webhook_url":"api"}}`), &nested); err != nil {
		t.Fatal(err)
	}
	if nested.Discord.BotToken != "token" || nested.Discord.GuildID != "guild" || nested.Discord.ChangelogChannelID != "announcements" || nested.Discord.APIWebhookURL != "api" {
		t.Fatalf("nested Discord config was not decoded: %#v", nested.Discord)
	}

	var legacy ConfigType
	if err := json.Unmarshal([]byte(`{"discord_token":"token","discord_invite_link":"https://discord.gg/ban","discord_hook":"user","discord_notif_hook":"server","discord_api_notif_hook":"api","discord_changelog_channel_id":"announcements"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Discord.BotToken != "token" || legacy.Discord.InviteURL != "https://discord.gg/ban" || legacy.Discord.UserWebhookURL != "user" || legacy.Discord.ServerWebhookURL != "server" || legacy.Discord.ChangelogChannelID != "announcements" {
		t.Fatalf("legacy Discord config was not migrated: %#v", legacy.Discord)
	}
	if legacy.Discord.GuildID == "" || legacy.Discord.DevelopmentChannelID == "" {
		t.Fatalf("Discord defaults were not applied: %#v", legacy.Discord)
	}
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
	oldID := Config.Discord.ChangelogChannelID
	oldSession := dg
	defer func() {
		Config.Discord.ChangelogChannelID = oldID
		dg = oldSession
	}()

	Config.Discord.ChangelogChannelID = ""
	dg = nil
	if _, err := getChangelogChannelID(); err == nil {
		t.Fatal("missing Discord session returned nil error")
	}
}

func TestGetChangelogChannelIDReportsMissingChannel(t *testing.T) {
	oldID := Config.Discord.ChangelogChannelID
	oldList := listChangelogChannelsFunc
	defer func() {
		Config.Discord.ChangelogChannelID = oldID
		listChangelogChannelsFunc = oldList
	}()

	Config.Discord.ChangelogChannelID = ""
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
			Title:       "**A smaller search page**",
			Description: "The new layout is live.",
			URL:         "https://mtgban.com/search",
			Author:      &discordgo.MessageEmbedAuthor{Name: "MTGBAN", URL: "https://mtgban.com"},
			Image:       &discordgo.MessageEmbedImage{URL: "https://cdn.discordapp.com/embed.png"},
			Fields: []*discordgo.MessageEmbedField{{
				Name:   "What changed",
				Value:  "**Faster** search",
				Inline: true,
			}},
		}},
		Attachments: []*discordgo.MessageAttachment{{
			Filename:    "preview.png",
			URL:         "https://cdn.discordapp.com/preview.png",
			ContentType: "image/png",
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
	if len(entry.Embeds) != 1 || entry.Embeds[0].Title != "**A smaller search page**" {
		t.Fatalf("unexpected embed mapping: %#v", entry.Embeds)
	}
	if !strings.Contains(string(entry.Embeds[0].TitleHTML), "<strong>A smaller search page</strong>") {
		t.Fatalf("embed title was not formatted: %q", entry.Embeds[0].TitleHTML)
	}
	if entry.Embeds[0].ImageURL != "https://cdn.discordapp.com/embed.png" || len(entry.Embeds[0].Fields) != 1 {
		t.Fatalf("embed media or fields were not mapped: %#v", entry.Embeds[0])
	}
	if len(entry.Attachments) != 1 || entry.Attachments[0].Name != "preview.png" {
		t.Fatalf("unexpected attachments: %#v", entry.Attachments)
	}
	if !entry.Attachments[0].IsImage {
		t.Fatal("PNG attachment was not classified as an image")
	}
}

func TestChangelogEntryFromMessageSkipsEmptyMessages(t *testing.T) {
	if _, ok := changelogEntryFromMessage(&discordgo.Message{}, "channel"); ok {
		t.Fatal("empty message should not become a changelog entry")
	}
}

func TestGroupChangelogEntriesKeepsDiscordOrder(t *testing.T) {
	base := time.Date(2026, time.September, 20, 16, 0, 0, 0, time.UTC)
	entries := []changelogEntry{
		{Content: "oldest", Timestamp: base.Add(-25 * time.Hour)},
		{Content: "newest", Timestamp: base},
		{Content: "same release", Timestamp: base.Add(-time.Hour)},
		{Content: "separate release", Timestamp: base.Add(-8 * time.Hour)},
	}

	groups := groupChangelogEntries(entries)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3: %#v", len(groups), groups)
	}
	if got := groups[0].Entries[0].Content; got != "same release" {
		t.Fatalf("first entry = %q, want oldest-first order within the day", got)
	}
	if len(groups[0].Entries) != 2 || groups[0].Entries[1].Content != "newest" {
		t.Fatalf("same-day entries were not grouped oldest-first: %#v", groups[0].Entries)
	}
	if groups[1].Entries[0].Content != "separate release" || groups[2].Entries[0].Content != "oldest" {
		t.Fatalf("groups are not in reverse chronological order: %#v", groups)
	}
}

func TestChangelogMentionsAndCustomEmoji(t *testing.T) {
	message := &discordgo.Message{
		ID:      "123",
		GuildID: "guild",
		Content: "Welcome <@123> <@&456> <#789> <:party:123456789012345678> _updates_",
	}
	labels := changelogMentionLabels{
		Users:    map[string]string{"123": "@alice"},
		Roles:    map[string]string{"456": "@moderators"},
		Channels: map[string]string{"789": "#general"},
	}
	entry, ok := changelogEntryFromMessageWithLabels(message, "channel", labels)
	if !ok {
		t.Fatal("changelogEntryFromMessageWithLabels returned ok=false")
	}
	for _, want := range []string{
		"@alice",
		"@moderators",
		"#general",
		"changelog-mention-user",
		"changelog-mention-role",
		"changelog-mention-channel",
		`class="changelog-emoji"`,
		"alt=\":party:\"",
		"<em>updates</em>",
	} {
		if !strings.Contains(string(entry.ContentHTML), want) {
			t.Errorf("rendered content missing %q: %s", want, entry.ContentHTML)
		}
	}
}

func TestChangelogEntryKeepsEmbeddedURL(t *testing.T) {
	message := &discordgo.Message{
		ID:      "123",
		GuildID: "guild",
		Content: "https://mtgban.com/search?q=secret",
		Embeds: []*discordgo.MessageEmbed{{
			URL: "https://mtgban.com/search?q=secret",
		}},
	}
	entry, ok := changelogEntryFromMessage(message, "channel")
	if !ok {
		t.Fatal("changelogEntryFromMessage returned ok=false")
	}
	if entry.Content == "" || !strings.Contains(string(entry.ContentHTML), "https://mtgban.com/search?q=secret") {
		t.Fatalf("embedded URL was not kept in message content: content=%q html=%q", entry.Content, entry.ContentHTML)
	}
}

func TestChangelogEntrySanitizesMediaURLs(t *testing.T) {
	message := &discordgo.Message{
		ID: "123",
		Embeds: []*discordgo.MessageEmbed{{
			URL:       "javascript:alert(1)",
			Image:     &discordgo.MessageEmbedImage{URL: "https://cdn.discordapp.com/image.png?size=1024&width=640"},
			Thumbnail: &discordgo.MessageEmbedThumbnail{URL: "data:text/html,unsafe"},
			Author:    &discordgo.MessageEmbedAuthor{URL: "https://mtgban.com/author", IconURL: "javascript:alert(1)"},
			Footer:    &discordgo.MessageEmbedFooter{IconURL: "https://cdn.discordapp.com/footer.png"},
		}},
		Attachments: []*discordgo.MessageAttachment{{URL: "javascript:alert(1)", Filename: "unsafe.png"}},
	}

	entry, ok := changelogEntryFromMessage(message, "channel")
	if !ok {
		t.Fatal("changelogEntryFromMessage returned ok=false")
	}
	embed := entry.Embeds[0]
	if embed.URL != "" || embed.ThumbnailURL != "" || embed.AuthorIconURL != "" {
		t.Fatalf("unsafe embed URLs were retained: %#v", embed)
	}
	if embed.ImageURL == "" || embed.AuthorURL == "" || embed.FooterIconURL == "" {
		t.Fatalf("safe embed URLs were discarded: %#v", embed)
	}
	if entry.Attachments[0].URL != "" {
		t.Fatalf("unsafe attachment URL was retained: %#v", entry.Attachments[0])
	}
}

func TestChangelogPaginationKeepsPartialLastPage(t *testing.T) {
	groups := make([]changelogGroup, changelogPageSize+1)
	page, pagination := Paginate(groups, 2, changelogPageSize, len(groups)+changelogPageSize-1)
	if len(page) != 1 || pagination.TotalIndex != 2 || pagination.CurrentIndex != 2 || pagination.PrevIndex != 1 || pagination.NextIndex != 0 {
		t.Fatalf("partial last page was not reachable: page=%d pagination=%+v", len(page), pagination)
	}
}

func TestRenderDiscordMarkdownEscapesAndDecorates(t *testing.T) {
	rendered := string(renderDiscordMarkdown("**bold** and *italic* [site](https://mtgban.com) https://mtgban.com/search?q=secret <script>\n> quote\n- list with `code`\n||hidden||"))
	for _, want := range []string{
		"<strong>bold</strong>",
		"<em>italic</em>",
		`href="https://mtgban.com"`,
		"mtgban.com/search",
		"&lt;script&gt;",
		"changelog-quote",
		"changelog-spoiler",
		"changelog-list-content",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered markdown missing %q: %s", want, rendered)
		}
	}
	if strings.Contains(rendered, "<script>") {
		t.Fatal("rendered markdown contains unescaped HTML")
	}
}

func TestIsChangelogImage(t *testing.T) {
	if !isChangelogImage("preview.bin", "image/webp") {
		t.Fatal("image content type was not recognized")
	}
	if !isChangelogImage("preview.PNG", "") {
		t.Fatal("image extension was not recognized")
	}
	if isChangelogImage("notes.txt", "text/plain") {
		t.Fatal("text attachment was classified as an image")
	}
}
