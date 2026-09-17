package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	defaultChangelogChannelName = "ban-nouncement"
	changelogMessageLimit       = 100
	changelogCacheTTL           = 5 * time.Minute
)

type ChangelogAttachment struct {
	Name string
	URL  string
}

type ChangelogEmbed struct {
	Title       string
	Description string
	URL         string
}

type ChangelogEntry struct {
	Content     string
	Published   string
	SourceURL   string
	Embeds      []ChangelogEmbed
	Attachments []ChangelogAttachment
}

type changelogCache struct {
	entries   []ChangelogEntry
	refreshed time.Time
}

var changelogCacheMu sync.Mutex
var cachedChangelog changelogCache

// Changelog renders the public release notes page. Discord is the source of
// truth; this process-local cache keeps page views from turning into a Discord
// API request for every visitor.
func Changelog(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav(r, "Changelog", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	entries, err := getChangelogEntries()
	pageVars.Changelog = entries
	if err != nil {
		pageVars.ChangelogError = "Announcements are temporarily unavailable."
		log.Println("changelog:", err)
	}

	render(w, "changelog.html", pageVars)
}

func getChangelogEntries() ([]ChangelogEntry, error) {
	changelogCacheMu.Lock()
	defer changelogCacheMu.Unlock()

	if !cachedChangelog.refreshed.IsZero() && time.Since(cachedChangelog.refreshed) < changelogCacheTTL {
		return cloneChangelogEntries(cachedChangelog.entries), nil
	}

	entries, err := fetchChangelogEntries()
	if err != nil {
		if len(cachedChangelog.entries) > 0 {
			return cloneChangelogEntries(cachedChangelog.entries), nil
		}
		return nil, err
	}

	cachedChangelog = changelogCache{
		entries:   entries,
		refreshed: time.Now(),
	}
	return cloneChangelogEntries(entries), nil
}

func fetchChangelogEntries() ([]ChangelogEntry, error) {
	if dg == nil {
		return nil, errors.New("discord session is not available")
	}

	channelID, err := getChangelogChannelID()
	if err != nil {
		return nil, err
	}

	messages, err := dg.ChannelMessages(channelID, changelogMessageLimit, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("reading channel %s: %w", channelID, err)
	}

	entries := make([]ChangelogEntry, 0, len(messages))
	for _, message := range messages {
		entry, ok := changelogEntryFromMessage(message, channelID)
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func getChangelogChannelID() (string, error) {
	if Config.DiscordChangelogChannelID != "" {
		return Config.DiscordChangelogChannelID, nil
	}
	if dg == nil {
		return "", errors.New("discord session is not available")
	}

	channels, err := dg.GuildChannels(MainDiscordID)
	if err != nil {
		return "", fmt.Errorf("listing Discord channels: %w", err)
	}
	for _, channel := range channels {
		if channel != nil && channel.Name == defaultChangelogChannelName {
			return channel.ID, nil
		}
	}
	return "", fmt.Errorf("Discord channel %q was not found", defaultChangelogChannelName)
}

func changelogEntryFromMessage(message *discordgo.Message, channelID string) (ChangelogEntry, bool) {
	if message == nil {
		return ChangelogEntry{}, false
	}
	if strings.TrimSpace(message.Content) == "" && len(message.Embeds) == 0 && len(message.Attachments) == 0 {
		return ChangelogEntry{}, false
	}

	guildID := message.GuildID
	if guildID == "" {
		guildID = MainDiscordID
	}
	entry := ChangelogEntry{
		Content:   message.Content,
		Published: message.Timestamp.Format("Jan 2, 2006"),
		SourceURL: fmt.Sprintf("https://discord.com/channels/%s/%s/%s", guildID, channelID, message.ID),
	}

	for _, embed := range message.Embeds {
		if embed == nil {
			continue
		}
		entry.Embeds = append(entry.Embeds, ChangelogEmbed{
			Title:       embed.Title,
			Description: embed.Description,
			URL:         embed.URL,
		})
	}
	for _, attachment := range message.Attachments {
		if attachment == nil {
			continue
		}
		entry.Attachments = append(entry.Attachments, ChangelogAttachment{
			Name: attachment.Filename,
			URL:  attachment.URL,
		})
	}
	return entry, true
}

func cloneChangelogEntries(entries []ChangelogEntry) []ChangelogEntry {
	clone := make([]ChangelogEntry, len(entries))
	for i, entry := range entries {
		clone[i] = entry
		clone[i].Embeds = append([]ChangelogEmbed(nil), entry.Embeds...)
		clone[i].Attachments = append([]ChangelogAttachment(nil), entry.Attachments...)
	}
	return clone
}
