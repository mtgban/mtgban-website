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
	changelogRetryBackoff       = 30 * time.Second
)

type changelogAttachment struct {
	Name string
	URL  string
}

type changelogEmbed struct {
	Title       string
	Description string
	URL         string
}

type changelogEntry struct {
	Content     string
	Published   string
	SourceURL   string
	Embeds      []changelogEmbed
	Attachments []changelogAttachment
}

type changelogCache struct {
	entries     []changelogEntry
	refreshed   time.Time
	retryAfter  time.Time
	lastErr     error
	refreshing  bool
	refreshDone chan struct{}
}

var changelogCacheMu sync.Mutex
var cachedChangelog changelogCache
var fetchChangelogEntriesFunc = fetchChangelogEntries
var listChangelogChannelsFunc = listChangelogChannels

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

func getChangelogEntries() ([]changelogEntry, error) {
	for {
		now := time.Now()
		changelogCacheMu.Lock()
		if !cachedChangelog.refreshed.IsZero() && now.Sub(cachedChangelog.refreshed) < changelogCacheTTL {
			entries := cloneChangelogEntries(cachedChangelog.entries)
			changelogCacheMu.Unlock()
			return entries, nil
		}
		if now.Before(cachedChangelog.retryAfter) {
			entries := cloneChangelogEntries(cachedChangelog.entries)
			err := cachedChangelog.lastErr
			changelogCacheMu.Unlock()
			if len(entries) > 0 {
				return entries, nil
			}
			return nil, err
		}
		if cachedChangelog.refreshing {
			done := cachedChangelog.refreshDone
			changelogCacheMu.Unlock()
			<-done
			continue
		}

		cachedChangelog.refreshing = true
		cachedChangelog.refreshDone = make(chan struct{})
		done := cachedChangelog.refreshDone
		changelogCacheMu.Unlock()

		entries, err := fetchChangelogEntriesFunc()

		changelogCacheMu.Lock()
		if err == nil {
			cachedChangelog.entries = entries
			cachedChangelog.refreshed = time.Now()
			cachedChangelog.retryAfter = time.Time{}
			cachedChangelog.lastErr = nil
		} else {
			cachedChangelog.retryAfter = time.Now().Add(changelogRetryBackoff)
			cachedChangelog.lastErr = err
		}
		cachedChangelog.refreshing = false
		close(done)
		cachedChangelog.refreshDone = nil

		result := cloneChangelogEntries(cachedChangelog.entries)
		resultErr := cachedChangelog.lastErr
		changelogCacheMu.Unlock()
		if len(result) > 0 {
			return result, nil
		}
		return result, resultErr
	}
}

func fetchChangelogEntries() ([]changelogEntry, error) {
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

	entries := make([]changelogEntry, 0, len(messages))
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
	// Existing deployments can bootstrap by name; once the channel ID is
	// configured, the stable ID path above avoids rename ambiguity.
	channels, err := listChangelogChannelsFunc()
	if err != nil {
		return "", fmt.Errorf("listing Discord channels: %w", err)
	}
	for _, channel := range channels {
		if channel != nil && channel.Name == defaultChangelogChannelName {
			return channel.ID, nil
		}
	}
	return "", fmt.Errorf("discord channel %q was not found", defaultChangelogChannelName)
}

func listChangelogChannels() ([]*discordgo.Channel, error) {
	if dg == nil {
		return nil, errors.New("discord session is not available")
	}
	return dg.GuildChannels(MainDiscordID)
}

func changelogEntryFromMessage(message *discordgo.Message, channelID string) (changelogEntry, bool) {
	if message == nil {
		return changelogEntry{}, false
	}
	if strings.TrimSpace(message.Content) == "" && len(message.Embeds) == 0 && len(message.Attachments) == 0 {
		return changelogEntry{}, false
	}

	guildID := message.GuildID
	if guildID == "" {
		guildID = MainDiscordID
	}
	entry := changelogEntry{
		Content:   message.Content,
		Published: message.Timestamp.Local().Format("Jan 2, 2006"),
		SourceURL: fmt.Sprintf("https://discord.com/channels/%s/%s/%s", guildID, channelID, message.ID),
	}

	for _, embed := range message.Embeds {
		if embed == nil {
			continue
		}
		entry.Embeds = append(entry.Embeds, changelogEmbed{
			Title:       embed.Title,
			Description: embed.Description,
			URL:         embed.URL,
		})
	}
	for _, attachment := range message.Attachments {
		if attachment == nil {
			continue
		}
		entry.Attachments = append(entry.Attachments, changelogAttachment{
			Name: attachment.Filename,
			URL:  attachment.URL,
		})
	}
	return entry, true
}

func cloneChangelogEntries(entries []changelogEntry) []changelogEntry {
	clone := make([]changelogEntry, len(entries))
	for i, entry := range entries {
		clone[i] = entry
		clone[i].Embeds = append([]changelogEmbed(nil), entry.Embeds...)
		clone[i].Attachments = append([]changelogAttachment(nil), entry.Attachments...)
	}
	return clone
}
