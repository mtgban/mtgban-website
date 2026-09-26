package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	defaultChangelogChannelName = "ban-nouncement"
	changelogDisplayTimezone    = "Europe/Rome"
	changelogMessageLimit       = 100
	changelogPageSize           = 8
	changelogGroupWindow        = 4 * time.Hour
	changelogCacheTTL           = 5 * time.Minute
	changelogRetryBackoff       = 30 * time.Second
)

var changelogDisplayLocation = loadChangelogDisplayLocation()

func loadChangelogDisplayLocation() *time.Location {
	location, err := time.LoadLocation(changelogDisplayTimezone)
	if err != nil {
		return time.Local
	}
	return location
}

type changelogAttachment struct {
	Name        string
	URL         string
	ContentType string
	Width       int
	Height      int
	IsImage     bool
}

type changelogEmbedField struct {
	Name      string
	NameHTML  template.HTML
	Value     string
	ValueHTML template.HTML
	Inline    bool
}

type changelogEmbed struct {
	Title           string
	TitleHTML       template.HTML
	Description     string
	DescriptionHTML template.HTML
	URL             string
	ImageURL        string
	ThumbnailURL    string
	Fields          []changelogEmbedField
	AuthorName      string
	AuthorNameHTML  template.HTML
	AuthorURL       string
	AuthorIconURL   string
	FooterText      string
	FooterTextHTML  template.HTML
	FooterIconURL   string
}

type changelogEntry struct {
	ID            string
	Timestamp     time.Time
	Content       string
	ContentHTML   template.HTML
	Published     string
	PublishedTime string
	SourceURL     string
	Embeds        []changelogEmbed
	Attachments   []changelogAttachment
}

type changelogGroup struct {
	Label   string
	Entries []changelogEntry
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

type changelogMentionLabels struct {
	Users    map[string]string
	Roles    map[string]string
	Channels map[string]string
}

var (
	changelogUserMentionPattern    = regexp.MustCompile(`<@!?([0-9]+)>`)
	changelogRoleMentionPattern    = regexp.MustCompile(`<@&([0-9]+)>`)
	changelogChannelMentionPattern = regexp.MustCompile(`<#([0-9]+)>`)
)

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
	groups := groupChangelogEntries(entries)
	pageIndex := atoiDefault(r.URL.Query().Get("page"), 1)
	// Paginate caps the number of pages from maxTotalResults. Round that cap up
	// so a final partial page of groups remains reachable.
	pageVars.Changelog, pageVars.Pagination = Paginate(groups, pageIndex, changelogPageSize, len(groups)+changelogPageSize-1)
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

		// Like the waiters, loop to serve what the refresh left in the cache.
		refreshChangelog(done)
	}
}

// refreshChangelog fills the cache and wakes the callers waiting on done.
// A panicking fetch leaves err at its initial value, so the deferred
// bookkeeping backs off as after any failure while the panic carries on.
func refreshChangelog(done chan struct{}) {
	var entries []changelogEntry
	err := errors.New("refresh panicked")
	defer func() {
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
		changelogCacheMu.Unlock()
	}()

	entries, err = fetchChangelogEntriesFunc()
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

	mentionLabels := resolveChangelogMentionLabels(messages)
	entries := make([]changelogEntry, 0, len(messages))
	for _, message := range messages {
		entry, ok := changelogEntryFromMessageWithLabels(message, channelID, mentionLabels)
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func getChangelogChannelID() (string, error) {
	if Config.Discord.ChangelogChannelID != "" {
		return Config.Discord.ChangelogChannelID, nil
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
	return dg.GuildChannels(discordGuildID())
}

func changelogEntryFromMessage(message *discordgo.Message, channelID string) (changelogEntry, bool) {
	return changelogEntryFromMessageWithLabels(message, channelID, changelogMentionLabels{})
}

func changelogEntryFromMessageWithLabels(message *discordgo.Message, channelID string, mentionLabels changelogMentionLabels) (changelogEntry, bool) {
	if message == nil {
		return changelogEntry{}, false
	}
	if strings.TrimSpace(message.Content) == "" && len(message.Embeds) == 0 && len(message.Attachments) == 0 {
		return changelogEntry{}, false
	}

	guildID := message.GuildID
	if guildID == "" {
		guildID = discordGuildID()
	}
	entry := changelogEntry{
		ID:            message.ID,
		Timestamp:     message.Timestamp,
		Content:       replaceChangelogMentions(message.Content, mentionLabels),
		ContentHTML:   renderDiscordMarkdownWithLabels(message.Content, mentionLabels),
		Published:     message.Timestamp.In(changelogDisplayLocation).Format("Jan 2, 2006"),
		PublishedTime: message.Timestamp.In(changelogDisplayLocation).Format("15:04"),
		SourceURL:     fmt.Sprintf("https://discord.com/channels/%s/%s/%s", guildID, channelID, message.ID),
	}

	for _, embed := range message.Embeds {
		if embed == nil {
			continue
		}
		mapped := changelogEmbed{
			Title:           replaceChangelogMentions(embed.Title, mentionLabels),
			TitleHTML:       renderDiscordMarkdownWithLabels(embed.Title, mentionLabels),
			Description:     replaceChangelogMentions(embed.Description, mentionLabels),
			DescriptionHTML: renderDiscordMarkdownWithLabels(embed.Description, mentionLabels),
			URL:             safeChangelogURL(embed.URL),
		}
		if embed.Image != nil {
			mapped.ImageURL = safeChangelogURL(embed.Image.URL)
		}
		if embed.Thumbnail != nil {
			mapped.ThumbnailURL = safeChangelogURL(embed.Thumbnail.URL)
		}
		if embed.Author != nil {
			mapped.AuthorName = replaceChangelogMentions(embed.Author.Name, mentionLabels)
			mapped.AuthorNameHTML = renderDiscordMarkdownWithLabels(embed.Author.Name, mentionLabels)
			mapped.AuthorURL = safeChangelogURL(embed.Author.URL)
			mapped.AuthorIconURL = safeChangelogURL(embed.Author.IconURL)
		}
		if embed.Footer != nil {
			mapped.FooterText = replaceChangelogMentions(embed.Footer.Text, mentionLabels)
			mapped.FooterTextHTML = renderDiscordMarkdownWithLabels(embed.Footer.Text, mentionLabels)
			mapped.FooterIconURL = safeChangelogURL(embed.Footer.IconURL)
		}
		for _, field := range embed.Fields {
			if field == nil {
				continue
			}
			mapped.Fields = append(mapped.Fields, changelogEmbedField{
				Name:      replaceChangelogMentions(field.Name, mentionLabels),
				NameHTML:  renderDiscordMarkdownWithLabels(field.Name, mentionLabels),
				Value:     replaceChangelogMentions(field.Value, mentionLabels),
				ValueHTML: renderDiscordMarkdownWithLabels(field.Value, mentionLabels),
				Inline:    field.Inline,
			})
		}
		entry.Embeds = append(entry.Embeds, mapped)
	}
	for _, attachment := range message.Attachments {
		if attachment == nil {
			continue
		}
		entry.Attachments = append(entry.Attachments, changelogAttachment{
			Name:        attachment.Filename,
			URL:         safeChangelogURL(attachment.URL),
			ContentType: attachment.ContentType,
			Width:       attachment.Width,
			Height:      attachment.Height,
			IsImage:     isChangelogImage(attachment.Filename, attachment.ContentType),
		})
	}
	return entry, true
}

func resolveChangelogMentionLabels(messages []*discordgo.Message) changelogMentionLabels {
	labels := changelogMentionLabels{
		Users:    make(map[string]string),
		Roles:    make(map[string]string),
		Channels: make(map[string]string),
	}
	roleIDs := make(map[string]struct{})
	channelIDs := make(map[string]struct{})
	for _, message := range messages {
		if message == nil {
			continue
		}
		for _, user := range message.Mentions {
			if user != nil && user.ID != "" && user.Username != "" {
				labels.Users[user.ID] = "@" + user.Username
			}
		}
		for _, roleID := range message.MentionRoles {
			roleIDs[roleID] = struct{}{}
		}
		for _, channel := range message.MentionChannels {
			if channel != nil && channel.ID != "" && channel.Name != "" {
				labels.Channels[channel.ID] = "#" + channel.Name
			}
		}
		collectChangelogChannelMentionIDs(message.Content, channelIDs)
		for _, embed := range message.Embeds {
			if embed == nil {
				continue
			}
			collectChangelogChannelMentionIDs(embed.Title, channelIDs)
			collectChangelogChannelMentionIDs(embed.Description, channelIDs)
			if embed.Author != nil {
				collectChangelogChannelMentionIDs(embed.Author.Name, channelIDs)
			}
			if embed.Footer != nil {
				collectChangelogChannelMentionIDs(embed.Footer.Text, channelIDs)
			}
			for _, field := range embed.Fields {
				if field != nil {
					collectChangelogChannelMentionIDs(field.Name, channelIDs)
					collectChangelogChannelMentionIDs(field.Value, channelIDs)
				}
			}
		}
	}
	if len(roleIDs) > 0 && dg != nil {
		roles, err := dg.GuildRoles(discordGuildID())
		if err != nil {
			log.Println("changelog: resolving Discord roles:", err)
		} else {
			for _, role := range roles {
				if role != nil {
					if _, mentioned := roleIDs[role.ID]; mentioned && role.Name != "" {
						labels.Roles[role.ID] = "@" + role.Name
					}
				}
			}
		}
	}
	if len(channelIDs) > 0 && dg != nil {
		channels, err := dg.GuildChannels(discordGuildID())
		if err != nil {
			log.Println("changelog: resolving Discord channels:", err)
		} else {
			for _, channel := range channels {
				if channel != nil {
					if _, mentioned := channelIDs[channel.ID]; mentioned && channel.Name != "" {
						labels.Channels[channel.ID] = "#" + channel.Name
					}
				}
			}
		}
	}
	return labels
}

func collectChangelogChannelMentionIDs(input string, channelIDs map[string]struct{}) {
	for _, match := range changelogChannelMentionPattern.FindAllStringSubmatch(input, -1) {
		if len(match) == 2 {
			channelIDs[match[1]] = struct{}{}
		}
	}
}

func replaceChangelogMentions(input string, labels changelogMentionLabels) string {
	input = changelogUserMentionPattern.ReplaceAllStringFunc(input, func(token string) string {
		match := changelogUserMentionPattern.FindStringSubmatch(token)
		if len(match) == 2 {
			if label := labels.Users[match[1]]; label != "" {
				return label
			}
		}
		return token
	})
	input = changelogRoleMentionPattern.ReplaceAllStringFunc(input, func(token string) string {
		match := changelogRoleMentionPattern.FindStringSubmatch(token)
		if len(match) == 2 {
			if label := labels.Roles[match[1]]; label != "" {
				return label
			}
		}
		return token
	})
	return changelogChannelMentionPattern.ReplaceAllStringFunc(input, func(token string) string {
		match := changelogChannelMentionPattern.FindStringSubmatch(token)
		if len(match) == 2 {
			if label := labels.Channels[match[1]]; label != "" {
				return label
			}
		}
		return token
	})
}

func changelogMentionAt(input string, labels changelogMentionLabels) (string, string, int, bool) {
	mentions := []struct {
		pattern *regexp.Regexp
		labels  map[string]string
		class   string
	}{
		{changelogUserMentionPattern, labels.Users, "changelog-mention-user"},
		{changelogRoleMentionPattern, labels.Roles, "changelog-mention-role"},
		{changelogChannelMentionPattern, labels.Channels, "changelog-mention-channel"},
	}
	for _, mention := range mentions {
		indices := mention.pattern.FindStringIndex(input)
		if indices == nil || indices[0] != 0 {
			continue
		}
		match := mention.pattern.FindStringSubmatch(input[:indices[1]])
		if len(match) == 2 {
			if label := mention.labels[match[1]]; label != "" {
				return label, mention.class, indices[1], true
			}
		}
	}
	return "", "", 0, false
}

func groupChangelogEntries(entries []changelogEntry) []changelogGroup {
	ordered := append([]changelogEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Timestamp.After(ordered[j].Timestamp)
	})

	groups := make([]changelogGroup, 0, len(ordered))
	for _, entry := range ordered {
		day := changelogDayKey(entry.Timestamp)
		previousDay := ""
		if len(groups) > 0 {
			previousDay = changelogDayKey(groups[len(groups)-1].Entries[0].Timestamp)
		}
		if len(groups) == 0 || day == "" || previousDay == "" || day != previousDay ||
			groups[len(groups)-1].Entries[0].Timestamp.Sub(entry.Timestamp) > changelogGroupWindow {
			label := entry.Published
			if label == "" {
				label = "Undated"
			}
			groups = append(groups, changelogGroup{Label: label, Entries: []changelogEntry{entry}})
			continue
		}
		groups[len(groups)-1].Entries = append(groups[len(groups)-1].Entries, entry)
	}
	for i := range groups {
		for left, right := 0, len(groups[i].Entries)-1; left < right; left, right = left+1, right-1 {
			groups[i].Entries[left], groups[i].Entries[right] = groups[i].Entries[right], groups[i].Entries[left]
		}
	}
	return groups
}

func changelogDayKey(timestamp time.Time) string {
	if timestamp.IsZero() {
		return ""
	}
	return timestamp.In(changelogDisplayLocation).Format("2006-01-02")
}

func isChangelogImage(filename, contentType string) bool {
	if strings.HasPrefix(strings.ToLower(contentType), "image/") {
		return true
	}
	switch strings.ToLower(path.Ext(filename)) {
	case ".avif", ".gif", ".jpeg", ".jpg", ".png", ".webp":
		return true
	default:
		return false
	}
}

func renderDiscordMarkdown(input string) template.HTML {
	return renderDiscordMarkdownWithLabels(input, changelogMentionLabels{})
}

func renderDiscordMarkdownWithLabels(input string, mentionLabels changelogMentionLabels) template.HTML {
	input = strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	if input == "" {
		return ""
	}

	var output strings.Builder
	lines := strings.Split(input, "\n")
	inCodeBlock := false
	var listIndents []int
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		isListItem := !inCodeBlock && (strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "))
		if !isListItem {
			listIndents = listIndents[:0]
		}
		if strings.HasPrefix(trimmed, "```") {
			if inCodeBlock {
				output.WriteString("</code></pre>")
			} else {
				output.WriteString(`<pre class="changelog-code"><code>`)
			}
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			output.WriteString(template.HTMLEscapeString(line))
			output.WriteByte('\n')
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "### "):
			output.WriteString(`<p class="changelog-markdown-heading changelog-markdown-heading-3">`)
			output.WriteString(renderDiscordInline(strings.TrimSpace(trimmed[4:]), 0, mentionLabels))
			output.WriteString("</p>")
		case strings.HasPrefix(trimmed, "## "):
			output.WriteString(`<p class="changelog-markdown-heading changelog-markdown-heading-2">`)
			output.WriteString(renderDiscordInline(strings.TrimSpace(trimmed[3:]), 0, mentionLabels))
			output.WriteString("</p>")
		case strings.HasPrefix(trimmed, "# "):
			output.WriteString(`<p class="changelog-markdown-heading changelog-markdown-heading-1">`)
			output.WriteString(renderDiscordInline(strings.TrimSpace(trimmed[2:]), 0, mentionLabels))
			output.WriteString("</p>")
		case strings.HasPrefix(trimmed, ">"):
			output.WriteString(`<blockquote class="changelog-quote">`)
			output.WriteString(renderDiscordInline(strings.TrimSpace(strings.TrimPrefix(trimmed, ">")), 0, mentionLabels))
			output.WriteString("</blockquote>")
		case isListItem:
			var depth int
			listIndents, depth = changelogListDepth(listIndents, line)
			if depth == 0 {
				output.WriteString(`<p class="changelog-list-item">`)
			} else {
				output.WriteString(`<p class="changelog-list-item" style="--changelog-list-depth: ` + strconv.Itoa(depth) + `">`)
			}
			output.WriteString(`<span class="changelog-list-marker" aria-hidden="true">` + changelogListMarkers[min(depth, len(changelogListMarkers)-1)] + `</span><span class="changelog-list-content">`)
			output.WriteString(renderDiscordInline(strings.TrimSpace(trimmed[2:]), 0, mentionLabels))
			output.WriteString("</span></p>")
		case trimmed == "":
			output.WriteString(`<span class="changelog-line-break" aria-hidden="true"></span>`)
		default:
			output.WriteString(`<p class="changelog-markdown-line">`)
			output.WriteString(renderDiscordInline(line, 0, mentionLabels))
			output.WriteString("</p>")
		}
	}
	if inCodeBlock {
		output.WriteString("</code></pre>")
	}
	return template.HTML(output.String())
}

// changelogListMarkers are the bullets per nesting level, deepest repeating.
var changelogListMarkers = []string{"•", "◦", "▪"}

// changelogListDepth nests a bullet line under the nearest shallower bullet
// above it, given the indents of the bullets still open. As in Discord, any
// deeper indent is one level down however wide it is, and a tab counts as
// four spaces.
func changelogListDepth(indents []int, line string) ([]int, int) {
	indent := 0
	for _, r := range line {
		if r == ' ' {
			indent++
		} else if r == '\t' {
			indent += 4
		} else {
			break
		}
	}
	for len(indents) > 0 && indents[len(indents)-1] > indent {
		indents = indents[:len(indents)-1]
	}
	if len(indents) == 0 || indents[len(indents)-1] < indent {
		indents = append(indents, indent)
	}
	return indents, len(indents) - 1
}

func renderDiscordInline(input string, depth int, mentionLabels changelogMentionLabels) string {
	if depth > 6 {
		return template.HTMLEscapeString(input)
	}
	var output strings.Builder
outer:
	for i := 0; i < len(input); {
		if input[i] == '`' {
			if end := strings.IndexByte(input[i+1:], '`'); end >= 0 {
				output.WriteString(`<code class="changelog-inline-code">`)
				output.WriteString(template.HTMLEscapeString(input[i+1 : i+1+end]))
				output.WriteString("</code>")
				i += end + 2
				continue
			}
		}
		for _, mark := range []struct {
			delimiter string
			tag       string
		}{
			{"**", "strong"},
			{"__", "u"},
			{"~~", "del"},
		} {
			if strings.HasPrefix(input[i:], mark.delimiter) {
				if end := strings.Index(input[i+len(mark.delimiter):], mark.delimiter); end > 0 {
					output.WriteString("<" + mark.tag + ">")
					output.WriteString(renderDiscordInline(input[i+len(mark.delimiter):i+len(mark.delimiter)+end], depth+1, mentionLabels))
					output.WriteString("</" + mark.tag + ">")
					i += len(mark.delimiter)*2 + end
					continue outer
				}
			}
		}
		if strings.HasPrefix(input[i:], "||") {
			if end := strings.Index(input[i+2:], "||"); end > 0 {
				output.WriteString(`<span class="changelog-spoiler" tabindex="0" role="button" aria-label="Reveal spoiler">`)
				output.WriteString(renderDiscordInline(input[i+2:i+2+end], depth+1, mentionLabels))
				output.WriteString("</span>")
				i += end + 4
				continue
			}
		}
		if input[i] == '*' && (i+1 < len(input)) {
			if end := strings.IndexByte(input[i+1:], '*'); end > 0 {
				output.WriteString("<em>")
				output.WriteString(renderDiscordInline(input[i+1:i+1+end], depth+1, mentionLabels))
				output.WriteString("</em>")
				i += end + 2
				continue
			}
		}
		if input[i] == '_' && i+1 < len(input) && (i == 0 || input[i-1] != '_') {
			if end := strings.IndexByte(input[i+1:], '_'); end > 0 {
				output.WriteString("<em>")
				output.WriteString(renderDiscordInline(input[i+1:i+1+end], depth+1, mentionLabels))
				output.WriteString("</em>")
				i += end + 2
				continue
			}
		}
		if input[i] == '<' {
			if label, class, length, ok := changelogMentionAt(input[i:], mentionLabels); ok {
				output.WriteString(`<span class="changelog-mention ` + class + `">`)
				output.WriteString(template.HTMLEscapeString(label))
				output.WriteString(`</span>`)
				i += length
				continue
			}
			if matchIndices := discordgo.EmojiRegex.FindStringIndex(input[i:]); matchIndices != nil && matchIndices[0] == 0 {
				match := input[i : i+matchIndices[1]]
				output.WriteString(renderChangelogEmoji(match))
				i += len(match)
				continue
			}
		}
		if input[i] == '[' {
			if closeLabel := strings.IndexByte(input[i+1:], ']'); closeLabel >= 0 {
				labelEnd := i + 1 + closeLabel
				if labelEnd+1 < len(input) && input[labelEnd+1] == '(' {
					if closeURL := strings.IndexByte(input[labelEnd+2:], ')'); closeURL >= 0 {
						linkURL := input[labelEnd+2 : labelEnd+2+closeURL]
						if safeURL := safeChangelogURL(linkURL); safeURL != "" {
							output.WriteString(`<a class="changelog-inline-link" href="` + template.HTMLEscapeString(safeURL) + `" target="_blank" rel="noopener">`)
							output.WriteString(renderDiscordInline(input[i+1:labelEnd], depth+1, mentionLabels))
							output.WriteString("</a>")
							i = labelEnd + closeURL + 3
							continue
						}
					}
				}
			}
		}
		if strings.HasPrefix(input[i:], "http://") || strings.HasPrefix(input[i:], "https://") {
			end := i
			for end < len(input) && !strings.ContainsRune(" \t\n", rune(input[end])) {
				end++
			}
			linkText := strings.TrimRight(input[i:end], ".,!?;:)")
			if safeURL := safeChangelogURL(linkText); safeURL != "" {
				output.WriteString(`<a class="changelog-inline-link" href="` + template.HTMLEscapeString(safeURL) + `" target="_blank" rel="noopener">`)
				output.WriteString(template.HTMLEscapeString(linkText))
				output.WriteString("</a>")
				output.WriteString(template.HTMLEscapeString(input[i+len(linkText) : end]))
				i = end
				continue
			}
		}
		start := i
		for i < len(input) && !strings.ContainsRune("`*_~[<h", rune(input[i])) {
			i++
		}
		if start == i {
			output.WriteString(template.HTMLEscapeString(input[i : i+1]))
			i++
		} else {
			output.WriteString(template.HTMLEscapeString(input[start:i]))
		}
	}
	return output.String()
}

func renderChangelogEmoji(token string) string {
	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		return template.HTMLEscapeString(token)
	}
	animated := strings.HasPrefix(token, "<a:")
	name := template.HTMLEscapeString(parts[1])
	id := template.HTMLEscapeString(strings.TrimSuffix(parts[2], ">"))
	extension := "png"
	if animated {
		extension = "gif"
	}
	return fmt.Sprintf(`<img class="changelog-emoji" src="https://cdn.discordapp.com/emojis/%s.%s?size=24&amp;quality=lossless" alt=":%s:" title=":%s:" loading="lazy">`, id, extension, name, name)
}

func safeChangelogURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return parsed.String()
}

func cloneChangelogEntries(entries []changelogEntry) []changelogEntry {
	clone := make([]changelogEntry, len(entries))
	for i, entry := range entries {
		clone[i] = entry
		clone[i].ContentHTML = entry.ContentHTML
		clone[i].Embeds = append([]changelogEmbed(nil), entry.Embeds...)
		for j := range clone[i].Embeds {
			clone[i].Embeds[j].Fields = append([]changelogEmbedField(nil), entry.Embeds[j].Fields...)
		}
		clone[i].Attachments = append([]changelogAttachment(nil), entry.Attachments...)
	}
	return clone
}
