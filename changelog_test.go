package main

import (
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

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
