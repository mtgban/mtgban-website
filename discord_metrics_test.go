package main

import (
	"net/http"
	"slices"
	"testing"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/mtgban-website/observability"
)

func TestDiscordForm(t *testing.T) {
	for _, c := range []struct {
		content string
		chat    bool
		want    string
	}{
		{"!Lightning Bolt", false, "card"}, {"?Alpha Booster Box", false, "sealed"}, {"$$Black Lotus", false, "last_sold"},
		{"anyone seen [[Black Lotus]] lately", true, "brackets"},
		{"anyone seen [[Black Lotus]] lately", false, ""}, // brackets only in the three channels
		{"price of {{Mox Pearl}}?", false, "pricefall"},
		{"https://gatherer.wizards.com/Pages/Card/Details.aspx?multiverseid=3", false, "gatherer_link"},
		{"[[a]] and {{b}}", true, "brackets"},
		{"good morning", true, ""},
	} {
		if got := discordForm(c.content, c.chat); got != c.want {
			t.Errorf("discordForm(%q, %v) = %q, want %q", c.content, c.chat, got, c.want)
		}
	}
}

// Every store the bot answers for has a registry value.
func TestDiscordStoresMatchTheCode(t *testing.T) {
	entry, _ := observability.Lookup("discord.store_link")
	seen := map[string]bool{}
	for _, store := range AffiliateStores {
		v := discordStore(store.Name)
		if v == "" || !slices.Contains(entry.Enum, v) {
			t.Errorf("%s has no registry value (%q)", store.Name, v)
		}
		seen[v] = true
	}
	if len(seen) != len(entry.Enum) {
		t.Errorf("the registry lists %d stores, the code answers for %d", len(entry.Enum), len(seen))
	}
}

// postToBot posts content in channel of the guild the test configured.
func postToBot(t *testing.T, s *site, discord *fakeDiscord, channel, content string) {
	t.Helper()
	s.messageCreate(fakeSession(t, discord), &discordgo.MessageCreate{Message: &discordgo.Message{
		Content: content, Author: &discordgo.User{}, ChannelID: channel, GuildID: "guild",
	}})
}

// withBotGuild sets the main guild and the chat channel, restored at cleanup.
func withBotGuild(t *testing.T) {
	t.Helper()
	oldGuild, oldChat := Config().Discord.GuildID, Config().Discord.ChatChannelID
	t.Cleanup(func() { Config().Discord.GuildID, Config().Discord.ChatChannelID = oldGuild, oldChat })
	Config().Discord.GuildID, Config().Discord.ChatChannelID = "guild", "chat"
}

// Each bracketed card re-enters the lookup; it is one brackets message, not card lookups too.
func TestBracketsCountOnce(t *testing.T) {
	s := lastSoldSite(t, nil)
	rows := withFeatureCounter(t)
	withBotGuild(t)

	discord := &fakeDiscord{}
	postToBot(t, s, discord, "chat", "look at [[Fixture Card Alpha]] and [[Fixture Card Alpha|FIXTUREA]]")
	if len(discord.sent) != 2 {
		t.Fatalf("the bot sent %d replies, want 2", len(discord.sent))
	}
	got := rows.rows()
	wantRow(t, got, "", "discord.message", "brackets", 1)
	if n := len(find(got, "discord.message")); n != 1 {
		t.Fatalf("%d discord.message rows, want 1", n)
	}
	if row := find(got, "discord.message")[0]; row.Device != "discord" {
		t.Errorf("device = %q", row.Device)
	}
}

// A store link answered with an affiliate link counts the store, not a message.
func TestAStoreLinkIsCounted(t *testing.T) {
	s := lastSoldSite(t, nil)
	rows := withFeatureCounter(t)
	withBotGuild(t)

	discord := &fakeDiscord{}
	postToBot(t, s, discord, "chat", "https://www.cardkingdom.com/mtg/fixture-edition-alpha/fixture-card-alpha")
	if len(discord.sent) != 1 {
		t.Fatalf("the bot sent %d replies, want 1", len(discord.sent))
	}
	got := rows.rows()
	wantRow(t, got, "", "discord.store_link", "ck", 1)
	wantNoRow(t, got, "discord.message")
}

func TestAPrefixedLookupIsCounted(t *testing.T) {
	s := lastSoldSite(t, nil)
	rows := withFeatureCounter(t)
	withBotGuild(t)

	discord := &fakeDiscord{}
	postToBot(t, s, discord, "chat", "!Fixture Card Alpha")
	if len(discord.sent) != 1 {
		t.Fatalf("the bot sent %d replies, want 1", len(discord.sent))
	}
	got := rows.rows()
	wantRow(t, got, "", "discord.message", "card", 1)
	wantNoRow(t, got, "discord.store_link")
}

// A message the bot ignores counts nothing.
func TestAnIgnoredMessageCountsNothing(t *testing.T) {
	s := lastSoldSite(t, nil)
	rows := withFeatureCounter(t)
	withBotGuild(t)

	discord := &fakeDiscord{}
	postToBot(t, s, discord, "chat", "good morning")
	s.messageCreate(fakeSession(t, discord), &discordgo.MessageCreate{Message: &discordgo.Message{
		Content: "!Fixture Card Alpha", Author: &discordgo.User{Bot: true}, ChannelID: "chat", GuildID: "guild",
	}})
	if len(discord.sent) != 0 {
		t.Fatalf("the bot sent %d replies, want 0", len(discord.sent))
	}
	got := rows.rows()
	wantNoRow(t, got, "discord.message")
	wantNoRow(t, got, "discord.store_link")
}

// panicSend panics on every message the bot sends.
type panicSend struct{}

func (panicSend) RoundTrip(*http.Request) (*http.Response, error) {
	panic("the reply broke")
}

// A lookup that panics is recovered and reported by itself, so the loop over a
// message's brackets goes on. Driven directly: discordgo leaves its rate-limit
// bucket locked when a send panics, so a second send in the same channel would hang.
func TestADiscordLookupRecoversAlone(t *testing.T) {
	s := lastSoldSite(t, nil)
	posts := serverWebhook(t)

	session, err := discordgo.New("Bot test")
	if err != nil {
		t.Fatal(err)
	}
	session.Client = &http.Client{Transport: panicSend{}}
	m := &discordgo.MessageCreate{Message: &discordgo.Message{
		Content: "!Fixture Card Alpha", Author: &discordgo.User{}, ChannelID: "chat", GuildID: "guild",
	}}
	s.discordLookup(session, m, s.datastore(), s.prices())

	message, _, source := panicReport(t, posts)
	if message != "the reply broke" || source != "source job: discord messageCreate" {
		t.Errorf("report %q from %q, want the send's panic from the handler", message, source)
	}
}
