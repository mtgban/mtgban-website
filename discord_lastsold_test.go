package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

// fakeDiscord answers the bot's REST calls in Discord's place, keeping the
// embed of each message sent and each edit. With refuseSends it answers a
// send as Discord does a bot missing a permission in the channel, and
// counts it in refused.
type fakeDiscord struct {
	refuseSends bool

	sent    []*discordgo.MessageEmbed
	refused int
	edited  []*discordgo.MessageEmbed
}

func (f *fakeDiscord) RoundTrip(req *http.Request) (*http.Response, error) {
	var body struct {
		Embeds []*discordgo.MessageEmbed `json:"embeds"`
	}
	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		return nil, err
	}

	status, reply := http.StatusOK, `{"id":"1"}`
	switch {
	case req.Method == http.MethodPost && f.refuseSends:
		f.refused++
		status, reply = http.StatusForbidden, `{"code":50013,"message":"Missing Permissions"}`
	case req.Method == http.MethodPost:
		f.sent = append(f.sent, body.Embeds...)
	case req.Method == http.MethodPatch:
		f.edited = append(f.edited, body.Embeds...)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprint(status, " ", http.StatusText(status)),
		Body:       io.NopCloser(strings.NewReader(reply)),
		Request:    req,
	}, nil
}

// describe sums up embeds for a failure message: what each one says, and
// how many fields it carries.
func describe(embeds []*discordgo.MessageEmbed) []string {
	var out []string
	for _, e := range embeds {
		out = append(out, fmt.Sprintf("%q with %d fields", e.Description, len(e.Fields)))
	}
	return out
}

// fakeSession is a bot session that makes its REST calls to the fake
// rather than to Discord.
func fakeSession(t *testing.T, discord *fakeDiscord) *discordgo.Session {
	t.Helper()
	session, err := discordgo.New("Bot test")
	if err != nil {
		t.Fatal(err)
	}
	session.Client = &http.Client{Transport: discord}
	return session
}

// lastSoldFetch is the type of site.fetchLastSold.
type lastSoldFetch = func(context.Context, *mtgmatcher.Backend, string, bool) ([]tcgplayer.LatestSalesData, error)

// lastSoldSite is a site holding one English card, whose $$ lookup fetches
// through fetch. It loads a seller and a vendor too: until some are, the
// handler ignores every message.
func lastSoldSite(t *testing.T, fetch lastSoldFetch) *site {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	info := mtgban.ScraperInfo{Name: "Test Store", Shorthand: "TEST"}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, info)}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, info)}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}})
	b.UUIDs["FIXTUREA-1"].Language = "English"

	s := newSite()
	s.ds.Store(s.newDatastore(b, time.Now()))
	s.fetchLastSold = fetch
	return s
}

// lastSoldLookup is a reader's $$ lookup of the fixture's card.
func lastSoldLookup() *discordgo.MessageCreate {
	return &discordgo.MessageCreate{Message: &discordgo.Message{
		Content:   "$$Fixture Card Alpha",
		Author:    &discordgo.User{},
		ChannelID: "channel",
		GuildID:   "guild",
	}}
}

// A $$ lookup replies at once that it is fetching, then edits the sales in
// rather than a timeout: on synctest's fake clock, a handler left waiting
// on a nil channel times out at once. Under -race it also catches the
// fetching goroutine sharing the handler's own variables, as it once
// shared its error, fields and channel.
func TestLastSoldEditsTheSalesIn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := lastSoldSite(t, func(context.Context, *mtgmatcher.Backend, string, bool) ([]tcgplayer.LatestSalesData, error) {
			return []tcgplayer.LatestSalesData{{
				Language:      "English",
				PurchasePrice: 4.5,
				OrderDate:     time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			}}, nil
		})
		discord := &fakeDiscord{}

		s.messageCreate(fakeSession(t, discord), lastSoldLookup())

		if len(discord.sent) != 1 || !strings.Contains(discord.sent[0].Description, "hang tight") || len(discord.sent[0].Fields) != 0 {
			t.Fatalf("sent %v, want one reply that is still fetching", describe(discord.sent))
		}
		if len(discord.edited) != 1 || len(discord.edited[0].Fields) != 1 || strings.Contains(discord.edited[0].Description, "time out") {
			t.Fatalf("edited %v, want the reply edited once, with the one sale and no timeout", describe(discord.edited))
		}
		field := discord.edited[0].Fields[0]
		if field.Name != "2026-09-01" || field.Value != "$4.50" {
			t.Errorf("sale %q %q, want 2026-09-01 $4.50", field.Name, field.Value)
		}
	})
}

// fetchOnRelease is a last-sold fetch that counts its calls and finds
// nothing once release is closed, whatever its context says: one still
// running after the handler has stopped waiting for it.
func fetchOnRelease(release <-chan struct{}, calls *int) lastSoldFetch {
	return func(context.Context, *mtgmatcher.Backend, string, bool) ([]tcgplayer.LatestSalesData, error) {
		*calls++
		<-release
		return nil, nil
	}
}

// The handler stops waiting for the $$ lookup's goroutine when its reply
// times out, and when Discord refuses the reply. Either way the goroutine
// must still exit once its fetch returns: synctest.Test fails on one left
// blocked, and its fake clock runs the 30 s timeout at once. Each case also
// checks, once the goroutine has settled, that the fetch ran: a lookup that
// never gets that far cannot pass.
func TestLastSoldGoroutineExits(t *testing.T) {
	t.Run("after a timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			var calls int
			s := lastSoldSite(t, fetchOnRelease(release, &calls))
			discord := &fakeDiscord{}

			s.messageCreate(fakeSession(t, discord), lastSoldLookup())

			synctest.Wait()
			if calls != 1 {
				t.Errorf("fetches = %d, want 1", calls)
			}
			if len(discord.edited) != 1 || !strings.Contains(discord.edited[0].Description, "Connection time out") {
				t.Errorf("edited %v, want the reply edited once, to say it timed out", describe(discord.edited))
			}
			close(release)
			synctest.Wait()
		})
	})

	t.Run("after a refused reply", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			var calls int
			s := lastSoldSite(t, fetchOnRelease(release, &calls))
			discord := &fakeDiscord{refuseSends: true}

			s.messageCreate(fakeSession(t, discord), lastSoldLookup())

			synctest.Wait()
			if calls != 1 || discord.refused != 1 {
				t.Errorf("fetches = %d, refused sends = %d; want 1 each", calls, discord.refused)
			}
			if len(discord.edited) != 0 {
				t.Errorf("edited %v, want no edit of a reply never sent", describe(discord.edited))
			}
			close(release)
			synctest.Wait()
		})
	})
}
