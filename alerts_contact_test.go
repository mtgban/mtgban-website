package main

import (
	"context"
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/userstate"
)

type refreshedTier struct{ userHash, tier string }

type deletedChannel struct {
	userHash string
	kind     alerts.ChannelKind
	source   alerts.ChannelSource
}

type recordedContacts struct {
	got       []alerts.Contact
	refreshed []refreshedTier
	channels  []alerts.Channel
	deleted   []deletedChannel
	// order is each write's method name, to pin the contact first.
	order []string
}

func (r *recordedContacts) UpsertContact(_ context.Context, c alerts.Contact) error {
	r.got = append(r.got, c)
	r.order = append(r.order, "contact")
	return nil
}

func (r *recordedContacts) UpsertChannel(_ context.Context, c alerts.Channel) error {
	r.channels = append(r.channels, c)
	r.order = append(r.order, "channel")
	return nil
}

func (r *recordedContacts) DeleteChannel(_ context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource) error {
	r.deleted = append(r.deleted, deletedChannel{userHash, kind, source})
	r.order = append(r.order, "delete")
	return nil
}

func (r *recordedContacts) RefreshContactTier(_ context.Context, userHash, tier string) error {
	r.refreshed = append(r.refreshed, refreshedTier{userHash, tier})
	return nil
}

func TestRecordAlertContactHashesTheBareEmail(t *testing.T) {
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("recorded %d contacts, want 1", len(rec.got))
	}
	if len(rec.refreshed) != 0 {
		t.Fatalf("allowed login also refreshed: %+v", rec.refreshed)
	}
	c := rec.got[0]
	if c.UserHash != userstate.HashEmail("a@b.com") || c.DiscordUserID != "77" || !c.DiscordKnown || c.Tier != "Legacy" {
		t.Fatalf("unexpected contact %+v", c)
	}
}

// The login writes the Discord id as a verified channel, and the Patreon
// email only when the ACL allows email; the contact goes first.
func TestRecordAlertContactWritesChannelsPerACL(t *testing.T) {
	email := []alerts.ChannelKind{alerts.ChannelDiscord, alerts.ChannelEmail}
	discordOnly := []alerts.ChannelKind{alerts.ChannelDiscord}
	cases := []struct {
		name      string
		user      PatreonUserData
		channels  []alerts.ChannelKind
		wantKinds []alerts.ChannelKind
		wantDel   int
	}{
		{"discord and email allowed", PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, email, email, 0},
		{"email not allowed", PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, discordOnly, discordOnly, 0},
		{"no channels listed", PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, nil, discordOnly, 0},
		{"discord unknown", PatreonUserData{Email: "a@b.com", EmailVerified: true}, email, []alerts.ChannelKind{alerts.ChannelEmail}, 0},
		{"discord unlinked", PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordKnown: true}, email, []alerts.ChannelKind{alerts.ChannelEmail}, 1},
	}
	for _, tc := range cases {
		rec := &recordedContacts{}
		err := recordAlertContact(context.Background(), rec, &tc.user, "Legacy", true, tc.channels)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(rec.order) == 0 || rec.order[0] != "contact" {
			t.Fatalf("%s: writes %v, want the contact first", tc.name, rec.order)
		}
		var kinds []alerts.ChannelKind
		for _, c := range rec.channels {
			kinds = append(kinds, c.Kind)
			if c.UserHash != userstate.HashEmail("a@b.com") || c.Source != alerts.SourcePatreon || c.VerifiedAt == nil {
				t.Errorf("%s: channel %+v", tc.name, c)
			}
			if c.Kind == alerts.ChannelEmail && c.Address != "a@b.com" {
				t.Errorf("%s: email address %q", tc.name, c.Address)
			}
			if c.Kind == alerts.ChannelDiscord && c.Address != "77" {
				t.Errorf("%s: discord address %q", tc.name, c.Address)
			}
		}
		if !slices.Equal(kinds, tc.wantKinds) {
			t.Errorf("%s: channel kinds %v, want %v", tc.name, kinds, tc.wantKinds)
		}
		if len(rec.deleted) != tc.wantDel {
			t.Errorf("%s: deleted %+v", tc.name, rec.deleted)
		}
		if tc.wantDel > 0 && rec.deleted[0].kind != alerts.ChannelDiscord {
			t.Errorf("%s: deleted %+v, want the discord row", tc.name, rec.deleted)
		}
	}
}

// An unverified email, or a tier without alerts, writes no channel at all.
func TestRecordAlertContactNoChannelsWithoutAlertsOrVerification(t *testing.T) {
	all := []alerts.ChannelKind{alerts.ChannelDiscord, alerts.ChannelEmail}
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: false, DiscordID: "77", DiscordKnown: true}
	_ = recordAlertContact(context.Background(), rec, user, "Legacy", true, all)
	user = &PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	_ = recordAlertContact(context.Background(), rec, user, "Legacy", false, all)
	if len(rec.channels) != 0 || len(rec.deleted) != 0 {
		t.Fatalf("channels written: %+v deleted %+v", rec.channels, rec.deleted)
	}
}

func TestRecordAlertContactNotAllowedRefreshesTierOnly(t *testing.T) {
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 0 {
		t.Fatalf("not-allowed login upserted a contact: %+v", rec.got)
	}
	if len(rec.refreshed) != 1 {
		t.Fatalf("refreshed %d times, want 1", len(rec.refreshed))
	}
	r := rec.refreshed[0]
	if r.userHash != userstate.HashEmail("a@b.com") || r.tier != "Legacy" {
		t.Fatalf("unexpected refresh %+v", r)
	}
}

func TestRecordAlertContactSkipsUnverified(t *testing.T) {
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: false, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 0 || len(rec.refreshed) != 0 {
		t.Fatalf("unverified login recorded got=%+v refreshed=%+v", rec.got, rec.refreshed)
	}
}

func TestRecordAlertContactSkipsWithoutStore(t *testing.T) {
	err := recordAlertContact(context.Background(), nil, &PatreonUserData{Email: "a@b.com"}, "Legacy", true, nil)
	if err != nil {
		t.Fatalf("nil recorder should be a no-op, got %v", err)
	}
}

// TestAlertContactsNilWithoutStore guards the nil-*Store-in-interface
// trap: alertContacts must return an untyped nil, not a non-nil interface
// wrapping a nil *alerts.Store.
func TestAlertContactsNilWithoutStore(t *testing.T) {
	rec := newSite().alertContacts()
	if rec != nil {
		t.Fatalf("expected nil recorder without a store, got %v", rec)
	}
}

func TestPatreonUserFromDataLinked(t *testing.T) {
	var userData patreon.UserData
	userData.Data.IDV1 = "u1"
	userData.Data.Attributes.Email = "A@B.com"
	userData.Data.Attributes.IsEmailVerified = true
	userData.Data.Attributes.FullName = "A B"
	userData.Data.Attributes.SocialConnections = &struct {
		Discord *patreon.SocialConnection `json:"discord"`
	}{Discord: &patreon.SocialConnection{UserID: "77"}}

	got := patreonUserFromData(&userData)
	if got.Email != "a@b.com" {
		t.Fatalf("email = %q, want lowercased", got.Email)
	}
	if !got.DiscordKnown || got.DiscordID != "77" {
		t.Fatalf("unexpected %+v", got)
	}
}

func TestPatreonUserFromDataAbsentDiscord(t *testing.T) {
	var userData patreon.UserData
	userData.Data.IDV1 = "u1"
	userData.Data.Attributes.Email = "a@b.com"
	userData.Data.Attributes.IsEmailVerified = true

	got := patreonUserFromData(&userData)
	if got.DiscordKnown || got.DiscordID != "" {
		t.Fatalf("unexpected %+v", got)
	}
}
