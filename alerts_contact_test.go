package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/userstate"
)

type deletedChannel struct {
	userHash string
	kind     alerts.ChannelKind
	source   alerts.ChannelSource
}

type recordedContacts struct {
	got      []alerts.Contact
	channels []alerts.Channel
	deleted  []deletedChannel
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

func TestRecordAlertContactHashesTheBareEmail(t *testing.T) {
	rec := &recordedContacts{}
	user := &pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("recorded %d contacts, want 1", len(rec.got))
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
		user      pledge.User
		channels  []alerts.ChannelKind
		wantKinds []alerts.ChannelKind
		wantDel   int
	}{
		{"discord and email allowed", pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, email, email, 0},
		{"email not allowed", pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, discordOnly, discordOnly, 0},
		{"no channels listed", pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}, nil, discordOnly, 0},
		{"discord unknown", pledge.User{Email: "a@b.com", EmailVerified: true}, email, []alerts.ChannelKind{alerts.ChannelEmail}, 0},
		{"discord unlinked", pledge.User{Email: "a@b.com", EmailVerified: true, DiscordKnown: true}, email, []alerts.ChannelKind{alerts.ChannelEmail}, 1},
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
	user := &pledge.User{Email: "a@b.com", EmailVerified: false, DiscordID: "77", DiscordKnown: true}
	_ = recordAlertContact(context.Background(), rec, user, "Legacy", true, all)
	user = &pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	_ = recordAlertContact(context.Background(), rec, user, "Legacy", false, all)
	if len(rec.channels) != 0 || len(rec.deleted) != 0 {
		t.Fatalf("channels written: %+v deleted %+v", rec.channels, rec.deleted)
	}
}

// A tier without alerts still records the login: the Account page reads
// the Discord id off this row, and the evaluator reads the tier.
func TestRecordAlertContactNotAllowedWritesTheContactOnly(t *testing.T) {
	rec := &recordedContacts{}
	user := &pledge.User{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("contacts upserted %d, want 1: %+v", len(rec.got), rec.got)
	}
	c := rec.got[0]
	if c.UserHash != userstate.HashEmail("a@b.com") || c.Tier != "Legacy" || c.DiscordUserID != "77" || !c.DiscordKnown {
		t.Fatalf("unexpected contact %+v", c)
	}
	if len(rec.channels) != 0 || len(rec.deleted) != 0 {
		t.Fatalf("not-allowed login wrote channels %+v deleted %+v", rec.channels, rec.deleted)
	}
}

func TestRecordAlertContactSkipsUnverified(t *testing.T) {
	rec := &recordedContacts{}
	user := &pledge.User{Email: "a@b.com", EmailVerified: false, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 0 {
		t.Fatalf("unverified login recorded %+v", rec.got)
	}
}

func TestRecordAlertContactSkipsWithoutStore(t *testing.T) {
	err := recordAlertContact(context.Background(), nil, &pledge.User{Email: "a@b.com"}, "Legacy", true, nil)
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

	got := pledge.UserFromData(&userData)
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

	got := pledge.UserFromData(&userData)
	if got.DiscordKnown || got.DiscordID != "" {
		t.Fatalf("unexpected %+v", got)
	}
}

// The privacy policy says what the login keeps: the contact row exists
// for every verified login, alerts tier or not.
func TestPrivacyPolicyNamesTheLoginContact(t *testing.T) {
	baseName, files := renderTemplateFiles("privacy.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	err = tmpl.ExecuteTemplate(&out, baseName, PageVars{Title: "Privacy", Hash: "test", UserNav: &NavElem{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hashed form of it", "Discord account Patreon reports as linked", "whether or not your tier includes price alerts"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("privacy policy lacks %q", want)
		}
	}
}
