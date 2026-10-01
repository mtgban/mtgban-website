package main

import (
	"context"
	"testing"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/userstate"
)

type refreshedTier struct{ userHash, tier string }

type recordedContacts struct {
	got       []alerts.Contact
	refreshed []refreshedTier
}

func (r *recordedContacts) UpsertContact(_ context.Context, c alerts.Contact) error {
	r.got = append(r.got, c)
	return nil
}

func (r *recordedContacts) RefreshContactTier(_ context.Context, userHash, tier string) error {
	r.refreshed = append(r.refreshed, refreshedTier{userHash, tier})
	return nil
}

func TestRecordAlertContactHashesTheBareEmail(t *testing.T) {
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true)
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

func TestRecordAlertContactNotAllowedRefreshesTierOnly(t *testing.T) {
	rec := &recordedContacts{}
	user := &PatreonUserData{Email: "a@b.com", EmailVerified: true, DiscordID: "77", DiscordKnown: true}
	err := recordAlertContact(context.Background(), rec, user, "Legacy", false)
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
	err := recordAlertContact(context.Background(), rec, user, "Legacy", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 0 || len(rec.refreshed) != 0 {
		t.Fatalf("unverified login recorded got=%+v refreshed=%+v", rec.got, rec.refreshed)
	}
}

func TestRecordAlertContactSkipsWithoutStore(t *testing.T) {
	err := recordAlertContact(context.Background(), nil, &PatreonUserData{Email: "a@b.com"}, "Legacy", true)
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
