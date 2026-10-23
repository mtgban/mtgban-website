package main

import (
	"context"
	"slices"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/userstate"
)

type contactRecorder interface {
	UpsertContact(ctx context.Context, c alerts.Contact) error
	UpsertChannel(ctx context.Context, c alerts.Channel) error
	DeleteChannel(ctx context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource) error
}

// recordAlertContact keeps what a login learned about the user: the
// contact row for every verified login (the evaluator reads its tier, the
// Account page its Discord id), channels only where the tier grants
// alerts. The Patreon email is written only when email is among them.
func recordAlertContact(ctx context.Context, rec contactRecorder, userData *pledge.User, tier string, allowed bool, channels []alerts.ChannelKind) error {
	// An unverified login never touches the contact row.
	if rec == nil || userData == nil || !userData.EmailVerified {
		return nil
	}
	userHash := userstate.HashEmail(userData.Email)
	// First: the channel rows reference the contact.
	err := rec.UpsertContact(ctx, alerts.Contact{
		UserHash:      userHash,
		DiscordKnown:  userData.DiscordKnown,
		DiscordUserID: userData.DiscordID,
		Tier:          tier,
	})
	if err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	now := time.Now()
	if userData.DiscordKnown {
		err = recordDiscordChannel(ctx, rec, userHash, userData.DiscordID, now)
		if err != nil {
			return err
		}
	}
	if !slices.Contains(channels, alerts.ChannelEmail) {
		return nil
	}
	return rec.UpsertChannel(ctx, alerts.Channel{
		UserHash:   userHash,
		Kind:       alerts.ChannelEmail,
		Address:    alerts.NormalizeAddress(userData.Email),
		Source:     alerts.SourcePatreon,
		VerifiedAt: &now,
	})
}

// recordDiscordChannel mirrors the contact's Discord id; an unlinked one
// drops the row so the cleared contact column is what ChannelFor reads.
func recordDiscordChannel(ctx context.Context, rec contactRecorder, userHash, discordID string, now time.Time) error {
	if discordID == "" {
		return rec.DeleteChannel(ctx, userHash, alerts.ChannelDiscord, alerts.SourcePatreon)
	}
	return rec.UpsertChannel(ctx, alerts.Channel{
		UserHash:   userHash,
		Kind:       alerts.ChannelDiscord,
		Address:    discordID,
		Source:     alerts.SourcePatreon,
		VerifiedAt: &now,
	})
}

// alertContacts is the site's alerts store as a recorder, or an untyped nil
// when there is none, so recordAlertContact's nil check holds.
func (s *site) alertContacts() contactRecorder {
	store := s.alerts.Store()
	if store != nil {
		return store
	}
	return nil
}
