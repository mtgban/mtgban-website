package main

import (
	"context"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/userstate"
)

type contactRecorder interface {
	UpsertContact(ctx context.Context, c alerts.Contact) error
	RefreshContactTier(ctx context.Context, userHash, tier string) error
}

// recordAlertContact keeps what a login learned about the user for the
// evaluator, which has no cookie to read it from later. A row is only
// created when the tier grants alerts; a downgrade just moves its tier.
func recordAlertContact(ctx context.Context, rec contactRecorder, userData *PatreonUserData, tier string, allowed bool) error {
	// An unverified login never touches the contact row.
	if rec == nil || userData == nil || !userData.EmailVerified {
		return nil
	}
	userHash := userstate.HashEmail(userData.Email)
	if !allowed {
		return rec.RefreshContactTier(ctx, userHash, tier)
	}
	return rec.UpsertContact(ctx, alerts.Contact{
		UserHash:      userHash,
		DiscordKnown:  userData.DiscordKnown,
		DiscordUserID: userData.DiscordID,
		Tier:          tier,
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
