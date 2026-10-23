package main

import (
	"context"
	"net/http"
	"net/url"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/siteorigin"
	"github.com/mtgban/mtgban-website/userstate"
)

// alertAPIDeps wires the ACL, prices and the live datastore into the API;
// the service builds the limiter when a store is attached.
func (s *site) alertAPIDeps() alerts.APIDeps {
	// No mailer: the email endpoints answer 503.
	var sendConfirm func(ctx context.Context, userHash, to, link string) error
	if alertMailConfigured() {
		sendConfirm = s.sendAlertConfirm
	}
	return alerts.APIDeps{
		Identity:    alertsIdentity,
		Allowance:   alertAllowance,
		Prices:      s.alertPrices,
		Resolve:     func(cardID string) (alerts.Card, bool, bool) { return alertCardSnapshot(s.backend(), cardID) },
		StoreLabel:  alertStoreLabel,
		Game:        func() string { return string(Config().Game) },
		Channels:    alertChannels,
		Mint:        func(t alerts.Token) string { return alerts.MintToken(alertTokenSecret(), t) },
		SendConfirm: sendConfirm,
		ConfirmTTL:  alertConfirmTTL,
	}
}

// alertPrices is alertVisiblePrices on the live datastore.
func (s *site) alertPrices(cardID string, side alerts.Side, v url.Values) []alerts.StorePrice {
	return alertVisiblePrices(s.backend(), cardID, side, v)
}

// alertVisiblePrices is a card's store prices on one side, less the
// stores the ACL values block.
func alertVisiblePrices(b *mtgmatcher.Backend, cardID string, side alerts.Side, v url.Values) []alerts.StorePrice {
	co, err := b.GetUUID(cardID)
	sealed := err == nil && co.Sealed
	retail, buylist := blocklistsFromValues(v)
	if side == alerts.SideRetail {
		return alertStorePrices(cardID, sealed, side, retail)
	}
	return alertStorePrices(cardID, sealed, side, buylist)
}

const alertsUnverifiedMsg = "verify your Patreon email to use alerts"

// alertsIdentity reads who is calling off a verified signature; a status
// other than 200 is the refusal to answer with.
func alertsIdentity(r *http.Request) (c alerts.Caller, status int, msg string) {
	v := parseSig(verifiedRequestSignature(r))
	email := v.Get("UserEmail")
	if email == "" {
		return c, http.StatusUnauthorized, "not signed in"
	}
	if v.Get("UserEmailUnverified") == "true" {
		return c, http.StatusForbidden, alertsUnverifiedMsg
	}
	return alerts.Caller{UserHash: userstate.HashEmail(email), Tier: v.Get("UserTier"), Values: v, Origin: siteorigin.Of(r)}, http.StatusOK, ""
}
