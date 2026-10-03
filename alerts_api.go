package main

import (
	"context"
	"net/http"
	"net/url"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/userstate"
)

// alertAPIDeps wires the ACL, prices and the live datastore into the API;
// the service builds the limiter when a store is attached.
func (s *site) alertAPIDeps() alerts.APIDeps {
	// No mailer: the email endpoints answer 503.
	var sendConfirm func(ctx context.Context, to, link string) error
	if alertMailConfigured() {
		sendConfirm = s.sendAlertConfirm
	}
	return alerts.APIDeps{
		Identity:    alertsIdentity,
		Allowance:   alertAllowance,
		Prices:      alertVisiblePrices,
		Resolve:     func(cardID string) (alerts.Card, bool, bool) { return alertCardSnapshot(s.backend(), cardID) },
		StoreLabel:  alertStoreLabel,
		Game:        func() string { return string(Config().Game) },
		Channels:    alertChannels,
		Mint:        func(t alerts.Token) string { return alerts.MintToken(alertTokenSecret(), t) },
		SendConfirm: sendConfirm,
		ConfirmTTL:  alertConfirmTTL,
	}
}

// alertVisiblePrices is a card's store prices on one side, less the
// stores the ACL values block.
func alertVisiblePrices(cardID string, side alerts.Side, v url.Values) []alerts.StorePrice {
	retail, buylist := blocklistsFromValues(v)
	if side == alerts.SideRetail {
		return alertStorePrices(cardID, side, retail)
	}
	return alertStorePrices(cardID, side, buylist)
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
	return alerts.Caller{UserHash: userstate.HashEmail(email), Tier: v.Get("UserTier"), Values: v, Origin: requestOrigin(r)}, http.StatusOK, ""
}
