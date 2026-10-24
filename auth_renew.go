package main

import (
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
)

// renewalEnabled says whether this deployment renews signatures: the config
// names an after_days, the site has a database to keep sessions in, it checks
// signatures, and it has a Patreon client id to refresh through. The same
// gates the API handoff reads to say it is off.
func renewalEnabled() bool {
	infra := Infrastructure()
	clientID := infra.Patreon.Client[infra.Patreon.Source]
	return infra.PatreonRenewal.AfterDays > 0 && UserStateDB != nil && SigCheck && clientID != ""
}

// renewalDecision is what signing does about a signature that may be due.
type renewalDecision int

const (
	// renewalSkip leaves the signature as it is.
	renewalSkip renewalDecision = iota
	// renewalDue renews a signature that has not run out.
	renewalDue
	// renewalGrace renews one that ran out no more than grace_days ago.
	renewalGrace
)

// decideRenewal says whether a signature wants renewing now. signed is
// whether this host wrote it, expired or not; cookieBorne that it came in the
// BAN_SIG cookie rather than ?sig=, and hasSession that the request carries a
// BAN_SESSION cookie. A signature that does not carry its issue time is aged
// from its expiry, every one a login or a renewal mints lasting
// DefaultSignatureDuration. It reads nothing but its arguments.
func decideRenewal(signed bool, expires, now time.Time, cookieBorne, hasSession bool, cfg infrastructure.PatreonRenewal) renewalDecision {
	if cfg.AfterDays <= 0 || !signed || !cookieBorne || !hasSession {
		return renewalSkip
	}
	age := now.Sub(expires.Add(-DefaultSignatureDuration))
	if age < cfg.After() {
		return renewalSkip
	}
	if !now.After(expires) {
		return renewalDue
	}
	if now.Sub(expires) <= cfg.Grace() {
		return renewalGrace
	}
	return renewalSkip
}
