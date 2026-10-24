package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/userstate"
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

// graceSignature is the signature in the BAN_SIG cookie, decoded, when it ran
// out and may still be renewed: this host wrote it, it names a reader, and
// the request is a GET with no ?sig= whose sig, as unverifiedSignature kept
// it, is empty. unverifiedSignature drops an expired cookie, so signing reads
// it here, for this alone. Nil otherwise, and always while renewal or
// grace_days is off.
func graceSignature(r *http.Request, sig, querySig string) url.Values {
	if sig != "" || querySig != "" || r.Method != http.MethodGet {
		return nil
	}
	raw := readCookie(r, signatureCookie)
	if raw == "" || Infrastructure().PatreonRenewal.GraceDays <= 0 || !renewalEnabled() {
		return nil
	}
	values := parseSig(raw)
	if values.Get("UserEmail") == "" || !signatureMatches(values) {
		return nil
	}
	return values
}

// renewDue renews the signature of the request signing is serving when
// decideRenewal says it is due, or when its reader was poked after it was
// issued and decideRenewal skipped it for its age alone, and reports what the
// request goes on with: the new signature, or refused when the reader's pledge
// is gone and they are logged out. values and signed are the cookie's signature as signing read
// it, expired or not, and whether this host wrote it; cookieBorne says it
// came from the cookie, not ?sig=.
func (s *site) renewDue(w http.ResponseWriter, r *http.Request, values url.Values, signed, cookieBorne bool) (sig string, refused bool) {
	expires, _ := strconv.ParseInt(values.Get("Expires"), 10, 64)
	ends := time.Unix(expires, 0)
	now := time.Now()
	hasSession := readCookie(r, sessionCookie) != ""
	cfg := Infrastructure().PatreonRenewal
	if decideRenewal(signed, ends, now, cookieBorne, hasSession, cfg) == renewalSkip {
		// A poke lifts the age check and nothing else: the signature is still
		// this host's, in the cookie, naming a reader beside their session, and
		// not past the end of grace
		email := values.Get("UserEmail")
		eligible := signed && cookieBorne && hasSession && email != "" && cfg.AfterDays > 0 && now.Sub(ends) <= cfg.Grace()
		if !eligible || Pokes.wants(userstate.HashEmail(email), ends.Add(-DefaultSignatureDuration)) == "" {
			return "", false
		}
	}
	if !renewalEnabled() {
		return "", false
	}
	return s.renewSignature(w, r, values, 0)
}

// The waits of a renewal: how long it holds the sessions of an email, how
// long they rest after an answer from Patreon that settled nothing, how long
// each database call may take, and how long they rest after Refresh now, so
// that a reader cannot press Patreon per request.
const (
	renewalLease       = time.Minute
	renewalBackoff     = time.Hour
	renewalDBTimeout   = 2 * time.Second
	renewalRefreshRest = 5 * time.Minute
)

// renewal is one attempt to renew a reader's signature, and the line the
// admin log tells it by. It holds no token.
type renewal struct {
	session string // the BAN_SESSION value
	email   string
	hash    string // userstate.HashEmail(email)
	fence   string // set once the email's sessions are leased
	tier    string // the signature's tier before
	age     time.Duration
	rest    time.Duration // how long the sessions rest once this renewal commits
	started time.Time
}

// log writes the attempt's line: who, how old their signature is, what
// Patreon said, and how long it took. The session is cut short, enough to
// tell attempts apart and no use to anyone holding the log.
func (rn *renewal) log(verdict string, cause error) {
	LogPages["Admin"].Printf("renew: session=%.8s email=%q age=%.1fd verdict=%s err=%v elapsed=%s",
		rn.session, rn.email, rn.age.Hours()/24, verdict, cause, time.Since(rn.started).Round(time.Millisecond))
}

// lease claims the email's sessions for this renewal and returns the refresh
// token they hold. It is false when another request, device or site holds
// them or they are backing off, the session is not this email's or is past
// its cap, or the database cannot say.
func (rn *renewal) lease(base context.Context) (token string, leased bool) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	token, fence, leased, err := UserStateDB.LeasePatreonSessions(ctx, rn.session, rn.hash, renewalLease)
	if err != nil {
		rn.log("unknown", fmt.Errorf("lease: %w", err))
		return "", false
	}
	rn.fence = fence
	return token, leased
}

// hold backs the email's sessions off for renewalBackoff after an answer
// that settled nothing, leaving the signature as it is. refreshToken is the
// one Patreon rotated to when the refresh went through, else empty.
func (rn *renewal) hold(base context.Context, refreshToken, verdict string, cause error) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	err := UserStateDB.DeferPatreonSessions(ctx, rn.hash, rn.fence, refreshToken, renewalBackoff)
	if err != nil {
		LogPages["Admin"].Println("DeferPatreonSessions", err)
	}
	rn.log(verdict, cause)
}

// revoke deletes every session of the email: Patreon refused the one token
// they all hold for good, so none of them can renew.
func (rn *renewal) revoke(base context.Context, cause error) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	_, err := UserStateDB.DeletePatreonSessions(ctx, rn.hash)
	if err != nil {
		LogPages["Admin"].Println("DeletePatreonSessions", err)
	}
	rn.log(patreon.InvalidGrant, cause)
}

// endSession is the database half of logging out a reader whose pledge is
// gone: this browser's session is deleted. The token Patreon rotated to goes
// on all of the email's sessions first, so the others hold a live one and
// learn the same at their own renewal.
func (rn *renewal) endSession(base context.Context, refreshToken string) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	_, err := UserStateDB.CommitPatreonSessions(ctx, rn.hash, rn.fence, refreshToken, 0)
	if err != nil {
		LogPages["Admin"].Println("CommitPatreonSessions", err)
	}
	err = UserStateDB.DeletePatreonSession(ctx, rn.session)
	if err != nil {
		LogPages["Admin"].Println("DeletePatreonSession", err)
	}
	rn.log("not entitled", nil)
}

// commit stores the token Patreon rotated to on every session of the email,
// and moves them to the email Patreon reports now when the reader changed it.
// It is false when the signature must not be re-issued: the sessions are gone
// (the reader logged out everywhere meanwhile), or the database failed.
func (rn *renewal) commit(base context.Context, refreshToken string, user *pledge.User) bool {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	rows, err := UserStateDB.CommitPatreonSessions(ctx, rn.hash, rn.fence, refreshToken, rn.rest)
	if err != nil {
		rn.hold(base, refreshToken, "unknown", fmt.Errorf("commit: %w", err))
		return false
	}
	if rows == 0 {
		rn.log("sessions gone", nil)
		return false
	}

	newHash := userstate.HashEmail(user.Email)
	if newHash == rn.hash {
		return true
	}
	err = UserStateDB.RekeyPatreonSessions(ctx, rn.hash, newHash)
	if err != nil {
		rn.log("unknown", fmt.Errorf("rekey: %w", err))
		return false
	}
	LogPages["Admin"].Printf("renew: session=%.8s email changed from %q to %q", rn.session, rn.email, user.Email)
	return true
}

// renewSignature renews the signature values describe, a reader's own, from
// the session their BAN_SESSION cookie names, and returns the new one. It
// returns nothing when it did not renew: another request holds the sessions,
// the session is not the signature's, or Patreon's answer settled nothing, in
// which case the sessions rest for an hour and the signature runs out on its
// own. A refresh token Patreon no longer honours ends every session of the
// email and the browser's cookie, and refused is true only when Patreon says
// nothing is pledged and clear_on_negative logged the reader out. A renewed
// signature is issued after its reader's poke and is left alone; the reader's
// other devices renew at their own next request.
//
// The calls to Patreon run under renew_timeout_seconds with no database
// connection held, and a reader who navigates away does not cancel a refresh
// Patreon may already have rotated. rest is how long the email's sessions
// rest once the renewal commits: zero for a due renewal, whose new signature
// is not due again for after_days; Refresh now rests them, so a reader cannot
// press Patreon per request.
func (s *site) renewSignature(w http.ResponseWriter, r *http.Request, values url.Values, rest time.Duration) (sig string, refused bool) {
	rn := renewal{
		session: readCookie(r, sessionCookie),
		email:   values.Get("UserEmail"),
		tier:    values.Get("UserTier"),
		rest:    rest,
		started: time.Now(),
	}
	if rn.session == "" || rn.email == "" {
		return "", false
	}
	rn.hash = userstate.HashEmail(rn.email)
	expires, _ := strconv.ParseInt(values.Get("Expires"), 10, 64)
	rn.age = rn.started.Sub(time.Unix(expires, 0).Add(-DefaultSignatureDuration))
	base := context.WithoutCancel(r.Context())

	token, leased := rn.lease(base)
	if !leased {
		return "", false
	}

	infra := Infrastructure()
	source := infra.Patreon.Source
	patreonCtx, cancel := context.WithTimeout(base, infra.PatreonRenewal.RenewTimeout())
	defer cancel()
	tokens, err := patreon.RefreshAuthToken(patreonCtx, infra.Patreon.Client[source], infra.Patreon.Secret[source], token)
	var grant *patreon.GrantError
	if errors.As(err, &grant) && grant.Code == patreon.InvalidGrant {
		rn.revoke(base, err)
		clearSessionCookie(w, r)
		return "", false
	}
	if err != nil {
		rn.hold(base, "", "unknown", err)
		return "", false
	}

	client := patreon.NewPatreonClient(patreonCtx, tokens.AccessToken)
	user, err := Pledge.UserIDs(patreonCtx, client)
	if err != nil {
		rn.hold(base, tokens.RefreshToken, "unknown", err)
		return "", false
	}
	tier, overrides, granted, verdict, err := Pledge.Resolve(patreonCtx, client, user)
	switch {
	case verdict == pledge.Entitled:
		if !rn.commit(base, tokens.RefreshToken, user) {
			return "", false
		}
		sig = s.signReaderIn(w, r, user, tier, overrides, granted)
		setSessionCookie(w, r, rn.session, signatureCookieDays*24*time.Hour)
		rn.log(fmt.Sprintf("entitled tier=%s->%s", rn.tier, tier), nil)
		return sig, false
	case verdict == pledge.NotEntitled && infra.PatreonRenewal.ClearOnNegative:
		rn.endSession(base, tokens.RefreshToken)
		clearLoginCookies(w, r)
		return "", true
	}
	rn.hold(base, tokens.RefreshToken, verdict.String(), err)
	return "", false
}
