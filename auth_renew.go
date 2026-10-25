package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/internal/poke"
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

// Pokes is what makes a signature stale before its age does, kept by this
// process: the readers Patreon's webhook named, directly on the site that
// received the delivery and through the patreon_poke NOTIFY on the others, the
// grantees a grant edit changed, and the moment the access table last changed
// (access_notify.go, common.go). A poke lasts pokeWindow.
var Pokes = poke.New()

// pokeWindow is how long a poke lasts: after_days, when the age check would
// have renewed the reader anyway.
func pokeWindow() time.Duration {
	return Infrastructure().PatreonRenewal.After()
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
// decideRenewal says it is due, or when it is stale in a way only the site
// knows (its reader was poked, or the access table changed after it was
// issued) and decideRenewal skipped it for its age alone, and reports what the
// request goes on with: the new signature, or refused when the reader's pledge
// is gone and they are logged out. values and signed are the cookie's
// signature as signing read it, expired or not, and whether this host wrote it;
// cookieBorne says it came from the cookie, not ?sig=.
func (s *site) renewDue(w http.ResponseWriter, r *http.Request, values url.Values, signed, cookieBorne bool) (sig string, refused bool) {
	expires, _ := strconv.ParseInt(values.Get("Expires"), 10, 64)
	ends := time.Unix(expires, 0)
	now := time.Now()
	hasSession := readCookie(r, sessionCookie) != ""
	cfg := Infrastructure().PatreonRenewal

	var cause string
	switch decideRenewal(signed, ends, now, cookieBorne, hasSession, cfg) {
	case renewalDue:
		cause = "due"
	case renewalGrace:
		cause = "grace"
	default:
		// A poke or a stamp lifts the age check and nothing else: the signature
		// is still this host's, in the cookie, naming a reader beside their
		// session, and not past the end of grace
		email := values.Get("UserEmail")
		eligible := signed && cookieBorne && hasSession && email != "" && cfg.AfterDays > 0 && now.Sub(ends) <= cfg.Grace()
		if !eligible {
			return "", false
		}
		cause = Pokes.Wants(userstate.HashEmail(email), ends.Add(-DefaultSignatureDuration), now, pokeWindow())
		if cause == "" {
			return "", false
		}
	}
	if !renewalEnabled() {
		return "", false
	}
	return s.renewSignature(w, r, values, 0, cause)
}

// The waits of a renewal: how long it holds the sessions of an account, how
// long they rest after an answer from Patreon that settled nothing, how long
// each database call may take, how long a signature just renewed is kept
// here, so that a request already on its way with it is served the new one
// rather than renewing it again, and how long the sessions rest after Refresh
// now, so that a reader cannot press Patreon per request.
// The token refresh has a wait of its own, longer than renew_timeout_seconds
// allows the lookups: an answer given up on after Patreon rotated the token
// loses the token. Both fit inside the lease, renewalLookupMax bounding
// renew_timeout_seconds.
const (
	renewalLease          = time.Minute
	renewalBackoff        = time.Hour
	renewalDBTimeout      = 2 * time.Second
	renewalSettle         = time.Minute
	renewalRefreshRest    = 5 * time.Minute
	renewalRefreshTimeout = 20 * time.Second
	renewalLookupMax      = 30 * time.Second
)

// sessionRests is when each session this process saw refused a lease may
// next ask for one, so that a reader whose sessions rest, or whose session is
// filed under another email (someone else's, or their own changed one) or
// client, costs the database nothing per request; and, for each
// signature it just renewed, keyed by settledKey, the signature it renewed
// to, which a request already on its way with the old one is served on.
type sessionRests struct {
	mu      sync.Mutex
	entries map[string]sessionRest
}

// sessionRest is one entry of sessionRests: until when it holds, and the
// signature a settled one renewed to.
type sessionRest struct {
	until   time.Time
	renewed string
}

// restingSessions is this process's sessionRests.
var restingSessions = newSessionRests()

func newSessionRests() *sessionRests {
	return &sessionRests{entries: map[string]sessionRest{}}
}

// settledKey names a session together with the signature values describe,
// by the HMAC that signature carries.
func settledKey(session string, values url.Values) string {
	return session + " " + values.Get("Signature")
}

// resting says whether session may not ask for a lease at now.
func (sr *sessionRests) resting(session string, now time.Time) bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return now.Before(sr.entries[session].until)
}

// renewedTo is the signature the one settledKey names was renewed to, while
// that renewal is settling.
func (sr *sessionRests) renewedTo(settled string, now time.Time) (string, bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	entry := sr.entries[settled]
	return entry.renewed, entry.renewed != "" && now.Before(entry.until)
}

// rest keeps key from asking for a lease until until, with renewed the
// signature it was renewed to when it is a settledKey, and forgets the
// entries whose rest is over.
func (sr *sessionRests) rest(key, renewed string, until, now time.Time) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	for other, entry := range sr.entries {
		if !now.Before(entry.until) {
			delete(sr.entries, other)
		}
	}
	sr.entries[key] = sessionRest{until: until, renewed: renewed}
}

// renewal is one attempt to renew a reader's signature, and the line the
// admin log tells it by. It holds no token.
type renewal struct {
	cause   string // what asked for it: due, grace, poke, acl or refresh
	session string // the BAN_SESSION value
	settled string // settledKey of the session and the signature it renews
	email   string
	hash    string // userstate.HashEmail(email)
	client  string // the Patreon client this site refreshes through
	fence   string // set once the account's sessions are leased
	tier    string // the signature's tier before
	age     time.Duration
	rest    time.Duration // how long the sessions rest once this renewal commits
	started time.Time
}

// log writes the attempt's line: who, how old their signature is, what asked
// for the renewal, what Patreon said, and how long it took. The session is cut
// short, enough to tell attempts apart and no use to anyone holding the log.
func (rn *renewal) log(verdict string, cause error) {
	LogPages["Admin"].Printf("renew: session=%.8s email=%q age=%.1fd cause=%s verdict=%s err=%v elapsed=%s",
		rn.session, rn.email, rn.age.Hours()/24, rn.cause, verdict, cause, time.Since(rn.started).Round(time.Millisecond))
}

// lease claims the account's sessions for this renewal and returns the
// refresh token they hold. It is false when another request, device or site
// holds them or they are resting, the session is not this email's, this
// client's or is past its cap, or the database cannot say. A session that is
// gone has its cookie cleared, and one that rests or is filed elsewhere is not
// asked again until the rest or the backoff is over, so none costs the
// database a statement per request.
func (rn *renewal) lease(base context.Context, w http.ResponseWriter, r *http.Request) (token string, leased bool) {
	if restingSessions.resting(rn.session, rn.started) {
		return "", false
	}
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	token, fence, leased, err := UserStateDB.LeasePatreonSessions(ctx, rn.session, rn.hash, rn.client, renewalLease)
	if err != nil {
		rn.log("unknown", fmt.Errorf("lease: %w", err))
		return "", false
	}
	if leased {
		rn.fence = fence
		return token, true
	}
	standing, wait, err := UserStateDB.PatreonSessionStanding(ctx, rn.session, rn.hash, rn.client)
	switch {
	case err != nil:
		rn.log("unknown", fmt.Errorf("standing: %w", err))
	case standing == userstate.SessionGone:
		clearSessionCookie(w, r)
		rn.log("session gone", nil)
	case standing == userstate.SessionElsewhere:
		restingSessions.rest(rn.session, "", rn.started.Add(renewalBackoff), rn.started)
	case wait > renewalLease:
		// A wait no longer than a lease is another renewal's, which ends as
		// soon as that one commits, so only a backoff or a rest is kept
		restingSessions.rest(rn.session, "", rn.started.Add(wait), rn.started)
	}
	return "", false
}

// hold backs the account's sessions off for renewalBackoff after an answer
// that settled nothing, leaving the signature as it is. refreshToken is the
// one Patreon rotated to when the refresh went through, else empty.
func (rn *renewal) hold(base context.Context, refreshToken, verdict string, cause error) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	err := UserStateDB.DeferPatreonSessions(ctx, rn.fence, refreshToken, renewalBackoff)
	if err != nil {
		LogPages["Admin"].Println("DeferPatreonSessions", err)
	}
	restingSessions.rest(rn.session, "", time.Now().Add(renewalBackoff), time.Now())
	rn.log(verdict, cause)
}

// revoke deletes the account's sessions holding token, which Patreon refused
// for good, and says whether this browser's was among them. A session that
// holds another token is left to try it.
func (rn *renewal) revoke(base context.Context, token string, cause error) (ownGone bool) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	gone, err := UserStateDB.RevokePatreonSessions(ctx, rn.fence, token)
	if err != nil {
		LogPages["Admin"].Println("RevokePatreonSessions", err)
	}
	rn.log(patreon.InvalidGrant, cause)
	return slices.Contains(gone, rn.session)
}

// endSession is the database half of logging out a reader whose pledge is
// gone: this browser's session is deleted. The token Patreon rotated to goes
// on all of the account's sessions first, so the others hold a live one and
// learn the same at their own renewal.
func (rn *renewal) endSession(base context.Context, refreshToken string) {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	_, err := UserStateDB.CommitPatreonSessions(ctx, rn.fence, rn.hash, refreshToken, 0)
	if err != nil {
		LogPages["Admin"].Println("CommitPatreonSessions", err)
	}
	err = UserStateDB.DeletePatreonSession(ctx, rn.session)
	if err != nil {
		LogPages["Admin"].Println("DeletePatreonSession", err)
	}
	rn.log("not entitled", nil)
}

// commit stores the token Patreon rotated to on every session of the
// account, filed under the email Patreon reports now when the reader changed
// it. It is false when the signature must not be re-issued: the sessions are
// gone (the reader logged out everywhere meanwhile), or the database failed.
func (rn *renewal) commit(base context.Context, refreshToken string, user *pledge.User) bool {
	ctx, cancel := context.WithTimeout(base, renewalDBTimeout)
	defer cancel()
	newHash := userstate.HashEmail(user.Email)
	rows, err := UserStateDB.CommitPatreonSessions(ctx, rn.fence, newHash, refreshToken, rn.rest)
	if err != nil {
		rn.hold(base, refreshToken, "unknown", fmt.Errorf("commit: %w", err))
		return false
	}
	if rows == 0 {
		rn.log("sessions gone", nil)
		return false
	}
	if newHash != rn.hash {
		LogPages["Admin"].Printf("renew: session=%.8s cause=%s email changed from %q to %q", rn.session, rn.cause, rn.email, user.Email)
	}
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
// The calls to Patreon run with no database connection held: the refresh
// under renewalRefreshTimeout, the lookups after it under
// renew_timeout_seconds, and a reader who navigates away does not cancel a
// refresh Patreon may already have rotated. rest is how long the account's
// sessions rest once the renewal commits: none for one asked for by
// the signature, whose new one is not due again for after_days; Refresh now
// rests them, so a reader cannot press Patreon per request. cause is what
// asked for the renewal, for the log.
func (s *site) renewSignature(w http.ResponseWriter, r *http.Request, values url.Values, rest time.Duration, cause string) (sig string, refused bool) {
	rn := renewal{
		cause:   cause,
		session: readCookie(r, sessionCookie),
		email:   values.Get("UserEmail"),
		tier:    values.Get("UserTier"),
		rest:    rest,
		started: time.Now(),
	}
	if rn.session == "" || rn.email == "" {
		return "", false
	}
	infra := Infrastructure()
	source := infra.Patreon.Source
	rn.client = infra.Patreon.Client[source]
	rn.hash = userstate.HashEmail(rn.email)
	rn.settled = settledKey(rn.session, values)
	expires, _ := strconv.ParseInt(values.Get("Expires"), 10, 64)
	rn.age = rn.started.Sub(time.Unix(expires, 0).Add(-DefaultSignatureDuration))
	base := context.WithoutCancel(r.Context())

	// A request that left before the renewal of its signature answered is
	// served on the signature that renewal minted
	renewed, settled := restingSessions.renewedTo(rn.settled, rn.started)
	if settled {
		putSignatureInCookies(w, r, renewed)
		return renewed, false
	}

	token, leased := rn.lease(base, w, r)
	if !leased {
		return "", false
	}

	refreshCtx, cancelRefresh := context.WithTimeout(base, renewalRefreshTimeout)
	defer cancelRefresh()
	tokens, err := patreon.RefreshAuthToken(refreshCtx, rn.client, infra.Patreon.Secret[source], token)
	var grant *patreon.GrantError
	if errors.As(err, &grant) && grant.Code == patreon.InvalidGrant {
		if rn.revoke(base, token, err) {
			clearSessionCookie(w, r)
		}
		return "", false
	}
	if err != nil {
		rn.hold(base, "", "unknown", err)
		return "", false
	}

	patreonCtx, cancel := context.WithTimeout(base, min(infra.PatreonRenewal.RenewTimeout(), renewalLookupMax))
	defer cancel()
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
		restingSessions.rest(rn.settled, sig, time.Now().Add(renewalSettle), time.Now())
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
