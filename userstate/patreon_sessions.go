package userstate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// Every statement here runs on its own and holds no connection once it
// returns, so none of it is lost to a transaction pooler and a Patreon call
// made between a lease and its commit costs the pool nothing. Durations
// travel as seconds and the database clock decides every expiry.

// newPatreonSessionID is 32 random bytes, for a session id or a lease fence.
func newPatreonSessionID() (string, error) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// PatreonLogin is what a Patreon login leaves to renew from: the reader's
// email hash, the Patreon account and the client the refresh token was
// issued to, and the token.
type PatreonLogin struct {
	EmailHash    string
	PatreonUser  string
	ClientID     string
	RefreshToken string
}

// CreatePatreonSession stores a login's refresh token under a new session
// ID, due for renewal at once and valid for maxAge. age is how long ago
// Patreon issued the token: a renewal that rotated it meanwhile stored the
// newer one on the account's other sessions, and the lease takes the token
// renewed last.
func (c *Client) CreatePatreonSession(ctx context.Context, login PatreonLogin, age, maxAge time.Duration) (string, error) {
	id, err := newPatreonSessionID()
	if err != nil {
		return "", fmt.Errorf("userstate: session id: %w", err)
	}
	_, err = c.db.ExecContext(ctx, `
		INSERT INTO patreon_sessions (session_id, email_hash, patreon_user, client_id, refresh_token, last_renewed, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() - make_interval(secs => $6), now() + make_interval(secs => $7))`,
		id, login.EmailHash, login.PatreonUser, login.ClientID, login.RefreshToken, age.Seconds(), maxAge.Seconds())
	if err != nil {
		return "", err
	}
	return id, nil
}

// Patreon keeps one refresh token per account and client, so every session
// of a Patreon account under one client carries the same one and a renewal
// moves them together: the lease, the commit, the deferral and the revocation
// below each act on all of the account's sessions under the client, which the
// fence names once the lease is taken.

// LeasePatreonSessions claims the right to renew the Patreon account behind
// sessionID for lease, and returns its refresh token with the fence that
// commit, defer and revoke need. sessionID must be a live session of
// emailHash issued to clientID. It is one UPDATE over every live session of
// the account under the client: leased is false, with no error, when the
// session is not such a one, or when any live session of the account is
// already leased or backing off. The token is that of the session renewed
// last.
func (c *Client) LeasePatreonSessions(ctx context.Context, sessionID, emailHash, clientID string, lease time.Duration) (refreshToken, fence string, leased bool, err error) {
	fence, err = newPatreonSessionID()
	if err != nil {
		return "", "", false, fmt.Errorf("userstate: lease fence: %w", err)
	}
	// renew_after is tested on the rows being updated as well as through
	// NOT EXISTS: a concurrent lease that committed first leaves the rows
	// this statement waited for with a renew_after the subquery, which
	// reads the table as it was when the statement began, does not see.
	rows, err := c.db.QueryContext(ctx, `
		UPDATE patreon_sessions s
		   SET renew_after = now() + make_interval(secs => $4), lease = $5
		  FROM (SELECT patreon_user, client_id FROM patreon_sessions
		         WHERE session_id = $1 AND email_hash = $2 AND client_id = $3 AND expires_at > now()) own
		 WHERE s.patreon_user = own.patreon_user AND s.client_id = own.client_id
		   AND s.expires_at > now() AND s.renew_after <= now()
		   AND NOT EXISTS (SELECT 1 FROM patreon_sessions o
		                    WHERE o.patreon_user = own.patreon_user AND o.client_id = own.client_id
		                      AND o.expires_at > now() AND o.renew_after > now())
		RETURNING s.refresh_token, s.last_renewed`,
		sessionID, emailHash, clientID, lease.Seconds(), fence)
	if err != nil {
		return "", "", false, err
	}
	defer rows.Close()
	var newest time.Time
	for rows.Next() {
		var token string
		var renewed time.Time
		err = rows.Scan(&token, &renewed)
		if err != nil {
			return "", "", false, err
		}
		if !leased || renewed.After(newest) {
			refreshToken, newest, leased = token, renewed, true
		}
	}
	err = rows.Err()
	if err != nil {
		return "", "", false, err
	}
	if !leased {
		return "", "", false, nil
	}
	return refreshToken, fence, true, nil
}

// CommitPatreonSessions stores the refresh token a renewal returned on every
// session of the account fence leased, one created after the lease included,
// files them under emailHash, the reader's email as Patreon reports it now,
// and makes them leasable again after rest, at once when rest is zero. rows
// is 0 when fence is no longer held: the sessions were deleted meanwhile, or
// the lease ran out and was taken over. A holder that outlived its lease
// must not overwrite a token a later holder rotated, and the caller must not
// act on a renewal the reader has revoked.
func (c *Client) CommitPatreonSessions(ctx context.Context, fence, emailHash, refreshToken string, rest time.Duration) (rows int64, err error) {
	res, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET refresh_token = $3, email_hash = $2, last_renewed = now(),
		       renew_after = now() + make_interval(secs => $4), lease = NULL
		 WHERE (patreon_user, client_id) IN (SELECT patreon_user, client_id FROM patreon_sessions WHERE lease = $1)`,
		fence, emailHash, refreshToken, rest.Seconds())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeferPatreonSessions holds every session of the account fence leased back
// from renewal for until, when fence is still held. A renewal whose refresh
// went through before it learned nothing usable passes the token Patreon
// rotated to, which is stored with the deferral since the old one is dead;
// empty leaves the stored token as it is.
func (c *Client) DeferPatreonSessions(ctx context.Context, fence, refreshToken string, until time.Duration) error {
	_, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET renew_after = now() + make_interval(secs => $3),
		       refresh_token = COALESCE(NULLIF($2, ''), refresh_token),
		       last_renewed = CASE WHEN $2 = '' THEN last_renewed ELSE now() END
		 WHERE (patreon_user, client_id) IN (SELECT patreon_user, client_id FROM patreon_sessions WHERE lease = $1)`,
		fence, refreshToken, until.Seconds())
	return err
}

// RevokePatreonSessions deletes the sessions of the account fence leased
// that hold refreshToken, one Patreon refused for good, and returns their
// ids. A session holding another token stays to be tried at its next lease,
// and nothing goes once fence is no longer held: a renewal that won the
// refresh this one lost has committed a live token to them all.
func (c *Client) RevokePatreonSessions(ctx context.Context, fence, refreshToken string) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, `
		DELETE FROM patreon_sessions
		 WHERE refresh_token = $2
		   AND (patreon_user, client_id) IN (SELECT patreon_user, client_id FROM patreon_sessions WHERE lease = $1)
		RETURNING session_id`,
		fence, refreshToken)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var gone []string
	for rows.Next() {
		var id string
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		gone = append(gone, id)
	}
	return gone, rows.Err()
}

// DeletePatreonSession removes one session.
func (c *Client) DeletePatreonSession(ctx context.Context, sessionID string) error {
	_, err := c.db.ExecContext(ctx,
		`DELETE FROM patreon_sessions WHERE session_id = $1`, sessionID)
	return err
}

// DeletePatreonSessions removes every session an email hash holds and says
// how many went.
func (c *Client) DeletePatreonSessions(ctx context.Context, emailHash string) (int64, error) {
	res, err := c.db.ExecContext(ctx,
		`DELETE FROM patreon_sessions WHERE email_hash = $1`, emailHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PrunePatreonSessions deletes expired sessions and says how many went.
func (c *Client) PrunePatreonSessions(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM patreon_sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
