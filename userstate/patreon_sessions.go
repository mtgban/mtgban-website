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

// CreatePatreonSession stores a login's refresh token under a new session
// ID, due for renewal at once and valid for maxAge.
func (c *Client) CreatePatreonSession(ctx context.Context, emailHash, refreshToken string, maxAge time.Duration) (string, error) {
	id, err := newPatreonSessionID()
	if err != nil {
		return "", fmt.Errorf("userstate: session id: %w", err)
	}
	_, err = c.db.ExecContext(ctx, `
		INSERT INTO patreon_sessions (session_id, email_hash, refresh_token, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
		id, emailHash, refreshToken, maxAge.Seconds())
	if err != nil {
		return "", err
	}
	return id, nil
}

// Patreon keeps one refresh token per account and client, so every session
// of an email hash carries the same one and a renewal moves them together:
// the lease, the commit and the deferral below each act on all of an email
// hash's sessions.

// LeasePatreonSessions claims the right to renew the Patreon account behind
// sessionID's email hash for lease, and returns its refresh token with the
// fence that commit and defer need. It is one UPDATE over every live session
// of the email hash: leased is false, with no error, when sessionID is
// unknown, belongs to another email hash or is past its expiry, or when any
// live session of the email hash is already leased or backing off. The token
// is that of the session renewed last.
func (c *Client) LeasePatreonSessions(ctx context.Context, sessionID, emailHash string, lease time.Duration) (refreshToken, fence string, leased bool, err error) {
	fence, err = newPatreonSessionID()
	if err != nil {
		return "", "", false, fmt.Errorf("userstate: lease fence: %w", err)
	}
	// renew_after is tested on the rows being updated as well as through
	// NOT EXISTS: a concurrent lease that committed first leaves the rows
	// this statement waited for with a renew_after the subquery, which
	// reads the table as it was when the statement began, does not see.
	rows, err := c.db.QueryContext(ctx, `
		UPDATE patreon_sessions
		   SET renew_after = now() + make_interval(secs => $3), lease = $4
		 WHERE email_hash = $2 AND expires_at > now() AND renew_after <= now()
		   AND EXISTS (SELECT 1 FROM patreon_sessions
		                WHERE session_id = $1 AND email_hash = $2 AND expires_at > now())
		   AND NOT EXISTS (SELECT 1 FROM patreon_sessions
		                    WHERE email_hash = $2 AND expires_at > now() AND renew_after > now())
		RETURNING refresh_token, last_renewed`,
		sessionID, emailHash, lease.Seconds(), fence)
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
// session of the email hash, one created after the lease included, and makes
// them leasable again after rest, at once when rest is zero. rows is 0 when
// fence is no longer held: the sessions were deleted meanwhile, or the lease
// ran out and was taken over. A holder that outlived its lease must not
// overwrite a token a later holder rotated, and the caller must not act on a
// renewal the reader has revoked.
func (c *Client) CommitPatreonSessions(ctx context.Context, emailHash, fence, refreshToken string, rest time.Duration) (rows int64, err error) {
	res, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET refresh_token = $3, last_renewed = now(), renew_after = now() + make_interval(secs => $4), lease = NULL
		 WHERE email_hash = $1
		   AND EXISTS (SELECT 1 FROM patreon_sessions WHERE email_hash = $1 AND lease = $2)`,
		emailHash, fence, refreshToken, rest.Seconds())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeferPatreonSessions holds every session of the email hash back from
// renewal for until, when fence is still held. A renewal whose refresh went
// through before it learned nothing usable passes the token Patreon rotated
// to, which is stored with the deferral since the old one is dead; empty
// leaves the stored token as it is.
func (c *Client) DeferPatreonSessions(ctx context.Context, emailHash, fence, refreshToken string, until time.Duration) error {
	_, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET renew_after = now() + make_interval(secs => $3),
		       refresh_token = COALESCE(NULLIF($4, ''), refresh_token),
		       last_renewed = CASE WHEN $4 = '' THEN last_renewed ELSE now() END
		 WHERE email_hash = $1
		   AND EXISTS (SELECT 1 FROM patreon_sessions WHERE email_hash = $1 AND lease = $2)`,
		emailHash, fence, until.Seconds(), refreshToken)
	return err
}

// RekeyPatreonSessions moves every session of an email hash to another, for
// a Patreon account whose email changed.
func (c *Client) RekeyPatreonSessions(ctx context.Context, emailHash, newEmailHash string) error {
	_, err := c.db.ExecContext(ctx,
		`UPDATE patreon_sessions SET email_hash = $2 WHERE email_hash = $1`,
		emailHash, newEmailHash)
	return err
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
