package userstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
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

// LeasePatreonSession claims the right to renew a session for lease and
// returns its refresh token with the fence that commit and defer need. It
// is one UPDATE: leased is false, with no error, when the session is
// unknown, belongs to another email hash, is past its expiry, or is already
// leased or backing off.
func (c *Client) LeasePatreonSession(ctx context.Context, sessionID, emailHash string, lease time.Duration) (refreshToken, fence string, leased bool, err error) {
	fence, err = newPatreonSessionID()
	if err != nil {
		return "", "", false, fmt.Errorf("userstate: lease fence: %w", err)
	}
	err = c.db.QueryRowContext(ctx, `
		UPDATE patreon_sessions
		   SET renew_after = now() + make_interval(secs => $3), lease = $4
		 WHERE session_id = $1 AND email_hash = $2 AND renew_after <= now() AND expires_at > now()
		RETURNING refresh_token`,
		sessionID, emailHash, lease.Seconds(), fence,
	).Scan(&refreshToken)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return refreshToken, fence, true, nil
}

// CommitPatreonSession stores the refresh token a renewal returned and
// makes the session leasable again. stored is false when the session was
// deleted meanwhile, or when fence is not the current lease's: a holder that
// outlived its lease must not overwrite a token a later holder rotated, and
// the caller must not act on a renewal the reader has revoked.
func (c *Client) CommitPatreonSession(ctx context.Context, sessionID, fence, refreshToken string) (stored bool, err error) {
	res, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET refresh_token = $3, last_renewed = now(), renew_after = now()
		 WHERE session_id = $1 AND lease = $2`,
		sessionID, fence, refreshToken)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// DeferPatreonSession holds a session back from renewal for until, when
// fence is still the current lease's.
func (c *Client) DeferPatreonSession(ctx context.Context, sessionID, fence string, until time.Duration) error {
	_, err := c.db.ExecContext(ctx, `
		UPDATE patreon_sessions
		   SET renew_after = now() + make_interval(secs => $3)
		 WHERE session_id = $1 AND lease = $2`,
		sessionID, fence, until.Seconds())
	return err
}

// RekeyPatreonSession moves a session to another email hash, for a Patreon
// account whose email changed.
func (c *Client) RekeyPatreonSession(ctx context.Context, sessionID, emailHash string) error {
	_, err := c.db.ExecContext(ctx,
		`UPDATE patreon_sessions SET email_hash = $2 WHERE session_id = $1`,
		sessionID, emailHash)
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
