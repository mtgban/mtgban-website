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

// UploadShare is one upload's rows, kept under a key until it expires.
type UploadShare struct {
	Key       string
	EmailHash string
	Rows      string
	Buylist   bool
	Game      string
	ExpiresAt time.Time
}

// uploadShareKeyLen is 16 random bytes as unpadded base64url.
const uploadShareKeyLen = 22

func newUploadShareKey() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ValidUploadShareKey reports whether key has the shape newUploadShareKey
// makes, so a page can refuse a malformed key before asking the store.
func ValidUploadShareKey(key string) bool {
	if len(key) != uploadShareKeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// CreateUploadShare stores rows under a new key for ttl.
func (c *Client) CreateUploadShare(ctx context.Context, emailHash, game, rows string, buylist bool, ttl time.Duration) (UploadShare, error) {
	key, err := newUploadShareKey()
	if err != nil {
		return UploadShare{}, fmt.Errorf("userstate: share key: %w", err)
	}
	share := UploadShare{Key: key, EmailHash: emailHash, Game: game, Rows: rows, Buylist: buylist, ExpiresAt: time.Now().Add(ttl)}
	_, err = c.db.ExecContext(ctx, `
		INSERT INTO upload_shares (share_key, email_hash, game, rows, buylist, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		share.Key, share.EmailHash, share.Game, share.Rows, share.Buylist, share.ExpiresAt)
	if err != nil {
		return UploadShare{}, err
	}
	return share, nil
}

// UploadShareByKey reads a live share of game; found is false for a
// malformed, unknown, expired or other-game key.
func (c *Client) UploadShareByKey(ctx context.Context, key, game string) (UploadShare, bool, error) {
	if !ValidUploadShareKey(key) {
		return UploadShare{}, false, nil
	}
	share := UploadShare{Key: key, Game: game}
	err := c.db.QueryRowContext(ctx, `
		SELECT email_hash, rows, buylist, expires_at
		  FROM upload_shares
		 WHERE share_key = $1 AND game = $2 AND expires_at > now()`, key, game,
	).Scan(&share.EmailHash, &share.Rows, &share.Buylist, &share.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UploadShare{}, false, nil
	}
	if err != nil {
		return UploadShare{}, false, err
	}
	return share, true, nil
}

// PruneUploadShares deletes expired shares and says how many went.
func (c *Client) PruneUploadShares(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM upload_shares WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountLiveUploadShares counts the unexpired shares an owner holds.
func (c *Client) CountLiveUploadShares(ctx context.Context, emailHash string) (int, error) {
	var n int
	err := c.db.QueryRowContext(ctx,
		`SELECT count(*) FROM upload_shares WHERE email_hash = $1 AND expires_at > now()`,
		emailHash).Scan(&n)
	return n, err
}
