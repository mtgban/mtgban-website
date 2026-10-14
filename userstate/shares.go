package userstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"
)

// ErrShareNotFound says a share id names no live share.
var ErrShareNotFound = errors.New("userstate: share not found")

// shareIDLen is 16 random bytes as unpadded base64url.
const shareIDLen = 22

func newShareID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ValidShareID reports whether s has the shape newShareID makes, so a
// page can refuse a malformed id before asking the store.
func ValidShareID(s string) bool {
	if len(s) != shareIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// CreateShare retires the owner's live share on the game and makes a new
// one, so one link is live per owner and game: sites sharing the database
// never see or retire each other's. A create that loses a race to another
// for the same owner and game returns the winner's id.
func (c *Client) CreateShare(ctx context.Context, emailHash, game string) (string, error) {
	id, err := newShareID()
	if err != nil {
		return "", fmt.Errorf("userstate: share id: %w", err)
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`UPDATE favorites_shares SET revoked_at = now() WHERE email_hash = $1 AND game = $2 AND revoked_at IS NULL`,
		emailHash, game); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO favorites_shares (share_id, email_hash, game) VALUES ($1, $2, $3)`,
		id, emailHash, game); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			_ = tx.Rollback()
			return c.ShareFor(ctx, emailHash, game)
		}
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// RevokeShare ends the owner's live share on the game, if any.
func (c *Client) RevokeShare(ctx context.Context, emailHash, game string) error {
	_, err := c.db.ExecContext(ctx,
		`UPDATE favorites_shares SET revoked_at = now() WHERE email_hash = $1 AND game = $2 AND revoked_at IS NULL`,
		emailHash, game)
	return err
}

// ShareFor is the owner's live share id on the game, or "" with no error.
func (c *Client) ShareFor(ctx context.Context, emailHash, game string) (string, error) {
	var id string
	err := c.db.QueryRowContext(ctx,
		`SELECT share_id FROM favorites_shares WHERE email_hash = $1 AND game = $2 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`,
		emailHash, game).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SharedFavorites is the owner's favorites behind a live share made on this
// game's site: [] when the owner has no row yet, ErrShareNotFound when the
// id is unknown, revoked or another game's.
func (c *Client) SharedFavorites(ctx context.Context, shareID, game string) (json.RawMessage, error) {
	var fav []byte
	err := c.db.QueryRowContext(ctx, `
		SELECT COALESCE(u.favorites, '[]'::jsonb)
		  FROM favorites_shares s
		  LEFT JOIN user_state u ON u.email_hash = s.email_hash
		 WHERE s.share_id = $1 AND s.revoked_at IS NULL AND s.game = $2`,
		shareID, game).Scan(&fav)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrShareNotFound
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(fav), nil
}
