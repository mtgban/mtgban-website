package userstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

var (
	// ErrInviteNotFound says no invite has the code, or none still open
	// to revoke.
	ErrInviteNotFound = errors.New("userstate: invite not found")
	// ErrInviteClosed says the invite cannot be accepted: used up,
	// expired, revoked, or its tier no longer one an invite may sign.
	ErrInviteClosed = errors.New("userstate: invite closed")
	// ErrInviteCodeTaken says another invite already has the code.
	ErrInviteCodeTaken = errors.New("userstate: invite code taken")
)

// Invite is one invite link, as minted and as used since.
type Invite struct {
	Code       string
	Game       string
	Tier       string
	Overrides  map[string]map[string]string
	MaxUses    int
	Uses       int
	AccessDays int
	OpenUntil  time.Time
	Note       string

	CreatedAt   time.Time
	CreatedBy   string
	CreatedIP   string
	CreatedUA   string
	CreatedSite string

	// RevokedAt is zero while the invite is not revoked.
	RevokedAt time.Time
	RevokedBy string
}

// Redeem is one press of an invite's Accept button.
type Redeem struct {
	Code  string
	Nonce string
	// Tiers are the tiers an invite may sign now; an invite whose own
	// tier is not among them is closed.
	Tiers    []string
	IP       string
	UA       string
	Site     string
	SignedIn bool
}

// Redemption is one acceptance of an invite. Tier and Overrides are the
// invite's, filled by RedeemInvite for the signature it is to mint.
type Redemption struct {
	RedeemedAt time.Time
	ExpiresAt  time.Time
	IP         string
	UA         string
	Site       string
	SignedIn   bool

	Tier      string
	Overrides map[string]map[string]string
	// Repeat says the nonce had already redeemed: nothing was spent, and
	// this is that first acceptance.
	Repeat bool
}

const inviteColumns = `code, game, tier, overrides, max_uses, uses, access_days, open_until, note,
	created_at, created_by, created_ip, created_ua, created_site, revoked_at, revoked_by`

// CreateInvite stores inv as minted; its code is the caller's to draw,
// and ErrInviteCodeTaken asks for another.
func (c *Client) CreateInvite(ctx context.Context, inv Invite) (Invite, error) {
	overrides, err := json.Marshal(nonNilOverrides(inv.Overrides))
	if err != nil {
		return Invite{}, err
	}
	row := c.db.QueryRowContext(ctx, `
		INSERT INTO invites (code, game, tier, overrides, max_uses, access_days, open_until, note,
			created_by, created_ip, created_ua, created_site)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (code) DO NOTHING
		RETURNING `+inviteColumns,
		inv.Code, inv.Game, inv.Tier, string(overrides), inv.MaxUses, inv.AccessDays, inv.OpenUntil, inv.Note,
		inv.CreatedBy, inv.CreatedIP, inv.CreatedUA, inv.CreatedSite)
	created, err := scanInvite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrInviteCodeTaken
	}
	return created, err
}

// InviteByCode reads one invite, open or not.
func (c *Client) InviteByCode(ctx context.Context, code string) (Invite, error) {
	row := c.db.QueryRowContext(ctx, `SELECT `+inviteColumns+` FROM invites WHERE code = $1`, code)
	inv, err := scanInvite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrInviteNotFound
	}
	return inv, err
}

// Invites lists the newest invites first, of every game.
func (c *Client) Invites(ctx context.Context, limit int) ([]Invite, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT `+inviteColumns+` FROM invites ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// InviteRedemptions lists the acceptances of each code, oldest first.
func (c *Client) InviteRedemptions(ctx context.Context, codes []string) (map[string][]Redemption, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT code, redeemed_at, expires_at, ip, ua, site, signed_in
		FROM invite_redemptions WHERE code = ANY($1) ORDER BY redeemed_at, id`, pq.Array(codes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Redemption{}
	for rows.Next() {
		var code string
		var red Redemption
		err := rows.Scan(&code, &red.RedeemedAt, &red.ExpiresAt, &red.IP, &red.UA, &red.Site, &red.SignedIn)
		if err != nil {
			return nil, err
		}
		out[code] = append(out[code], red)
	}
	return out, rows.Err()
}

// RedeemInvite spends one use of an open invite and records who spent it,
// in one transaction, so two presses on the last use cannot both have it.
// A press whose nonce already redeemed the invite spends nothing and gets
// that first redemption back, marked Repeat, while the invite's tier is
// still in Tiers; it can find the invite used up, or collide on the nonce,
// when it raced the first.
func (c *Client) RedeemInvite(ctx context.Context, in Redeem) (Redemption, error) {
	red, err := c.spendInvite(ctx, in)
	if err == nil {
		return red, nil
	}
	if !errors.Is(err, ErrInviteClosed) && !isUniqueViolation(err) {
		return Redemption{}, err
	}
	red, err = c.redemptionByNonce(ctx, in.Code, in.Nonce, in.Tiers)
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, ErrInviteClosed
	}
	if err != nil {
		return Redemption{}, err
	}
	red.Repeat = true
	return red, nil
}

func (c *Client) spendInvite(ctx context.Context, in Redeem) (Redemption, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return Redemption{}, err
	}
	defer tx.Rollback()

	var red Redemption
	var overrides []byte
	var accessDays int
	err = tx.QueryRowContext(ctx, `
		UPDATE invites SET uses = uses + 1
		WHERE code = $1 AND tier = ANY($2) AND revoked_at IS NULL
			AND open_until > now() AND uses < max_uses
		RETURNING tier, overrides, access_days`, in.Code, pq.Array(in.Tiers)).Scan(&red.Tier, &overrides, &accessDays)
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, ErrInviteClosed
	}
	if err != nil {
		return Redemption{}, err
	}
	err = json.Unmarshal(overrides, &red.Overrides)
	if err != nil {
		return Redemption{}, fmt.Errorf("userstate: invite overrides: %w", err)
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO invite_redemptions (code, nonce, expires_at, ip, ua, site, signed_in)
		VALUES ($1, $2, now() + $3 * interval '1 day', $4, $5, $6, $7)
		RETURNING redeemed_at, expires_at`,
		in.Code, in.Nonce, accessDays, in.IP, in.UA, in.Site, in.SignedIn).Scan(&red.RedeemedAt, &red.ExpiresAt)
	if err != nil {
		return Redemption{}, err
	}
	red.IP, red.UA, red.Site, red.SignedIn = in.IP, in.UA, in.Site, in.SignedIn
	return red, tx.Commit()
}

// redemptionByNonce is the redemption the nonce made, with its invite's
// tier and overrides; sql.ErrNoRows when it made none, or when that tier
// is not among tiers, since a repeat signs the tier again.
func (c *Client) redemptionByNonce(ctx context.Context, code, nonce string, tiers []string) (Redemption, error) {
	var red Redemption
	var overrides []byte
	err := c.db.QueryRowContext(ctx, `
		SELECT r.redeemed_at, r.expires_at, r.ip, r.ua, r.site, r.signed_in, i.tier, i.overrides
		FROM invite_redemptions r JOIN invites i USING (code)
		WHERE r.code = $1 AND r.nonce = $2 AND i.tier = ANY($3)`, code, nonce, pq.Array(tiers)).Scan(
		&red.RedeemedAt, &red.ExpiresAt, &red.IP, &red.UA, &red.Site, &red.SignedIn, &red.Tier, &overrides)
	if err != nil {
		return Redemption{}, err
	}
	err = json.Unmarshal(overrides, &red.Overrides)
	if err != nil {
		return Redemption{}, fmt.Errorf("userstate: invite overrides: %w", err)
	}
	return red, nil
}

// RevokeInvite closes an invite to further acceptances.
func (c *Client) RevokeInvite(ctx context.Context, code, by string) error {
	res, err := c.db.ExecContext(ctx,
		`UPDATE invites SET revoked_at = now(), revoked_by = $2 WHERE code = $1 AND revoked_at IS NULL`, code, by)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// PruneInvites deletes the invites closed for more than 90 days, by
// expiry or by revocation, and their redemptions with them.
func (c *Client) PruneInvites(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx,
		`DELETE FROM invites WHERE LEAST(open_until, revoked_at) < now() - interval '90 days'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// rowScanner is what scanInvite reads from: a *sql.Row or *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanInvite(row rowScanner) (Invite, error) {
	var inv Invite
	var overrides []byte
	var revoked sql.NullTime
	err := row.Scan(&inv.Code, &inv.Game, &inv.Tier, &overrides, &inv.MaxUses, &inv.Uses, &inv.AccessDays,
		&inv.OpenUntil, &inv.Note, &inv.CreatedAt, &inv.CreatedBy, &inv.CreatedIP, &inv.CreatedUA,
		&inv.CreatedSite, &revoked, &inv.RevokedBy)
	if err != nil {
		return Invite{}, err
	}
	err = json.Unmarshal(overrides, &inv.Overrides)
	if err != nil {
		return Invite{}, fmt.Errorf("userstate: invite overrides: %w", err)
	}
	inv.RevokedAt = revoked.Time
	return inv, nil
}

func nonNilOverrides(o map[string]map[string]string) map[string]map[string]string {
	if o == nil {
		return map[string]map[string]string{}
	}
	return o
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}
