package alerts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// Store is the alerts tables on the userstate pool, which the API and the
// evaluator share with user_state; its 5-connection default covers all.
type Store struct {
	db *sql.DB
}

// alertsSchemaLockID is the pg_advisory_xact_lock key that serialises the
// schema DDL across concurrent first starts.
const alertsSchemaLockID = 7264617

// New wraps an already-open pool (shared with userstate) and ensures the
// alerts schema on it.
func New(db *sql.DB) (*Store, error) {
	err := ensureSchema(db)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// ensureSchema runs the DDL inside one transaction, serialised by an
// advisory lock so concurrent first starts don't race the catalog.
func ensureSchema(db *sql.DB) error {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("alerts: begin schema tx: %w", err)
	}
	_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, alertsSchemaLockID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("alerts: advisory lock: %w", err)
	}
	var newLedger bool
	err = tx.QueryRowContext(ctx, `SELECT to_regclass('alert_mails') IS NULL`).Scan(&newLedger)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("alerts: find mail ledger: %w", err)
	}
	_, err = tx.ExecContext(ctx, schemaSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("alerts: ensure schema: %w", err)
	}
	// A new ledger starts with the day's mails as alert_events counted them,
	// once: a restart finds the table and leaves it be.
	if newLedger {
		_, err = tx.ExecContext(ctx, ledgerBackfillSQL)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("alerts: backfill mail ledger: %w", err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("alerts: commit schema: %w", err)
	}
	return nil
}

// UpsertContact records what login learned. The Discord id is only ever
// written by a login that had an opinion on it (DiscordKnown); an unknown
// login leaves whatever id is already on the row alone.
func (s *Store) UpsertContact(ctx context.Context, c Contact) error {
	writeDiscord := c.DiscordKnown
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_contacts (user_hash, discord_user_id, tier, updated_at)
		VALUES ($1, CASE WHEN $4 THEN NULLIF($2, '') ELSE NULL END, $3, now())
		ON CONFLICT (user_hash) DO UPDATE
		   SET discord_user_id = CASE WHEN $4 THEN NULLIF($2, '') ELSE alert_contacts.discord_user_id END,
		       tier = EXCLUDED.tier,
		       updated_at = now()`,
		c.UserHash, c.DiscordUserID, c.Tier, writeDiscord)
	return err
}

// EnsureContact makes sure a row exists for a user who logged in before
// contacts were captured. It only inserts: an existing row's tier is
// login's to set, not a stale cookie's on some later create.
func (s *Store) EnsureContact(ctx context.Context, userHash, tier string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_contacts (user_hash, tier) VALUES ($1, $2)
		ON CONFLICT (user_hash) DO NOTHING`,
		userHash, tier)
	return err
}

// RefreshContactTier moves an existing contact's tier; it never inserts,
// so a user without alerts leaves no row behind. It also bumps updated_at,
// so updated_at means the last login of any tier, not just one with alerts,
// and the evaluator still computes allowance 0 from a lapsed tier.
func (s *Store) RefreshContactTier(ctx context.Context, userHash, tier string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_contacts SET tier = $2, updated_at = now() WHERE user_hash = $1`,
		userHash, tier)
	return err
}

// Contact reads one user's row; found is false when there is none.
func (s *Store) Contact(ctx context.Context, userHash string) (Contact, bool, error) {
	c := Contact{UserHash: userHash}
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(discord_user_id, ''), tier, updated_at
		  FROM alert_contacts WHERE user_hash = $1`, userHash,
	).Scan(&c.DiscordUserID, &c.Tier, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Contact{}, false, nil
	}
	if err != nil {
		return Contact{}, false, err
	}
	return c, true, nil
}

const channelColumns = `user_hash, kind, address, source, verified_at, disabled_at, disabled_reason, created_at, updated_at`

func scanChannel(row rowScanner) (Channel, error) {
	var c Channel
	var verifiedAt, disabledAt sql.NullTime
	err := row.Scan(&c.UserHash, &c.Kind, &c.Address, &c.Source, &verifiedAt, &disabledAt,
		&c.DisabledReason, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return Channel{}, err
	}
	if verifiedAt.Valid {
		t := verifiedAt.Time
		c.VerifiedAt = &t
	}
	if disabledAt.Valid {
		t := disabledAt.Time
		c.DisabledAt = &t
	}
	return c, nil
}

// UpsertChannel inserts a channel or updates its address; verified_at is
// written as given, and a changed address is a new row in all but its key.
func (s *Store) UpsertChannel(ctx context.Context, c Channel) error {
	return upsertChannel(ctx, s.db, c)
}

// StageEmail claims a confirm mail to address as ClaimConfirmSend does and
// puts address on the user's own email row, unless the row holds a working
// address, which stays until the new one is confirmed; claimed is false,
// staging nothing, when the claim is refused. Both happen under the user's
// lock, against the row as a confirm left it, so an unsubscribe lands
// before the claim or after the row moved, never in between.
func (s *Store) StageEmail(ctx context.Context, userHash, address string, now, since time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return false, err
	}
	err = lockAddress(ctx, tx, address)
	if err != nil {
		return false, err
	}
	claimed, err := claimConfirmSend(ctx, tx, userHash, address, now, since)
	if err != nil || !claimed {
		return false, err
	}
	var working bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM alert_channels
		 WHERE user_hash = $1 AND kind = 'email' AND source = 'user' AND verified_at IS NOT NULL AND disabled_at IS NULL
		   AND lower(address) <> lower($2))`, userHash, address).Scan(&working)
	if err != nil {
		return false, err
	}
	if !working {
		err = upsertChannel(ctx, tx, Channel{UserHash: userHash, Kind: ChannelEmail, Address: address, Source: SourceUser})
		if err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func upsertChannel(ctx context.Context, db execer, c Channel) error {
	var verifiedAt any
	if c.VerifiedAt != nil {
		verifiedAt = *c.VerifiedAt
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO alert_channels (user_hash, kind, address, source, verified_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (user_hash, kind, source) DO UPDATE
		   SET address = EXCLUDED.address,
		       verified_at = CASE WHEN lower(alert_channels.address) = lower(EXCLUDED.address) THEN COALESCE(EXCLUDED.verified_at, alert_channels.verified_at) ELSE EXCLUDED.verified_at END,
		       disabled_at = CASE WHEN lower(alert_channels.address) = lower(EXCLUDED.address) THEN alert_channels.disabled_at ELSE NULL END,
		       disabled_reason = CASE WHEN lower(alert_channels.address) = lower(EXCLUDED.address) THEN alert_channels.disabled_reason ELSE '' END,
		       created_at = CASE WHEN lower(alert_channels.address) = lower(EXCLUDED.address) THEN alert_channels.created_at ELSE now() END,
		       updated_at = now()`,
		c.UserHash, c.Kind, c.Address, c.Source, verifiedAt)
	return err
}

// Channels is every channel a user has, Discord and email alike.
func (s *Store) Channels(ctx context.Context, userHash string) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+channelColumns+`
		  FROM alert_channels WHERE user_hash = $1 ORDER BY kind, source`, userHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChannelFor is the active channel of a kind: a verified user address over
// an undisabled patreon one. Discord falls back to the legacy
// alert_contacts.discord_user_id, read as a synthetic verified patreon
// channel, only when no alert_channels row of that kind exists at all; an
// explicit row that is merely disabled means none, not the old id.
func (s *Store) ChannelFor(ctx context.Context, userHash string, kind ChannelKind) (Channel, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+channelColumns+` FROM alert_channels
		 WHERE user_hash = $1 AND kind = $2 AND disabled_at IS NULL AND (source = 'patreon' OR verified_at IS NOT NULL)
		 ORDER BY (source = 'user') DESC LIMIT 1`, userHash, kind)
	c, err := scanChannel(row)
	if err == nil {
		return c, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Channel{}, false, err
	}
	if kind != ChannelDiscord {
		return Channel{}, false, nil
	}
	var anyRow bool
	err = s.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM alert_channels WHERE user_hash = $1 AND kind = $2)`,
		userHash, kind).Scan(&anyRow)
	if err != nil {
		return Channel{}, false, err
	}
	if anyRow {
		return Channel{}, false, nil
	}
	var discordID string
	var updatedAt time.Time
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(discord_user_id, ''), updated_at FROM alert_contacts WHERE user_hash = $1`,
		userHash).Scan(&discordID, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) || discordID == "" {
		return Channel{}, false, nil
	}
	if err != nil {
		return Channel{}, false, err
	}
	return Channel{UserHash: userHash, Kind: ChannelDiscord, Address: discordID, Source: SourcePatreon, VerifiedAt: &updatedAt}, true, nil
}

// SetChannelVerified stamps a channel verified and enabled while it still
// holds address and was neither unsubscribed nor marked as spam, its
// confirm mail included; found is
// false when no row matched. A user email row holding another address
// first moves to this one, in the same transaction so a refused confirm
// leaves the old address in place, if this was the user's latest confirm
// mail, failed sends aside, and came after the row was verified; an
// unsubscribed or spam-marked row never moves, so coming back takes a fresh
// add. A working row keeps its verified_at, so confirming it again leaves a
// newer request valid.
func (s *Store) SetChannelVerified(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource, address string, at time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return false, err
	}
	if kind == ChannelEmail {
		err = lockAddress(ctx, tx, address)
		if err != nil {
			return false, err
		}
	}
	if kind == ChannelEmail && source == SourceUser {
		_, err = tx.ExecContext(ctx, `
			UPDATE alert_channels c
			   SET address = r.address, verified_at = NULL, disabled_at = NULL, disabled_reason = '', created_at = now(), updated_at = now()
			  FROM alert_confirm_sends r
			 WHERE c.user_hash = $1 AND c.kind = 'email' AND c.source = 'user' AND lower(c.address) <> lower($2)
			   AND c.disabled_reason <> ALL($3)
			   AND r.user_hash = $1 AND r.address = lower($2) AND r.sent_at > COALESCE(c.verified_at, '-infinity')
			   AND NOT EXISTS (SELECT 1 FROM alert_confirm_sends n WHERE n.user_hash = $1 AND n.sent_at > r.sent_at AND NOT n.released)`,
			userHash, address, pq.Array([]string{ReasonUnsubscribed, ReasonComplained}))
		if err != nil {
			return false, err
		}
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE alert_channels SET verified_at = CASE WHEN verified_at IS NOT NULL AND disabled_at IS NULL THEN verified_at ELSE $5 END,
		       disabled_at = NULL, disabled_reason = '', updated_at = now()
		 WHERE user_hash = $1 AND kind = $2 AND source = $3 AND lower(address) = lower($4) AND disabled_reason <> ALL($6)
		   AND NOT EXISTS (SELECT 1 FROM alert_confirm_sends WHERE address = lower($4) AND complained_at IS NOT NULL)`,
		userHash, kind, source, address, at, pq.Array([]string{ReasonUnsubscribed, ReasonComplained}))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if kind == ChannelEmail {
		err = restoreEmailAlerts(ctx, tx, userHash)
		if err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// DisableChannel marks a channel unusable, with the reason why. A complaint
// is final: a row marked as spam keeps that reason and its time.
func (s *Store) DisableChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource, reason string, at time.Time) error {
	_, err := disableChannelAt(ctx, s.db, userHash, kind, source, "", reason, at)
	return err
}

// DisableAndPark is a mail report's write for one row: it disables the row
// if it still holds address, so a late report about an old address leaves
// the new one alone, and parks the user's email alerts when no working
// email channel is left. found is false when the row held another address.
// It runs under the user's lock, so a confirm restoring alerts cannot land
// between the check and the park.
func (s *Store) DisableAndPark(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource, address, reason, parkReason string, at time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return false, err
	}
	disabled, err := disableChannelAt(ctx, tx, userHash, kind, source, address, reason, at)
	if err != nil || !disabled {
		return false, err
	}
	if kind == ChannelEmail {
		working, err := emailWorks(ctx, tx, userHash)
		if err != nil {
			return false, err
		}
		if !working {
			_, err = parkEmailAlerts(ctx, tx, userHash, parkReason)
			if err != nil {
				return false, err
			}
		}
	}
	return true, tx.Commit()
}

// emailWorks is whether the user has an email channel mail can go to, as
// ChannelFor picks one.
func emailWorks(ctx context.Context, tx *sql.Tx, userHash string) (bool, error) {
	var working bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM alert_channels
		 WHERE user_hash = $1 AND kind = 'email' AND disabled_at IS NULL AND (source = 'patreon' OR verified_at IS NOT NULL))`,
		userHash).Scan(&working)
	return working, err
}

// UnsubscribeEmail disables every email row of the user's not already
// disabled, from either source, and parks their email alerts, in one
// transaction under the user's lock so an Enable cannot land in between.
func (s *Store) UnsubscribeEmail(ctx context.Context, userHash string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE alert_channels SET disabled_at = $2, disabled_reason = $3, updated_at = now()
		 WHERE user_hash = $1 AND kind = 'email' AND disabled_at IS NULL`, userHash, at, ReasonUnsubscribed)
	if err != nil {
		return err
	}
	_, err = parkEmailAlerts(ctx, tx, userHash, ParkUnsubscribed)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// execer is a pool or a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// userLockID namespaces the per-user advisory lock that orders a mail
// report's park against a confirm or enable restoring alerts.
const userLockID = alertsSchemaLockID + 2

// lockUser serialises, until tx ends, the channel writes that park or
// restore one user's email alerts.
func lockUser(ctx context.Context, tx *sql.Tx, userHash string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, userLockID, userHash)
	return err
}

// disableChannelAt disables a row still holding address, an empty one
// matching any; found is false when no row matched.
func disableChannelAt(ctx context.Context, db execer, userHash string, kind ChannelKind, source ChannelSource, address, reason string, at time.Time) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE alert_channels
		   SET disabled_at = CASE WHEN disabled_reason = $6 THEN disabled_at ELSE $5 END,
		       disabled_reason = CASE WHEN disabled_reason = $6 THEN disabled_reason ELSE $4 END,
		       updated_at = now()
		 WHERE user_hash = $1 AND kind = $2 AND source = $3 AND ($7 = '' OR lower(address) = lower($7))`,
		userHash, kind, source, reason, at, ReasonComplained, address)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// EnableChannel clears a channel's disabled state, unless it was marked as
// spam; found is false when no row was enabled.
func (s *Store) EnableChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource) (bool, error) {
	return s.enableAndRestore(ctx, userHash, kind, `
		UPDATE alert_channels SET disabled_at = NULL, disabled_reason = '', updated_at = now()
		 WHERE user_hash = $1 AND kind = $2 AND source = $3 AND disabled_reason <> $4`, userHash, kind, source, ReasonComplained)
}

// enableAndRestore runs a channel UPDATE and, when it matched an email row,
// returns the user's email alerts parked for their address to active.
func (s *Store) enableAndRestore(ctx context.Context, userHash string, kind ChannelKind, update string, args ...any) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, update, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 && kind == ChannelEmail {
		err = restoreEmailAlerts(ctx, tx, userHash)
		if err != nil {
			return false, err
		}
	}
	return n > 0, tx.Commit()
}

// restoreEmailAlerts returns a user's email alerts parked for their address
// to active, inside the transaction that gave them a working one.
func restoreEmailAlerts(ctx context.Context, tx *sql.Tx, userHash string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE alerts SET status = 'active', last_error = '', updated_at = now()
		 WHERE user_hash = $1 AND status = 'undeliverable' AND delivery = 'email' AND last_error = ANY($2)`,
		userHash, pq.Array(emailParkReasons))
	return err
}

// DeleteChannel removes a channel outright.
func (s *Store) DeleteChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM alert_channels WHERE user_hash = $1 AND kind = $2 AND source = $3`, userHash, kind, source)
	return err
}

// ChannelByAddress is every channel using an address, for the webhook that
// resolves an inbound bounce or reply back to its user.
func (s *Store) ChannelByAddress(ctx context.Context, kind ChannelKind, address string) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+channelColumns+`
		  FROM alert_channels WHERE kind = $1 AND lower(address) = lower($2)`, kind, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// parkEmailAlerts marks a user's active email alerts undeliverable, inside
// the transaction that took their last working address; it answers how many
// rows it touched.
func parkEmailAlerts(ctx context.Context, db execer, userHash, reason string) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE alerts SET status = 'undeliverable', last_error = $2, updated_at = now()
		 WHERE user_hash = $1 AND status = 'active' AND delivery = 'email'`,
		userHash, reason)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ClaimConfirmSend records, before its mail goes, that userHash asked for
// a confirm mail to address at now; false means one went to the address,
// from anyone, since. The confirm link resolves against the record, so the
// user's working address stays in place until the new one is confirmed.
// An address a confirm mail drew a complaint from is never claimed again,
// with ErrConfirmComplained.
func (s *Store) ClaimConfirmSend(ctx context.Context, userHash, address string, now, since time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockAddress(ctx, tx, address)
	if err != nil {
		return false, err
	}
	claimed, err := claimConfirmSend(ctx, tx, userHash, address, now, since)
	if err != nil || !claimed {
		return false, err
	}
	return true, tx.Commit()
}

// claimConfirmSend is ClaimConfirmSend inside tx, which holds the address's lock.
func claimConfirmSend(ctx context.Context, tx *sql.Tx, userHash, address string, now, since time.Time) (bool, error) {
	var recent, complained bool
	err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(bool_or(sent_at >= $2 AND NOT released), false), COALESCE(bool_or(complained_at IS NOT NULL), false)
		  FROM alert_confirm_sends WHERE address = lower($1)`,
		address, since).Scan(&recent, &complained)
	if err != nil {
		return false, err
	}
	if complained {
		return false, ErrConfirmComplained
	}
	if recent {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_confirm_sends (user_hash, address, sent_at) VALUES ($1, lower($2), $3)
		ON CONFLICT (user_hash, address) DO UPDATE SET sent_at = EXCLUDED.sent_at, released = false`,
		userHash, address, now)
	return err == nil, err
}

// ErrConfirmComplained is an address whose recipient marked a confirm mail as spam.
var ErrConfirmComplained = errors.New("alerts: address complained about a confirm mail")

// ComplainConfirmSend records a complaint about a mail to address, which no
// confirm mail then reaches: userHash's confirm mail, whether or not its
// request is still on file, or with userHash empty any other alert mail.
func (s *Store) ComplainConfirmSend(ctx context.Context, userHash, address string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockAddress(ctx, tx, address)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_confirm_sends (user_hash, address, sent_at, complained_at) VALUES ($1, lower($2), $3, $3)
		ON CONFLICT (user_hash, address) DO UPDATE SET complained_at = COALESCE(alert_confirm_sends.complained_at, EXCLUDED.complained_at)`,
		userHash, address, at)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// lockAddress serialises, until tx ends, the writers of one address's
// confirm mail records.
func lockAddress(ctx context.Context, tx *sql.Tx, address string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext(lower($2)))`, alertsSchemaLockID, address)
	return err
}

// ReleaseConfirmSend frees the claim made at at, for a mail that failed:
// the address may be mailed again at once, and a link that did go out
// still resolves.
func (s *Store) ReleaseConfirmSend(ctx context.Context, userHash, address string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_confirm_sends SET released = true WHERE user_hash = $1 AND address = lower($2) AND sent_at = $3`,
		userHash, address, at)
	return err
}

// PendingEmail is the replacement a user with a verified user email row
// last asked to confirm, since it was verified and since since, failed sends
// aside: the address its link can move the row to. found is false when
// there is none.
func (s *Store) PendingEmail(ctx context.Context, userHash string, since time.Time) (string, bool, error) {
	var address string
	err := s.db.QueryRowContext(ctx, `
		SELECT r.address FROM alert_confirm_sends r
		  JOIN alert_channels c ON c.user_hash = r.user_hash AND c.kind = 'email' AND c.source = 'user'
		 WHERE r.user_hash = $1 AND r.address <> lower(c.address) AND r.sent_at > c.verified_at AND r.sent_at > $2
		   AND NOT r.released
		   AND NOT EXISTS (SELECT 1 FROM alert_confirm_sends n WHERE n.user_hash = $1 AND n.sent_at > r.sent_at AND NOT n.released)
		   AND r.complained_at IS NULL`,
		userHash, since).Scan(&address)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return address, true, nil
}

// PruneUnverifiedChannels deletes user-entered addresses nobody ever
// verified, and the confirm mails recorded before the same time.
func (s *Store) PruneUnverifiedChannels(ctx context.Context, before time.Time) (int64, error) {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_confirm_sends WHERE sent_at < $1 AND complained_at IS NULL`, before)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM alert_channels WHERE source = 'user' AND verified_at IS NULL AND created_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ChannelsDisabledSince counts channels a bounce or complaint disabled in
// [since, until), for the admin dashboard's run summary.
func (s *Store) ChannelsDisabledSince(ctx context.Context, since, until time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM alert_channels WHERE disabled_at >= $1 AND disabled_at < $2 AND disabled_reason IN ($3, $4)`,
		since, until, ReasonBounced, ReasonComplained).Scan(&n)
	return n, err
}

const alertColumns = `id, user_hash, game, card_id, side, condition, stores, reference_price,
	above_kind, above_value, below_kind, below_value, delivery, status, above_armed, below_armed,
	last_fired_at, last_error, card_name, card_set, card_number, card_finish, created_price,
	created_at, updated_at, origin`

type rowScanner interface{ Scan(dest ...any) error }

func scanAlert(row rowScanner) (Alert, error) {
	var a Alert
	var aboveKind, belowKind sql.NullString
	var aboveValue, belowValue, createdPrice sql.NullFloat64
	var lastFired sql.NullTime
	err := row.Scan(&a.ID, &a.UserHash, &a.Game, &a.CardID, &a.Side, &a.Condition, pq.Array(&a.Stores), &a.ReferencePrice,
		&aboveKind, &aboveValue, &belowKind, &belowValue, &a.Delivery, &a.Status, &a.AboveArmed, &a.BelowArmed,
		&lastFired, &a.LastError, &a.Card.Name, &a.Card.Set, &a.Card.Number, &a.Card.Finish, &createdPrice,
		&a.CreatedAt, &a.UpdatedAt, &a.Origin)
	if err != nil {
		return Alert{}, err
	}
	if aboveKind.Valid {
		a.Above = Threshold{Kind: Kind(aboveKind.String), Value: aboveValue.Float64}
	}
	if belowKind.Valid {
		a.Below = Threshold{Kind: Kind(belowKind.String), Value: belowValue.Float64}
	}
	if lastFired.Valid {
		t := lastFired.Time
		a.LastFiredAt = &t
	}
	if createdPrice.Valid {
		p := createdPrice.Float64
		a.CreatedPrice = &p
	}
	// Guards against a NULL the schema does not produce.
	if a.Stores == nil {
		a.Stores = []string{}
	}
	return a, nil
}

func nullKind(t Threshold) (any, any) {
	if !t.Set() {
		return nil, nil
	}
	return string(t.Kind), t.Value
}

// Create inserts a validated alert, armed as it says, and returns it with
// its id and defaults.
func (s *Store) Create(ctx context.Context, a Alert) (Alert, error) {
	ak, av := nullKind(a.Above)
	bk, bv := nullKind(a.Below)
	var createdPrice any
	if a.CreatedPrice != nil {
		createdPrice = *a.CreatedPrice
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO alerts (user_hash, game, card_id, side, condition, stores, reference_price,
			above_kind, above_value, below_kind, below_value, delivery,
			card_name, card_set, card_number, card_finish, created_price, above_armed, below_armed, origin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING `+alertColumns,
		a.UserHash, a.Game, a.CardID, a.Side, a.Condition, pq.Array(a.Stores), a.ReferencePrice,
		ak, av, bk, bv, a.Delivery, a.Card.Name, a.Card.Set, a.Card.Number, a.Card.Finish, createdPrice,
		a.AboveArmed, a.BelowArmed, a.Origin)
	return scanAlert(row)
}

// ListByUser is one user's alerts for one game, newest first.
func (s *Store) ListByUser(ctx context.Context, userHash, game string) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE user_hash = $1 AND game = $2 ORDER BY created_at DESC, id DESC`, userHash, game)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountByUser counts every alert a user has for a game, paused included.
func (s *Store) CountByUser(ctx context.Context, userHash, game string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE user_hash = $1 AND game = $2`, userHash, game).Scan(&n)
	return n, err
}

// Get reads one alert, only for its owner.
func (s *Store) Get(ctx context.Context, id int64, userHash string) (Alert, bool, error) {
	a, err := scanAlert(s.db.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = $1 AND user_hash = $2`, id, userHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, nil
	}
	if err != nil {
		return Alert{}, false, err
	}
	return a, true, nil
}

// Update writes the user-editable columns, the armed state and the origin
// it is given.
func (s *Store) Update(ctx context.Context, a Alert) (bool, error) {
	ak, av := nullKind(a.Above)
	bk, bv := nullKind(a.Below)
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET condition = $3, stores = $4, reference_price = $5,
			above_kind = $6, above_value = $7, below_kind = $8, below_value = $9, delivery = $10,
			above_armed = $11, below_armed = $12, origin = $13, last_error = '', updated_at = now()
		WHERE id = $1 AND user_hash = $2`,
		a.ID, a.UserHash, a.Condition, pq.Array(a.Stores), a.ReferencePrice, ak, av, bk, bv, a.Delivery,
		a.AboveArmed, a.BelowArmed, a.Origin)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetStatus is the user's pause or resume; resuming re-arms and clears the error.
func (s *Store) SetStatus(ctx context.Context, id int64, userHash string, status Status) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET status = $3,
			above_armed = CASE WHEN $3 = 'active' THEN true ELSE above_armed END,
			below_armed = CASE WHEN $3 = 'active' THEN true ELSE below_armed END,
			last_error = CASE WHEN $3 = 'active' THEN '' ELSE last_error END,
			updated_at = now()
		WHERE id = $1 AND user_hash = $2`, id, userHash, status)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Delete removes an alert and, through the cascade, its events.
func (s *Store) Delete(ctx context.Context, id int64, userHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE id = $1 AND user_hash = $2`, id, userHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetState is the evaluator's write; it never touches a row the user paused,
// nor one edited since the run listed it at seenUpdatedAt.
func (s *Store) SetState(ctx context.Context, id int64, seenUpdatedAt time.Time, st State) (bool, error) {
	return writeState(ctx, s.db, id, seenUpdatedAt, st)
}

// ParkForNoAddress is the evaluator's SetState for an email alert whose user
// had no working address when the run looked; it writes nothing if one works
// by now, deciding under the user's lock so a confirm restoring alerts
// cannot land between the check and the park.
func (s *Store) ParkForNoAddress(ctx context.Context, userHash string, id int64, seenUpdatedAt time.Time, st State) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = lockUser(ctx, tx, userHash)
	if err != nil {
		return false, err
	}
	working, err := emailWorks(ctx, tx, userHash)
	if err != nil || working {
		return false, err
	}
	parked, err := writeState(ctx, tx, id, seenUpdatedAt, st)
	if err != nil {
		return false, err
	}
	return parked, tx.Commit()
}

func writeState(ctx context.Context, db execer, id int64, seenUpdatedAt time.Time, st State) (bool, error) {
	var fired any
	if st.LastFiredAt != nil {
		fired = *st.LastFiredAt
	}
	res, err := db.ExecContext(ctx, `
		UPDATE alerts SET status = $2, above_armed = $3, below_armed = $4,
			last_fired_at = COALESCE($5, last_fired_at), last_error = $6, updated_at = now()
		WHERE id = $1 AND status = 'active' AND updated_at = $7`, id, st.Status, st.AboveArmed, st.BelowArmed, fired, st.LastError, seenUpdatedAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AddEvent records one firing.
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_events (alert_id, fired_at, threshold, store, price, delivered, error, message_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.AlertID, e.FiredAt, e.Threshold, e.Store, e.Price, e.Delivered, e.Error, e.MessageID)
	return err
}

// mailLockID namespaces the per-user advisory lock around a mail
// reservation, apart from the schema's and the addresses' locks.
const mailLockID = alertsSchemaLockID + 1

// ReserveMail records, before it is sent, an alert mail to a user, digest
// or park notice, in a ledger no alert row owns; ok is false, reserving
// nothing, once the user had ceiling mails in the 24 hours before at. The
// count and the reservation run under one lock per user, so two sends at
// the last slot cannot both pass. A ceiling of 0 or less is none.
func (s *Store) ReserveMail(ctx context.Context, userHash string, at time.Time, ceiling int) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, mailLockID, userHash)
	if err != nil {
		return 0, false, err
	}
	if ceiling > 0 {
		var n int
		err = tx.QueryRowContext(ctx, `
			SELECT count(*) FROM alert_mails WHERE user_hash = $1 AND sent_at > $2`,
			userHash, at.Add(-24*time.Hour)).Scan(&n)
		if err != nil {
			return 0, false, err
		}
		if n >= ceiling {
			return 0, false, nil
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO alert_mails (user_hash, sent_at) VALUES ($1, $2) RETURNING id`,
		userHash, at).Scan(&id)
	if err != nil {
		return 0, false, err
	}
	return id, true, tx.Commit()
}

// ReleaseMail drops a reserved mail that was not sent.
func (s *Store) ReleaseMail(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_mails WHERE id = $1`, id)
	return err
}

// LastEvents is the newest event per alert id.
func (s *Store) LastEvents(ctx context.Context, ids []int64) (map[int64]Event, error) {
	out := map[int64]Event{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT ON (alert_id) id, alert_id, fired_at, threshold, store, price, delivered, error, message_id
		  FROM alert_events WHERE alert_id = ANY($1)
		 ORDER BY alert_id, fired_at DESC, id DESC`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.AlertID, &e.FiredAt, &e.Threshold, &e.Store, &e.Price, &e.Delivered, &e.Error, &e.MessageID)
		if err != nil {
			return nil, err
		}
		out[e.AlertID] = e
	}
	return out, rows.Err()
}

// ActiveAlert is an alert with the contact the evaluator delivers to.
type ActiveAlert struct {
	Alert
	Contact Contact
}

// ListActive is every active alert of a game on the given sides.
func (s *Store) ListActive(ctx context.Context, game string, sides []Side) ([]ActiveAlert, error) {
	names := make([]string, len(sides))
	for i, side := range sides {
		names[i] = string(side)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.user_hash, a.game, a.card_id, a.side, a.condition, a.stores, a.reference_price,
		       a.above_kind, a.above_value, a.below_kind, a.below_value, a.delivery, a.status, a.above_armed, a.below_armed,
		       a.last_fired_at, a.last_error, a.card_name, a.card_set, a.card_number, a.card_finish, a.created_price,
		       a.created_at, a.updated_at, a.origin,
		       COALESCE(c.discord_user_id, ''), c.tier, c.updated_at
		  FROM alerts a JOIN alert_contacts c USING (user_hash)
		 WHERE a.game = $1 AND a.status = 'active' AND a.side = ANY($2)
		 ORDER BY a.user_hash, a.id`, game, pq.Array(names))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActiveAlert
	for rows.Next() {
		var x ActiveAlert
		var aboveKind, belowKind sql.NullString
		var aboveValue, belowValue, createdPrice sql.NullFloat64
		var lastFired sql.NullTime
		err := rows.Scan(&x.ID, &x.UserHash, &x.Game, &x.CardID, &x.Side, &x.Condition, pq.Array(&x.Stores), &x.ReferencePrice,
			&aboveKind, &aboveValue, &belowKind, &belowValue, &x.Delivery, &x.Status, &x.AboveArmed, &x.BelowArmed,
			&lastFired, &x.LastError, &x.Card.Name, &x.Card.Set, &x.Card.Number, &x.Card.Finish, &createdPrice,
			&x.CreatedAt, &x.UpdatedAt, &x.Origin,
			&x.Contact.DiscordUserID, &x.Contact.Tier, &x.Contact.UpdatedAt)
		if err != nil {
			return nil, err
		}
		x.Contact.UserHash = x.UserHash
		if aboveKind.Valid {
			x.Above = Threshold{Kind: Kind(aboveKind.String), Value: aboveValue.Float64}
		}
		if belowKind.Valid {
			x.Below = Threshold{Kind: Kind(belowKind.String), Value: belowValue.Float64}
		}
		if lastFired.Valid {
			t := lastFired.Time
			x.LastFiredAt = &t
		}
		if createdPrice.Valid {
			p := createdPrice.Float64
			x.CreatedPrice = &p
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// Moved is an alert MarkOverAllowance parked or brought back.
type Moved struct {
	ID        int64
	Status    Status
	Card      Card
	Side      Side
	Condition string
	Origin    string
}

// channelParkReason marks an alert parked for its channel, which the
// allowance neither counts nor restores.
const channelParkReason = "channel not in your tier"

// MarkOverAllowance keeps a user's newest alerts active up to the
// allowance and parks the rest, restoring parked ones when room returns.
// Alerts parked for their channel are left out, and so is one paused or
// edited after the ranking read it. It answers with the alerts it moved,
// newest first.
func (s *Store) MarkOverAllowance(ctx context.Context, userHash, game string, allowance int) ([]Moved, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT id, status, updated_at, row_number() OVER (ORDER BY created_at DESC, id DESC) AS rn
			  FROM alerts
			 WHERE user_hash = $1 AND game = $2 AND status IN ('active', 'over_allowance')
			   AND NOT (status = 'over_allowance' AND last_error = $4)
		), moved AS (
			UPDATE alerts a
			   SET status = CASE WHEN r.rn <= $3 THEN 'active' ELSE 'over_allowance' END,
			       updated_at = now()
			  FROM ranked r
			 WHERE a.id = r.id AND a.status = r.status AND a.updated_at = r.updated_at
			   AND a.status <> CASE WHEN r.rn <= $3 THEN 'active' ELSE 'over_allowance' END
			RETURNING a.id, a.status, a.card_name, a.card_set, a.card_number, a.card_finish,
			          a.side, a.condition, a.origin, r.rn
		)
		SELECT id, status, card_name, card_set, card_number, card_finish, side, condition, origin
		  FROM moved ORDER BY rn`,
		userHash, game, allowance, channelParkReason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Moved
	for rows.Next() {
		var m Moved
		err := rows.Scan(&m.ID, &m.Status, &m.Card.Name, &m.Card.Set, &m.Card.Number, &m.Card.Finish,
			&m.Side, &m.Condition, &m.Origin)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkChannelDisallowed parks and restores alerts by channel, reporting
// status changes; one paused or edited after it read them is left alone.
func (s *Store) MarkChannelDisallowed(ctx context.Context, userHash, game string, allowed []ChannelKind) ([]Moved, error) {
	kinds := make([]string, len(allowed))
	for i, k := range allowed {
		kinds[i] = string(k)
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH target AS (
			SELECT id, status AS was, updated_at AS seen
			  FROM alerts
			 WHERE user_hash = $1 AND game = $2
			   AND ((status IN ('active', 'over_allowance') AND last_error <> $4 AND delivery <> ALL($3))
			     OR (status = 'over_allowance' AND last_error = $4 AND delivery = ANY($3)))
		), moved AS (
			UPDATE alerts a
			   SET status = CASE WHEN a.last_error = $4 THEN 'active' ELSE 'over_allowance' END,
			       last_error = CASE WHEN a.last_error = $4 THEN '' ELSE $4 END,
			       updated_at = now()
			  FROM target t
			 WHERE a.id = t.id AND a.status = t.was AND a.updated_at = t.seen
			RETURNING a.id, a.status, a.card_name, a.card_set, a.card_number, a.card_finish,
			          a.side, a.condition, a.origin, a.created_at, t.was
		)
		SELECT id, status, card_name, card_set, card_number, card_finish, side, condition, origin
		  FROM moved WHERE status <> was ORDER BY created_at DESC, id DESC`,
		userHash, game, pq.Array(kinds), channelParkReason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Moved
	for rows.Next() {
		var m Moved
		err := rows.Scan(&m.ID, &m.Status, &m.Card.Name, &m.Card.Set, &m.Card.Number, &m.Card.Finish,
			&m.Side, &m.Condition, &m.Origin)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PruneEvents drops firings older than before.
func (s *Store) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_mails WHERE sent_at < $1`, before)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM alert_events WHERE fired_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UsersWithAlerts is every contact with an active or parked alert in a game.
func (s *Store) UsersWithAlerts(ctx context.Context, game string) ([]Contact, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT c.user_hash, c.tier, COALESCE(c.discord_user_id, ''), c.updated_at
		  FROM alerts a JOIN alert_contacts c USING (user_hash)
		 WHERE a.game = $1 AND a.status IN ('active', 'over_allowance')
		 ORDER BY c.user_hash`, game)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		var c Contact
		err := rows.Scan(&c.UserHash, &c.Tier, &c.DiscordUserID, &c.UpdatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClaimFire flips the armed flags before a send, only if the row is as listed;
// the fire time is stamped by SetState once the DM lands.
func (s *Store) ClaimFire(ctx context.Context, id int64, seenUpdatedAt time.Time, wasAbove, wasBelow, nextAbove, nextBelow bool) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET above_armed = $5, below_armed = $6, last_error = ''
		 WHERE id = $1 AND status = 'active' AND updated_at = $2 AND above_armed = $3 AND below_armed = $4`,
		id, seenUpdatedAt, wasAbove, wasBelow, nextAbove, nextBelow)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
