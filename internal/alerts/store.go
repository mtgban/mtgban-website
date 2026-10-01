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
	_, err = tx.ExecContext(ctx, schemaSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("alerts: ensure schema: %w", err)
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

const alertColumns = `id, user_hash, game, card_id, side, condition, stores, reference_price,
	above_kind, above_value, below_kind, below_value, delivery, status, above_armed, below_armed,
	last_fired_at, last_error, card_name, card_set, card_number, card_finish, created_price,
	created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanAlert(row rowScanner) (Alert, error) {
	var a Alert
	var aboveKind, belowKind sql.NullString
	var aboveValue, belowValue, createdPrice sql.NullFloat64
	var lastFired sql.NullTime
	err := row.Scan(&a.ID, &a.UserHash, &a.Game, &a.CardID, &a.Side, &a.Condition, pq.Array(&a.Stores), &a.ReferencePrice,
		&aboveKind, &aboveValue, &belowKind, &belowValue, &a.Delivery, &a.Status, &a.AboveArmed, &a.BelowArmed,
		&lastFired, &a.LastError, &a.Card.Name, &a.Card.Set, &a.Card.Number, &a.Card.Finish, &createdPrice,
		&a.CreatedAt, &a.UpdatedAt)
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
			card_name, card_set, card_number, card_finish, created_price, above_armed, below_armed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING `+alertColumns,
		a.UserHash, a.Game, a.CardID, a.Side, a.Condition, pq.Array(a.Stores), a.ReferencePrice,
		ak, av, bk, bv, a.Delivery, a.Card.Name, a.Card.Set, a.Card.Number, a.Card.Finish, createdPrice,
		a.AboveArmed, a.BelowArmed)
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

// Update writes the user-editable columns and the armed state it is given.
func (s *Store) Update(ctx context.Context, a Alert) (bool, error) {
	ak, av := nullKind(a.Above)
	bk, bv := nullKind(a.Below)
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET condition = $3, stores = $4, reference_price = $5,
			above_kind = $6, above_value = $7, below_kind = $8, below_value = $9, delivery = $10,
			above_armed = $11, below_armed = $12, last_error = '', updated_at = now()
		WHERE id = $1 AND user_hash = $2`,
		a.ID, a.UserHash, a.Condition, pq.Array(a.Stores), a.ReferencePrice, ak, av, bk, bv, a.Delivery,
		a.AboveArmed, a.BelowArmed)
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

// SetState is the evaluator's write; it never touches a row the user paused.
func (s *Store) SetState(ctx context.Context, id int64, st State) (bool, error) {
	var fired any
	if st.LastFiredAt != nil {
		fired = *st.LastFiredAt
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET status = $2, above_armed = $3, below_armed = $4,
			last_fired_at = COALESCE($5, last_fired_at), last_error = $6, updated_at = now()
		WHERE id = $1 AND status = 'active'`, id, st.Status, st.AboveArmed, st.BelowArmed, fired, st.LastError)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AddEvent records one firing.
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_events (alert_id, fired_at, threshold, store, price, delivered, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.AlertID, e.FiredAt, e.Threshold, e.Store, e.Price, e.Delivered, e.Error)
	return err
}

// LastEvents is the newest event per alert id.
func (s *Store) LastEvents(ctx context.Context, ids []int64) (map[int64]Event, error) {
	out := map[int64]Event{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT ON (alert_id) id, alert_id, fired_at, threshold, store, price, delivered, error
		  FROM alert_events WHERE alert_id = ANY($1)
		 ORDER BY alert_id, fired_at DESC, id DESC`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.AlertID, &e.FiredAt, &e.Threshold, &e.Store, &e.Price, &e.Delivered, &e.Error)
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
		       a.created_at, a.updated_at,
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
			&x.CreatedAt, &x.UpdatedAt,
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

// MarkOverAllowance keeps a user's newest alerts active up to the
// allowance and parks the rest, restoring parked ones when room returns.
func (s *Store) MarkOverAllowance(ctx context.Context, userHash, game string, allowance int) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		WITH ranked AS (
			SELECT id, row_number() OVER (ORDER BY created_at DESC, id DESC) AS rn
			  FROM alerts
			 WHERE user_hash = $1 AND game = $2 AND status IN ('active', 'over_allowance')
		)
		UPDATE alerts a
		   SET status = CASE WHEN r.rn <= $3 THEN 'active' ELSE 'over_allowance' END,
		       updated_at = now()
		  FROM ranked r
		 WHERE a.id = r.id
		   AND a.status <> CASE WHEN r.rn <= $3 THEN 'active' ELSE 'over_allowance' END`,
		userHash, game, allowance)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneEvents drops firings older than before.
func (s *Store) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
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
