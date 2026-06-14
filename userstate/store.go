package userstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// State is the full per-user payload; section columns pass through as raw JSON.
type State struct {
	Favorites   json.RawMessage `json:"favorites"`
	Recents     json.RawMessage `json:"recents"`
	Preferences json.RawMessage `json:"preferences"`
	Version     int64           `json:"version"`
}

var validSections = map[string]bool{
	"favorites": true, "recents": true, "preferences": true,
}

// Get returns the row for emailHash, or the zero state if missing.
func (c *Client) Get(ctx context.Context, emailHash string) (State, error) {
	st := State{
		Favorites:   json.RawMessage("[]"),
		Recents:     json.RawMessage("[]"),
		Preferences: json.RawMessage("{}"),
	}
	var fav, rec, pref []byte
	err := c.db.QueryRowContext(ctx,
		`SELECT favorites, recents, preferences, version FROM user_state WHERE email_hash = $1`,
		emailHash,
	).Scan(&fav, &rec, &pref, &st.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return State{}, err
	}
	st.Favorites = json.RawMessage(fav)
	st.Recents = json.RawMessage(rec)
	st.Preferences = json.RawMessage(pref)
	return st, nil
}

// GetVersion returns the row's version, or 0 if missing.
func (c *Client) GetVersion(ctx context.Context, emailHash string) (int64, error) {
	var version int64
	err := c.db.QueryRowContext(ctx,
		`SELECT version FROM user_state WHERE email_hash = $1`, emailHash,
	).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return version, nil
}

// writeWithConflict runs a write-or-read CTE; on version mismatch it returns the current row (conflict). Zero rows is a conflict with the zero state.
func (c *Client) writeWithConflict(ctx context.Context, query string, args ...any) (State, bool, error) {
	var updated bool
	var version int64
	var fav, rec, pref []byte
	err := c.db.QueryRowContext(ctx, query, args...).Scan(&updated, &version, &fav, &rec, &pref)
	if errors.Is(err, sql.ErrNoRows) {
		return State{
			Favorites:   json.RawMessage("[]"),
			Recents:     json.RawMessage("[]"),
			Preferences: json.RawMessage("{}"),
		}, true, nil
	}
	if err != nil {
		return State{}, false, err
	}
	return State{
		Favorites:   json.RawMessage(fav),
		Recents:     json.RawMessage(rec),
		Preferences: json.RawMessage(pref),
		Version:     version,
	}, !updated, nil
}

// Put fully replaces all sections, version-checked; on conflict returns the current state.
func (c *Client) Put(ctx context.Context, emailHash string, st State, expectedVersion int64) (State, bool, error) {
	if expectedVersion == 0 {
		return c.writeWithConflict(ctx, `
			WITH ins AS (
				INSERT INTO user_state (email_hash, favorites, recents, preferences, version)
				VALUES ($1, $2, $3, $4, 1)
				ON CONFLICT (email_hash) DO NOTHING
				RETURNING version, favorites, recents, preferences
			)
			SELECT TRUE AS updated, version, favorites, recents, preferences FROM ins
			UNION ALL
			SELECT FALSE AS updated, version, favorites, recents, preferences
			  FROM user_state
			 WHERE email_hash = $1 AND NOT EXISTS (SELECT 1 FROM ins)`,
			emailHash,
			jsonOrEmpty(st.Favorites, "[]"), jsonOrEmpty(st.Recents, "[]"), jsonOrEmpty(st.Preferences, "{}"),
		)
	}
	return c.writeWithConflict(ctx, `
		WITH upd AS (
			UPDATE user_state
			   SET favorites = $2, recents = $3, preferences = $4,
			       version = version + 1, updated_at = now()
			 WHERE email_hash = $1 AND version = $5
			 RETURNING version, favorites, recents, preferences
		)
		SELECT TRUE AS updated, version, favorites, recents, preferences FROM upd
		UNION ALL
		SELECT FALSE AS updated, version, favorites, recents, preferences
		  FROM user_state
		 WHERE email_hash = $1 AND NOT EXISTS (SELECT 1 FROM upd)`,
		emailHash,
		jsonOrEmpty(st.Favorites, "[]"), jsonOrEmpty(st.Recents, "[]"), jsonOrEmpty(st.Preferences, "{}"),
		expectedVersion,
	)
}

// Patch replaces one section column, version-checked, with Put's return shape.
func (c *Client) Patch(ctx context.Context, emailHash, section string, payload json.RawMessage, expectedVersion int64) (State, bool, error) {
	if !validSections[section] {
		return State{}, false, fmt.Errorf("userstate: unknown section %q", section)
	}

	if expectedVersion == 0 {
		cols := map[string][]byte{"favorites": []byte("[]"), "recents": []byte("[]"), "preferences": []byte("{}")}
		cols[section] = []byte(jsonOrEmpty(payload, defaultFor(section)))
		return c.writeWithConflict(ctx, `
			WITH ins AS (
				INSERT INTO user_state (email_hash, favorites, recents, preferences, version)
				VALUES ($1, $2, $3, $4, 1)
				ON CONFLICT (email_hash) DO NOTHING
				RETURNING version, favorites, recents, preferences
			)
			SELECT TRUE AS updated, version, favorites, recents, preferences FROM ins
			UNION ALL
			SELECT FALSE AS updated, version, favorites, recents, preferences
			  FROM user_state
			 WHERE email_hash = $1 AND NOT EXISTS (SELECT 1 FROM ins)`,
			emailHash, cols["favorites"], cols["recents"], cols["preferences"],
		)
	}

	// section is validated against validSections above; safe to interpolate.
	q := fmt.Sprintf(`
		WITH upd AS (
			UPDATE user_state
			   SET %s = $2, version = version + 1, updated_at = now()
			 WHERE email_hash = $1 AND version = $3
			 RETURNING version, favorites, recents, preferences
		)
		SELECT TRUE AS updated, version, favorites, recents, preferences FROM upd
		UNION ALL
		SELECT FALSE AS updated, version, favorites, recents, preferences
		  FROM user_state
		 WHERE email_hash = $1 AND NOT EXISTS (SELECT 1 FROM upd)`, section)
	return c.writeWithConflict(ctx, q, emailHash, []byte(jsonOrEmpty(payload, defaultFor(section))), expectedVersion)
}

func defaultFor(section string) string {
	if section == "preferences" {
		return "{}"
	}
	return "[]"
}

func jsonOrEmpty(raw json.RawMessage, empty string) string {
	if len(raw) == 0 {
		return empty
	}
	return string(raw)
}
