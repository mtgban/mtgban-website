package userstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// State is the full per-user payload. Section columns are passed through as raw
// JSON so the server stays agnostic to their shape (JSONB schema evolution).
type State struct {
	Favorites   json.RawMessage `json:"favorites"`
	Recents     json.RawMessage `json:"recents"`
	Preferences json.RawMessage `json:"preferences"`
	Version     int64           `json:"version"`
}

var validSections = map[string]bool{
	"favorites": true, "recents": true, "preferences": true,
}

// Get returns the row for emailHash. A missing row yields the zero state
// (empty arrays / object, version 0) without erroring.
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

// Put fully replaces all sections, version-checked. expectedVersion 0 inserts a
// new row (version 1). A nonzero expectedVersion updates only if the stored
// version matches. Returns (newVersion, conflict, error); conflict is true when
// the version did not match.
func (c *Client) Put(ctx context.Context, emailHash string, st State, expectedVersion int64) (int64, bool, error) {
	if expectedVersion == 0 {
		var newVersion int64
		err := c.db.QueryRowContext(ctx, `
			INSERT INTO user_state (email_hash, favorites, recents, preferences, version)
			VALUES ($1, $2, $3, $4, 1)
			ON CONFLICT (email_hash) DO NOTHING
			RETURNING version`,
			emailHash, jsonOrEmpty(st.Favorites, "[]"), jsonOrEmpty(st.Recents, "[]"), jsonOrEmpty(st.Preferences, "{}"),
		).Scan(&newVersion)
		if errors.Is(err, sql.ErrNoRows) {
			// Row already existed; caller passed 0 but should have a version.
			return 0, true, nil
		}
		if err != nil {
			return 0, false, err
		}
		return newVersion, false, nil
	}

	var newVersion int64
	err := c.db.QueryRowContext(ctx, `
		UPDATE user_state
		   SET favorites = $2, recents = $3, preferences = $4,
		       version = version + 1, updated_at = now()
		 WHERE email_hash = $1 AND version = $5
		 RETURNING version`,
		emailHash, jsonOrEmpty(st.Favorites, "[]"), jsonOrEmpty(st.Recents, "[]"), jsonOrEmpty(st.Preferences, "{}"), expectedVersion,
	).Scan(&newVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	return newVersion, false, nil
}

// Patch replaces a single section column, version-checked. Creates the row if
// it does not exist when expectedVersion is 0.
func (c *Client) Patch(ctx context.Context, emailHash, section string, payload json.RawMessage, expectedVersion int64) (int64, bool, error) {
	if !validSections[section] {
		return 0, false, fmt.Errorf("userstate: unknown section %q", section)
	}

	if expectedVersion == 0 {
		// Insert a fresh row with this section populated, others defaulted.
		cols := map[string]any{"favorites": []byte("[]"), "recents": []byte("[]"), "preferences": []byte("{}")}
		cols[section] = []byte(jsonOrEmpty(payload, defaultFor(section)))
		var newVersion int64
		err := c.db.QueryRowContext(ctx, `
			INSERT INTO user_state (email_hash, favorites, recents, preferences, version)
			VALUES ($1, $2, $3, $4, 1)
			ON CONFLICT (email_hash) DO NOTHING
			RETURNING version`,
			emailHash, cols["favorites"], cols["recents"], cols["preferences"],
		).Scan(&newVersion)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, true, nil
		}
		if err != nil {
			return 0, false, err
		}
		return newVersion, false, nil
	}

	// Section name is validated against an allowlist above, so interpolating it
	// into the column position is safe.
	q := fmt.Sprintf(`
		UPDATE user_state
		   SET %s = $2, version = version + 1, updated_at = now()
		 WHERE email_hash = $1 AND version = $3
		 RETURNING version`, section)
	var newVersion int64
	err := c.db.QueryRowContext(ctx, q, emailHash, []byte(jsonOrEmpty(payload, defaultFor(section))), expectedVersion).Scan(&newVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	return newVersion, false, nil
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
