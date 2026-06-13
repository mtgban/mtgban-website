package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mtgban/mtgban-website/userstate"
)

// maxUserStateBody caps a single sync payload. Section caps (50 favorites / 15
// recents) are client-side; this is the server-side guard against oversized or
// malicious bodies bloating the JSONB row.
const maxUserStateBody = 512 * 1024

// writeJSON is a small helper for JSON responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// UserStateAPI dispatches GET/PUT for /api/userstate/ and PATCH for
// /api/userstate/{section}. All paths require an authenticated user; anonymous
// requests get 401 and the client falls back to localStorage. When the DB is
// not configured, 503 signals "sync unavailable".
func UserStateAPI(w http.ResponseWriter, r *http.Request) {
	email := signedUserEmail(r)
	if email == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	if !UserRateLimiter.Allow(email) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	if UserStateDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sync unavailable"})
		return
	}

	hash := userstate.HashEmail(email)
	ctx := r.Context()

	// Determine section suffix after the base path, if any.
	section := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/userstate/"), "/")

	switch r.Method {
	case http.MethodGet:
		if section != "" {
			http.Error(w, "404 not found", http.StatusNotFound)
			return
		}
		st, err := UserStateDB.Get(ctx, hash)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
			return
		}
		writeJSON(w, http.StatusOK, st)

	case http.MethodPut:
		if section != "" {
			http.Error(w, "404 not found", http.StatusNotFound)
			return
		}
		var body userstate.State
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUserStateBody)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
			return
		}
		newVersion, conflict, err := UserStateDB.Put(ctx, hash, body, body.Version)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
			return
		}
		if conflict {
			current, _ := UserStateDB.Get(ctx, hash)
			writeJSON(w, http.StatusConflict, current)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"version": newVersion})

	case http.MethodPatch:
		if section == "" {
			http.Error(w, "404 not found", http.StatusNotFound)
			return
		}
		var body struct {
			Data    json.RawMessage `json:"data"`
			Version int64           `json:"version"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUserStateBody)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
			return
		}
		newVersion, conflict, err := UserStateDB.Patch(ctx, hash, section, body.Data, body.Version)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if conflict {
			current, _ := UserStateDB.Get(ctx, hash)
			writeJSON(w, http.StatusConflict, current)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"version": newVersion})

	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
