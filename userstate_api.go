package main

import (
	"encoding/json"
	"net/http"
	"strconv"
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
	if !SyncRateLimiter.Allow(email) {
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
		w.Header().Set("Cache-Control", "private, no-store")
		// Conditional GET: when the client's version matches, skip reading the
		// JSONB columns and return 304.
		if inm := strings.Trim(r.Header.Get("If-None-Match"), `"`); inm != "" {
			if v, verr := UserStateDB.GetVersion(ctx, hash); verr == nil && strconv.FormatInt(v, 10) == inm {
				w.Header().Set("ETag", `"`+inm+`"`)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		st, err := UserStateDB.Get(ctx, hash)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(st.Version, 10)+`"`)
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
		result, conflict, err := UserStateDB.Put(ctx, hash, body, body.Version)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
			return
		}
		if conflict {
			writeJSON(w, http.StatusConflict, result)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"version": result.Version})

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
		result, conflict, err := UserStateDB.Patch(ctx, hash, section, body.Data, body.Version)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if conflict {
			writeJSON(w, http.StatusConflict, result)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"version": result.Version})

	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
