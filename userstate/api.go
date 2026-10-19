// Package userstate persists per-user preferences and entitlements in
// Postgres, keyed by a hash of the login email.
package userstate

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/ratelimit"
)

// maxBody is the server-side cap on a sync payload.
const maxBody = 512 * 1024

// apiLimiter throttles /api/userstate/ separately from page rendering.
var apiLimiter = ratelimit.NewLimiter(10, 5) // 10 req/s, burst 5

// writeJSON is a small helper for JSON responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ServeAPI handles GET/PUT on /api/userstate/, PATCH on /{section} and
// GET/POST/DELETE on /share for an already-authenticated email; a nil db is
// 503. game is the site's, which a new share is made for.
func ServeAPI(w http.ResponseWriter, r *http.Request, db *Client, email, game string) {
	if !apiLimiter.Allow(email) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sync unavailable"})
		return
	}

	hash := HashEmail(email)
	ctx := r.Context()

	// Determine section suffix after the base path, if any.
	section := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/userstate/"), "/")
	if section == "share" {
		serveShare(w, r, db, hash, game)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if section != "" {
			http.Error(w, "404 not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		// Conditional GET: matching version returns 304 without reading the row.
		if inm := strings.Trim(r.Header.Get("If-None-Match"), `"`); inm != "" {
			if v, verr := db.GetVersion(ctx, hash); verr == nil && strconv.FormatInt(v, 10) == inm {
				w.Header().Set("ETag", `"`+inm+`"`)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		st, err := db.Get(ctx, hash)
		if err != nil {
			log.Printf("userstate: GET failed for %.10s: %v", hash, err)
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
		var body State
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
			return
		}
		result, conflict, err := db.Put(ctx, hash, body, body.Version)
		if err != nil {
			log.Printf("userstate: PUT failed for %.10s: %v", hash, err)
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
		if !validSections[section] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown section"})
			return
		}
		var body struct {
			Data    json.RawMessage `json:"data"`
			Version int64           `json:"version"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
			return
		}
		result, conflict, err := db.Patch(ctx, hash, section, body.Data, body.Version)
		if err != nil {
			log.Printf("userstate: PATCH %s failed for %.10s: %v", section, hash, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
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

// shareStore is what serveShare asks of the store; *Client is one, tests
// fake it.
type shareStore interface {
	ShareFor(ctx context.Context, emailHash, game string) (string, error)
	CreateShare(ctx context.Context, emailHash, game string) (string, error)
	RevokeShare(ctx context.Context, emailHash, game string) error
}

// serveShare is /api/userstate/share: the owner's live favorites share
// link id. GET shows it, POST makes or replaces it, DELETE ends it.
func serveShare(w http.ResponseWriter, r *http.Request, db shareStore, hash, game string) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "private, no-store")
	// The cookie rides cross-site requests; a custom header needs a CORS
	// preflight that another site's page cannot pass.
	if (r.Method == http.MethodPost || r.Method == http.MethodDelete) && r.Header.Get("X-Requested-With") != "fetch" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "same-origin only"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		id, err := db.ShareFor(ctx, hash, game)
		if err != nil {
			log.Printf("userstate: share GET failed for %.10s: %v", hash, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
			return
		}
		if id == "" {
			writeJSON(w, http.StatusOK, map[string]string{})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id})
	case http.MethodPost:
		id, err := db.CreateShare(ctx, hash, game)
		// A lost race whose winner was revoked meanwhile leaves no id.
		if err == nil && id == "" {
			err = errors.New("no live share after create")
		}
		if err != nil {
			log.Printf("userstate: share POST failed for %.10s: %v", hash, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id})
	case http.MethodDelete:
		if err := db.RevokeShare(ctx, hash, game); err != nil {
			log.Printf("userstate: share DELETE failed for %.10s: %v", hash, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
