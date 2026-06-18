package userstate

import (
	"encoding/json"
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

// ServeAPI handles GET/PUT on /api/userstate/ and PATCH on /{section} for an
// already-authenticated email; a nil db is 503.
func ServeAPI(w http.ResponseWriter, r *http.Request, db *Client, email string) {
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
			return
		}
		result, conflict, err := db.Patch(ctx, hash, section, body.Data, body.Version)
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
