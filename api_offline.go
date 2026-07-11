package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OfflineAPI dispatches /api/offline/ endpoints for the offline PWA mode.
func OfflineAPI(w http.ResponseWriter, r *http.Request) {
	_, ok := offlineModeAllowed(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "offline mode not available"})
		return
	}

	endpoint := strings.TrimPrefix(r.URL.Path, "/api/offline/")
	switch {
	default:
		http.NotFound(w, r)
	}
	_ = endpoint
}

// offlineModeAllowed authenticates the caller and checks the SearchOfflineMode
// ACL flag baked into their signed cookie.
func offlineModeAllowed(r *http.Request) (string, bool) {
	if DevMode && !SigCheck {
		return "dev@localhost", true
	}
	email := signedUserEmail(r)
	if email == "" {
		return "", false
	}
	sig := getSignatureFromCookies(r)
	return email, GetParamFromSig(sig, "SearchOfflineMode") == "true"
}
