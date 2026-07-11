package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OfflineAPI dispatches /api/offline/ endpoints for the offline PWA mode.
func OfflineAPI(w http.ResponseWriter, r *http.Request) {
	email, ok := offlineModeAllowed(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "offline mode not available"})
		return
	}

	endpoint := strings.TrimPrefix(r.URL.Path, "/api/offline/")
	switch {
	case endpoint == "manifest.json":
		serveOfflineManifest(w, r)
	case endpoint == "catalog.json":
		serveOfflineCatalog(w, r)
	case strings.HasPrefix(endpoint, "prices/"):
		serveOfflinePrices(w, r, email, strings.TrimPrefix(endpoint, "prices/"))
	case strings.HasPrefix(endpoint, "images/"):
		serveOfflineImage(w, r, strings.TrimPrefix(endpoint, "images/"))
	case strings.HasPrefix(endpoint, "imagebundles/"):
		serveOfflineImageBundle(w, r, strings.TrimPrefix(endpoint, "imagebundles/"))
	default:
		http.NotFound(w, r)
	}
}

// offlineModeAllowed authenticates the caller and checks the OfflineMode
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
	return email, GetParamFromSig(sig, "OfflineMode") == "true"
}
