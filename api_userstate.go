package main

import (
	"encoding/json"
	"net/http"

	"github.com/mtgban/mtgban-website/userstate"
)

// userStateIdentity returns the sync identity for a signed-in email. The
// game instances share one user_state database, so a non-default game gets
// its own namespace - each site keeps its own favorites and recents - while
// the default game keeps the bare email, so rows created before the scoping
// existed stay reachable. The separator cannot occur in an email address.
func userStateIdentity(email string) string {
	if Config.Game == "" || Config.Game == DefaultGame {
		return email
	}
	return email + "\x00" + Config.Game
}

// UserStateAPI authenticates the caller from their signed cookie/sig, then
// delegates request handling to the userstate package.
func UserStateAPI(w http.ResponseWriter, r *http.Request) {
	email := signedUserEmail(r)
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not signed in"})
		return
	}
	userstate.ServeAPI(w, r, UserStateDB, userStateIdentity(email))
}
