package main

import (
	"encoding/json"
	"net/http"

	"github.com/mtgban/mtgban-website/userstate"
)

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
	userstate.ServeAPI(w, r, UserStateDB, email)
}
