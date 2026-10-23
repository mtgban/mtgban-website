package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mtgban/mtgban-website/userstate"
)

// userStateIdentity returns the sync identity for a signed-in email. The
// game instances share one user_state database, so a non-default game gets
// its own namespace - each site keeps its own favorites and recents - while
// the default game keeps the bare email, so rows created before the scoping
// existed stay reachable. The separator cannot occur in an email address.
func userStateIdentity(email string) string {
	if Config().Game == "" || Config().Game == DefaultGame {
		return email
	}
	return email + "\x00" + string(Config().Game)
}

// defaultBackpackMax is how many cards the backpack holds where the tier sets
// no SearchBackpackMax, and maxBackpackMax the most a tier can set: at about
// 365 bytes a card, that many cards and as many tombstones still fit the
// userstate sync body's 1 MB beside the other sections.
const (
	defaultBackpackMax = 100
	maxBackpackMax     = 1000
)

// backpackMaxFromValues reads SearchBackpackMax off signed ACL values, held
// to maxBackpackMax.
func backpackMaxFromValues(v url.Values) int {
	n, err := strconv.Atoi(v.Get("SearchBackpackMax"))
	if err != nil || n < 1 {
		return defaultBackpackMax
	}
	return min(n, maxBackpackMax)
}

// UserStateAPI authenticates the caller from their signed cookie/sig, then
// delegates request handling to the userstate package.
func UserStateAPI(w http.ResponseWriter, r *http.Request) {
	v := parseSig(verifiedRequestSignature(r))
	email := v.Get("UserEmail")
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not signed in"})
		return
	}
	userstate.ServeAPI(w, r, UserStateDB, userStateIdentity(email), backpackMaxFromValues(v))
}
