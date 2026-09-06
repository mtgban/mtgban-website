package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// RawCardAPI serves the record behind one card id exactly as the backend
// holds it: the CardObject that mtgmatcher.GetUUID resolves, every field
// present since the mtgmatcher structs carry no omitempty. It exists to
// debug what the matcher knows about a printing - finishes, identifiers,
// number decorations - beside the Fix links that correct its matches, so it
// is gated like them: admins, or a sigless dev build.
func RawCardAPI(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	canAdmin, _ := strconv.ParseBool(GetParamFromSig(sig, "Admin"))
	if !canAdmin && !(DevMode && !SigCheck) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	cardID := strings.TrimPrefix(r.URL.Path, "/api/mtgmatcher/raw/")
	co, err := mtgmatcher.GetUUID(cardID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	out, err := json.MarshalIndent(co, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}
