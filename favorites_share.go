package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

// SharedVars is what the shared favorites page shows.
type SharedVars struct {
	SharedRows     []sharedFavorite
	SharedCount    int
	SharedNotice   string
	SharedSignedIn bool
}

// sharedFavorite is one row of a shared list: the fields the owner's pane
// syncs (trimFavorite in user-state.js) that the page shows or Merge copies.
// pinned and del arrive as whatever the browser held, a time or a bool.
type sharedFavorite struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Set         string          `json:"set"`
	Edition     string          `json:"edition"`
	Number      string          `json:"number"`
	Foil        bool            `json:"foil"`
	Etched      bool            `json:"etched"`
	FinishTag   string          `json:"finishTag"`
	FinishClass string          `json:"finishClass"`
	Treatments  []string        `json:"treatments"`
	Img         string          `json:"img"`
	CW          bool            `json:"cw"`
	Query       string          `json:"query"`
	T           float64         `json:"t"`
	Pinned      json.RawMessage `json:"pinned,omitempty"`
	Del         json.RawMessage `json:"del,omitempty"`
}

// sharedFavoritesStore is what the page reads: the owner's favorites behind
// a live share id. *userstate.Client satisfies it; tests fake it.
type sharedFavoritesStore interface {
	SharedFavorites(ctx context.Context, shareID, game string) (json.RawMessage, error)
}

// sharedPageLimiter throttles the public page by client address.
var sharedPageLimiter = ratelimit.NewLimiter(2, 5)

const sharedListCap = 50

const (
	sharedGoneText        = "This list is no longer shared."
	sharedUnavailableText = "Sharing is unavailable right now."
	sharedErrorText       = "Something went wrong reading this list."
	sharedBusyText        = "Too many requests, try again in a moment."
)

// FavoritesShared serves /search/shared: a favorites list by its share id.
func (s *site) FavoritesShared(w http.ResponseWriter, r *http.Request) {
	// A nil *Client must reach the handler as a nil interface.
	var store sharedFavoritesStore
	if UserStateDB != nil {
		store = UserStateDB
	}
	s.favoritesShared(w, r, store)
}

func (s *site) favoritesShared(w http.ResponseWriter, r *http.Request, store sharedFavoritesStore) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	vars := SharedVars{SharedSignedIn: signedUserEmail(r) != ""}
	status := http.StatusOK
	id := r.FormValue("id")
	switch {
	case !sharedPageLimiter.Allow(sharedClientKey(r)):
		vars.SharedNotice, status = sharedBusyText, http.StatusTooManyRequests
	case store == nil:
		vars.SharedNotice, status = sharedUnavailableText, http.StatusServiceUnavailable
	case !userstate.ValidShareID(id):
		vars.SharedNotice, status = sharedGoneText, http.StatusNotFound
	default:
		raw, err := store.SharedFavorites(r.Context(), id, string(Config().Game))
		switch {
		case errors.Is(err, userstate.ErrShareNotFound):
			vars.SharedNotice, status = sharedGoneText, http.StatusNotFound
		case err != nil:
			log.Println("favorites share:", err)
			vars.SharedNotice, status = sharedErrorText, http.StatusInternalServerError
		default:
			vars.SharedRows = sharedRows(raw)
			vars.SharedCount = len(vars.SharedRows)
		}
	}
	s.renderShared(w, r, status, vars)
}

// sharedClientKey is the address the limiter counts, as the API limiter
// in auth.go reads it.
func sharedClientKey(r *http.Request) string {
	ip, err := ratelimit.IPAddress(r)
	if err != nil || ip == nil {
		return r.RemoteAddr
	}
	return ip.String()
}

func (s *site) renderShared(w http.ResponseWriter, r *http.Request, status int, vars SharedVars) {
	pageVars := genPageNav(s, r, "Search", verifiedSignature(r))
	// An expired cookie's notice must not replace this page's own.
	pageVars.ErrorMessage = ""
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	pageVars.Title = "Shared favorites"
	pageVars.SharedVars = vars
	w.Header().Set("Cache-Control", "no-store")
	// The query string is the share secret; keep it from the image hosts.
	w.Header().Set("Referrer-Policy", "same-origin")
	render(&statusOnWrite{ResponseWriter: w, status: status}, "favorites-shared.html", pageVars)
}

// sharedRows reads a favorites column the way the owner's pane shows it:
// tombstones and nameless entries out, pinned first, newest first, at most
// sharedListCap rows. Unreadable JSON is an empty list.
func sharedRows(raw json.RawMessage) []sharedFavorite {
	var all []sharedFavorite
	if err := json.Unmarshal(raw, &all); err != nil {
		log.Println("favorites share: list:", err)
		return nil
	}
	var rows []sharedFavorite
	for _, f := range all {
		if jsonTruthy(f.Del) || f.ID == "" || f.Name == "" {
			continue
		}
		rows = append(rows, f)
	}
	slices.SortStableFunc(rows, func(a, b sharedFavorite) int {
		if pa, pb := jsonTruthy(a.Pinned), jsonTruthy(b.Pinned); pa != pb {
			if pa {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.T, a.T)
	})
	if len(rows) > sharedListCap {
		rows = rows[:sharedListCap]
	}
	return rows
}

// jsonTruthy reads a JSON value the way the pane's JS does: absent, null,
// false, 0 and "" are false, anything else true.
func jsonTruthy(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "false", "0", `""`:
		return false
	}
	return true
}
