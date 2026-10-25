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

	"github.com/mtgban/go-mtgban/mtgmatcher"
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

// sharedEntry is what a shared row takes from the owner's synced list
// (trimFavorite in user-state.js): which card, when it was added, and its
// pin and tombstone, which arrive as whatever the browser held, a time or a
// bool.
type sharedEntry struct {
	ID     string          `json:"id"`
	T      float64         `json:"t"`
	Pinned json.RawMessage `json:"pinned,omitempty"`
	Del    json.RawMessage `json:"del,omitempty"`
}

// sharedFavorite is one row of a shared list as the page shows it and Merge
// copies it, in the shape the pane keeps. Every field is the datastore's for
// the row's id, never the owner's.
type sharedFavorite struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Set         string   `json:"set"`
	Edition     string   `json:"edition"`
	Number      string   `json:"number"`
	Foil        bool     `json:"foil"`
	Etched      bool     `json:"etched"`
	FinishTag   string   `json:"finishTag"`
	FinishClass string   `json:"finishClass"`
	Treatments  []string `json:"treatments"`
	Img         string   `json:"img"`
	CW          bool     `json:"cw"`
	Query       string   `json:"query"`
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
			vars.SharedRows = sharedRows(s.backend(), raw)
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
// tombstones out, pinned first by pin time, then newest first, at most
// sharedListCap rows. Unreadable JSON is an empty list. A row whose id names
// no card is dropped, and the rest are drawn from b: the owner's synced
// text and art would reach every visitor, and Merge would copy them.
func sharedRows(b *mtgmatcher.Backend, raw json.RawMessage) []sharedFavorite {
	var all []sharedEntry
	err := json.Unmarshal(raw, &all)
	if err != nil {
		log.Println("favorites share: list:", err)
		return nil
	}
	var live []sharedEntry
	for _, e := range all {
		if jsonTruthy(e.Del) {
			continue
		}
		_, err := b.GetUUID(e.ID)
		if err != nil {
			continue
		}
		live = append(live, e)
	}
	slices.SortStableFunc(live, func(a, b sharedEntry) int {
		pa, pb := jsonTruthy(a.Pinned), jsonTruthy(b.Pinned)
		if pa != pb {
			if pa {
				return -1
			}
			return 1
		}
		byPin := cmp.Compare(pinStamp(b.Pinned), pinStamp(a.Pinned))
		if byPin != 0 {
			return byPin
		}
		return cmp.Compare(b.T, a.T)
	})
	if len(live) > sharedListCap {
		live = live[:sharedListCap]
	}
	rows := make([]sharedFavorite, 0, len(live))
	for _, e := range live {
		rows = append(rows, sharedCard(b, e.ID))
	}
	return rows
}

// sharedCard is the row for a card id the way search shows the card, and
// the query its result links to.
func sharedCard(b *mtgmatcher.Backend, id string) sharedFavorite {
	card := uuid2card(b, id, false)
	co, _ := b.GetUUID(id)
	treatments := make([]string, 0, len(card.Treatments))
	for _, promoType := range card.Treatments {
		treatments = append(treatments, card.PromoLabels[promoType])
	}
	return sharedFavorite{
		ID:          id,
		Name:        card.Name,
		Set:         card.SetCode,
		Edition:     card.Edition,
		Number:      card.Number,
		Foil:        card.Foil,
		Etched:      card.Etched,
		FinishTag:   card.FinishTag,
		FinishClass: card.FinishClass,
		Treatments:  treatments,
		Img:         cmp.Or(card.ImageURL, card.FullImageURL),
		CW:          card.HasContentWarning,
		Query:       genQuery(co),
	}
}

// pinStamp is a pinned value as the pane's sort subtracts it: a number is
// itself, true is 1, anything else 0.
func pinStamp(raw json.RawMessage) float64 {
	var v any
	err := json.Unmarshal(raw, &v)
	if err != nil {
		return 0
	}
	switch v := v.(type) {
	case float64:
		return v
	case bool:
		if v {
			return 1
		}
	}
	return 0
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
